use async_graphql::{Context, Error, ErrorExtensions, Guard, Result};
use chrono::Utc;
use identity_application::error::{AppError, params::ErrorParams};
use identity_domain::{
    auth::{ACR_AAL2, acr_satisfies, authentication_is_fresh},
    authorization::AdministratorRole,
    openid_connect::ApiScope,
};

use super::{
    context::RequestContext,
    error::{self, app_error},
};

pub(super) fn request_context<'a>(ctx: &'a Context<'_>) -> Result<&'a RequestContext> {
    ctx.data::<RequestContext>().map_err(|_| {
        error::coded_error(
            ctx,
            identity_application::error::codes::graphql::GraphqlErrorCode::AuthenticationContextUnavailable,
            ErrorParams::new(),
        )
    })
}

/// Result of the principal-specific effective-permission adapter.
///
/// `role` is the instance administrator role only when a real binding exists.
/// The default adapter never grants a role or management scope.
pub(crate) struct EffectivePermissionsView {
    pub role: Option<AdministratorRole>,
    pub requestable_scopes: Vec<String>,
    pub effective_scopes: Vec<String>,
}

/// Adapter port for the effective-permission repository lookup.
///
/// The parent injects an implementation backed by the administrator binding
/// repository when it becomes available. This module deliberately does not
/// depend on `AppServices` internals: the absence of an injected provider means
/// an ordinary self-service principal with no management role or scopes.
#[async_trait::async_trait]
pub(crate) trait EffectivePermissionsProvider: Send + Sync {
    async fn effective_permissions(
        &self,
        request: &RequestContext,
    ) -> std::result::Result<EffectivePermissionsView, AppError>;
}

/// Requires a current user principal. The transport already rejects requests
/// without a valid token; this guard makes the resolver-level requirement
/// explicit and keeps machine principals from reaching self-service fields.
pub(super) struct UserPrincipalGuard;

impl Guard for UserPrincipalGuard {
    async fn check(&self, ctx: &Context<'_>) -> Result<()> {
        request_context(ctx)?.user().map(|_| ())
    }
}

/// Requires one existing self-service scope.
pub(super) struct ScopeGuard {
    scope: ApiScope,
}

impl ScopeGuard {
    pub(crate) fn policy(scope: ApiScope) -> super::access::AccessPolicy {
        super::access::AccessPolicy::scope(scope)
    }

    pub(super) const fn new(scope: ApiScope) -> Self {
        Self { scope }
    }
}

impl Guard for ScopeGuard {
    async fn check(&self, ctx: &Context<'_>) -> Result<()> {
        let request = request_context(ctx)?;
        if request.claims.scope.allows(self.scope) {
            return Ok(());
        }
        let scope = self.scope.name();
        let params = ErrorParams::new().insert("scope", scope);
        let message = error::localized_message(
            ctx,
            identity_application::error::codes::graphql::GraphqlErrorCode::InsufficientScope,
            &params,
        );
        let correlation = error::correlation(ctx);
        Err(Error::new(message).extend_with(|_, extensions| {
            extensions.set("kind", "authorization_error");
            extensions.set("code", "insufficient_scope");
            extensions.set("requiredScope", scope);
            extensions.set("requiredScopes", vec![scope.to_owned()]);
            correlation.apply(extensions);
        }))
    }
}

/// Requires recent authentication, optionally at a specific ACR.
///
/// `aal2()` requires both AAL2 assurance and freshness within the elevated
/// window. The generic guard requires recent AAL1-or-better authentication
/// within the ordinary recent window.
pub(super) struct RecentAuthenticationGuard {
    required_acr: Option<&'static str>,
}

impl RecentAuthenticationGuard {
    pub(crate) fn policy(&self) -> super::access::AccessPolicy {
        super::access::AccessPolicy::recent(self.required_acr == Some(ACR_AAL2))
    }

    pub(super) const fn new() -> Self {
        Self { required_acr: None }
    }

    pub(super) const fn aal2() -> Self {
        Self {
            required_acr: Some(ACR_AAL2),
        }
    }
}

impl Default for RecentAuthenticationGuard {
    fn default() -> Self {
        Self::new()
    }
}

impl Guard for RecentAuthenticationGuard {
    async fn check(&self, ctx: &Context<'_>) -> Result<()> {
        let request = request_context(ctx)?;
        let now = Utc::now().timestamp();
        let max_age = self.policy().max_age.unwrap_or_default() as u64;
        let fresh = request
            .claims
            .auth_time
            .is_some_and(|auth_time| authentication_is_fresh(auth_time, now, max_age));
        let acr_satisfied = match self.required_acr {
            Some(required) => request
                .claims
                .acr
                .as_deref()
                .is_some_and(|acr| acr_satisfies(acr, required)),
            None => request.claims.acr.is_some(),
        };
        if fresh && acr_satisfied {
            return Ok(());
        }

        let params = ErrorParams::new();
        let message = error::localized_message(
            ctx,
            identity_application::error::codes::graphql::GraphqlErrorCode::RecentAuthenticationRequired,
            &params,
        );
        let correlation = error::correlation(ctx);
        Err(Error::new(message).extend_with(|_, extensions| {
            extensions.set("kind", "authorization_error");
            extensions.set("code", "insufficient_user_authentication");
            extensions.set("max_age", max_age);
            if let Some(required) = self.required_acr {
                extensions.set("acr_values", required);
            }
            correlation.apply(extensions);
        }))
    }
}

/// Dynamic recent-authentication requirement for account security changes.
///
/// The account only needs step-up when a second factor exists. The guard reads
/// the authoritative MFA/passkey state from the request-scoped services. It is
/// always composed with the required scope guard by the field declaration.
pub(super) struct MfaRecentAuthenticationGuard;

impl Guard for MfaRecentAuthenticationGuard {
    async fn check(&self, ctx: &Context<'_>) -> Result<()> {
        let request = request_context(ctx)?;
        let user_oid = request.user_oid()?;
        let state = request.state.clone();
        let status = state
            .services()
            .mfa()
            .status(user_oid)
            .await
            .map_err(|error| app_error(ctx, error))?;
        let has_passkeys = !state
            .services()
            .passkey()
            .list(user_oid)
            .await
            .map_err(|error| app_error(ctx, error))?
            .is_empty();
        if status.totp_enabled || has_passkeys {
            RecentAuthenticationGuard::aal2().check(ctx).await
        } else {
            RecentAuthenticationGuard::new().check(ctx).await
        }
    }
}
