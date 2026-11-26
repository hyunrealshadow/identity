use std::result::Result as StdResult;

use async_graphql::{Context, Guard, Result};
use chrono::Utc;
use identity_application::error::{AppError, StepUpChallenge, codes::graphql};
use identity_domain::{
    auth::{AuthenticationContextClass, authentication_is_fresh},
    openid_connect::ApiScope,
};

use super::{access::AccessPolicy, context::RequestContext, error::app_error};

pub(super) fn request_context<'a>(ctx: &'a Context<'_>) -> Result<&'a RequestContext> {
    ctx.data::<RequestContext>()
        .map_err(|_| app_error(ctx, graphql::error::AuthenticationContextUnavailable))
}

/// Result of the principal-specific effective-permission adapter. The default
/// adapter never grants a management scope.
pub(crate) struct EffectivePermissionsView {
    pub requestable_scopes: Vec<String>,
    pub effective_scopes: Vec<String>,
}

/// Adapter port for the effective-permission repository lookup.
///
/// The parent injects an implementation backed by the unified RBAC
/// repository. This module deliberately does not depend on `AppServices`
/// internals: the absence of an injected provider means an ordinary
/// self-service principal with no management scopes.
#[async_trait::async_trait]
pub(crate) trait EffectivePermissionsProvider: Send + Sync {
    async fn effective_permissions(
        &self,
        request: &RequestContext,
    ) -> StdResult<EffectivePermissionsView, AppError>;
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
    pub(crate) fn policy(scope: ApiScope) -> AccessPolicy {
        AccessPolicy::scope(scope)
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
        Err(app_error(
            ctx,
            graphql::error::InsufficientScope::new(scope)
                .into_error()
                .with_required_scopes([scope]),
        ))
    }
}

/// Requires recent authentication, optionally at a specific ACR.
///
/// `aal2()` requires both AAL2 assurance and freshness within the elevated
/// window. The generic guard requires recent AAL1-or-better authentication
/// within the ordinary recent window.
pub(super) struct RecentAuthenticationGuard {
    required_acr: Option<AuthenticationContextClass>,
}

impl RecentAuthenticationGuard {
    pub(crate) fn policy(&self) -> AccessPolicy {
        AccessPolicy::recent(self.required_acr == Some(AuthenticationContextClass::MultiFactor))
    }

    pub(super) const fn new() -> Self {
        Self { required_acr: None }
    }

    pub(super) const fn aal2() -> Self {
        Self {
            required_acr: Some(AuthenticationContextClass::MultiFactor),
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
                .is_some_and(|acr| acr.satisfies(required)),
            None => request.claims.acr.is_some(),
        };
        if fresh && acr_satisfied {
            return Ok(());
        }

        Err(app_error(
            ctx,
            graphql::error::RecentAuthenticationRequired
                .into_error()
                .with_step_up(StepUpChallenge {
                    acr: self.required_acr,
                    max_age_secs: Some(max_age),
                }),
        ))
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
        let has_mfa = request
            .state
            .services()
            .login()
            .has_second_factor(user_oid)
            .await
            .map_err(|error| app_error(ctx, error))?;
        if has_mfa {
            RecentAuthenticationGuard::aal2().check(ctx).await
        } else {
            RecentAuthenticationGuard::new().check(ctx).await
        }
    }
}
