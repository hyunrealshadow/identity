//! Shared async-graphql guard for forthcoming functional management fields.
use super::{authorization::request_context, error::app_error};
use async_graphql::{Context, ErrorExtensions, Guard, Result};
use chrono::Utc;
use identity_application::{
    authorization::{
        CurrentManagementAuthority, DEFAULT_RECENT_AAL2_TTL, ManagementAuthorizationError,
        ManagementAuthorizationRequest, ManagementTarget, ManagementTargetKind,
        evaluate_management_authority,
    },
    error::{AppError, codes::authorization::AuthorizationErrorCode},
};
use identity_domain::{
    authorization::{ManagementAuthorityRepository, ManagementScope},
    user::UserOid,
};

pub(crate) struct ManagementGuard {
    required: ManagementScope,
    target: ManagementTarget,
}

impl ManagementGuard {
    pub(crate) fn policy(required: ManagementScope) -> super::access::AccessPolicy {
        super::access::AccessPolicy::management(required)
    }

    pub(crate) const fn new(required: ManagementScope, target: ManagementTarget) -> Self {
        Self { required, target }
    }
}

impl Guard for ManagementGuard {
    async fn check(&self, ctx: &Context<'_>) -> Result<()> {
        let request = request_context(ctx)?;
        let repo = request.state.services().authorization();
        let current = if let Some(user) = request.claims.user_oid {
            repo.find_user_permission_authority(user)
                .await
                .map_err(|error| app_error(ctx, error.into()))?
                .map(CurrentManagementAuthority::UserPermissions)
        } else {
            repo.find_client_scope_authority(request.claims.client_oid)
                .await
                .map_err(|error| app_error(ctx, error.into()))?
                .map(CurrentManagementAuthority::ClientScopes)
        };
        let mut target = self.target;
        // The flag now means "target is a full recoverable capability holder",
        // never membership in a fixed role or built-in group.
        target.is_instance_owner = if target.kind == ManagementTargetKind::User {
            repo.find_user_permission_authority(UserOid(target.oid))
                .await
                .map_err(|error| app_error(ctx, error.into()))?
                .is_some_and(|authority| authority.has_full_management_permissions())
        } else {
            false
        };
        let snapshot = request
            .claims
            .management
            .as_ref()
            .map(|snapshot| snapshot.to_snapshot())
            .transpose()
            .map_err(|_| {
                app_error(
                    ctx,
                    AppError::from_code(AuthorizationErrorCode::AuthorizationSnapshotExpired),
                )
            })?;
        let policy_version = ManagementAuthorityRepository::current_policy_version(repo.as_ref())
            .await
            .map_err(|error| app_error(ctx, error.into()))?;
        let scopes = request
            .claims
            .scope
            .management_scopes()
            .into_iter()
            .collect::<std::collections::BTreeSet<_>>();
        evaluate_management_authority(&ManagementAuthorizationRequest {
            actor: &request.actor,
            token_scopes: &scopes,
            required: self.required,
            target,
            current_authority: current.as_ref(),
            snapshot: snapshot.as_ref(),
            credential_client_boundary: None,
            current_policy_version: policy_version,
            now: Utc::now(),
            recent_aal2_ttl: DEFAULT_RECENT_AAL2_TTL,
        })
        .map(|_| ())
        .map_err(|error| {
            let step_up = matches!(
                error,
                ManagementAuthorizationError::AuthenticationRequired { .. }
                    | ManagementAuthorizationError::RecentAuthenticationRequired
            );
            let recent = matches!(
                error,
                ManagementAuthorizationError::RecentAuthenticationRequired
            );
            let error = app_error(ctx, error.into());
            if step_up {
                error.extend_with(|_, extensions| {
                    extensions.set("applicationCode", 27021);
                    extensions.set("code", "insufficient_user_authentication");
                    extensions.set("acr_values", "aal2");
                    if recent {
                        extensions.set("max_age", DEFAULT_RECENT_AAL2_TTL.as_secs());
                    }
                })
            } else {
                error
            }
        })
    }
}
