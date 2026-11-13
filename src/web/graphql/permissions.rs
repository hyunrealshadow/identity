use async_trait::async_trait;
use chrono::Utc;
use identity_application::{
    authorization::{
        CurrentManagementAuthority, DEFAULT_RECENT_AAL2_TTL, ManagementAuthorizationRequest,
        ManagementTarget, evaluate_management_authority,
    },
    error::{AppError, codes::common::CommonErrorCode},
};
use identity_domain::{
    authorization::ManagementAuthorityRepository,
    openid_connect::{API_RESOURCE, ScopeSet, resource::OAuthResourceRepository},
};
use identity_infrastructure::database::repository::oauth_resource::OAuthResourceRepositoryImpl;
use std::collections::BTreeSet;

use super::schema::{
    RequestContext,
    authorization::{EffectivePermissionsProvider, EffectivePermissionsView},
};

pub(super) struct LiveEffectivePermissions;

#[async_trait]
impl EffectivePermissionsProvider for LiveEffectivePermissions {
    async fn effective_permissions(
        &self,
        request: &RequestContext,
    ) -> Result<EffectivePermissionsView, AppError> {
        let repo = request.state.services().authorization();
        let (eligible, current) = if let Some(user) = request.claims.user_oid {
            let Some(authority) = repo
                .find_user_permission_authority(user)
                .await
                .map_err(AppError::from)?
            else {
                return Ok(empty());
            };
            (
                authority.permissions.clone(),
                CurrentManagementAuthority::UserPermissions(authority),
            )
        } else {
            let Some(authority) = repo
                .find_client_scope_authority(request.claims.client_oid)
                .await
                .map_err(AppError::from)?
            else {
                return Ok(empty());
            };
            (
                authority.permissions.clone(),
                CurrentManagementAuthority::ClientScopes(authority),
            )
        };
        let resource = OAuthResourceRepositoryImpl::new(request.state.resources().db().clone())
            .find_by_uri(API_RESOURCE)
            .await
            .map_err(AppError::map_source(CommonErrorCode::ResourceLookupFailed))?
            .ok_or_else(|| AppError::from_code(CommonErrorCode::ResourceLookupFailed))?;
        if !resource.enabled {
            return Ok(empty());
        }
        let allowed = ScopeSet::parse(&resource.scopes.join(" ")).map_err(AppError::internal)?;
        let requestable = eligible
            .into_iter()
            .filter(|scope| allowed.management_scopes().contains(scope))
            .collect::<BTreeSet<_>>();
        let snapshot = request
            .claims
            .management
            .as_ref()
            .map(|snapshot| snapshot.to_snapshot())
            .transpose()
            .map_err(AppError::internal)?;
        let version = ManagementAuthorityRepository::current_policy_version(repo.as_ref())
            .await
            .map_err(AppError::from)?;
        let granted = request
            .claims
            .scope
            .management_scopes()
            .into_iter()
            .collect::<BTreeSet<_>>();
        let effective_scopes = requestable
            .iter()
            .filter(|scope| {
                evaluate_management_authority(&ManagementAuthorizationRequest {
                    actor: &request.actor,
                    token_scopes: &granted,
                    required: **scope,
                    target: ManagementTarget::instance(),
                    current_authority: Some(&current),
                    snapshot: snapshot.as_ref(),
                    credential_client_boundary: None,
                    current_policy_version: version,
                    now: Utc::now(),
                    recent_aal2_ttl: DEFAULT_RECENT_AAL2_TTL,
                })
                .is_ok()
            })
            .map(|scope| scope.name().to_owned())
            .collect();
        Ok(EffectivePermissionsView {
            requestable_scopes: requestable
                .iter()
                .map(|scope| scope.name().to_owned())
                .collect(),
            effective_scopes,
        })
    }
}

fn empty() -> EffectivePermissionsView {
    EffectivePermissionsView {
        requestable_scopes: vec![],
        effective_scopes: vec![],
    }
}
