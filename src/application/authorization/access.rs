//! Live management access for an authenticated request.
//!
//! Transports pass the request's principal, token scopes and parsed snapshot;
//! this service loads the live authority and evaluates the shared policy, so
//! no transport reads authorization repositories itself.

use std::{collections::BTreeSet, sync::Arc};

use chrono::Utc;
use identity_domain::{
    authorization::{
        ActorContext, ClientScopeAuthority, ManagementAuthorityRepository,
        ManagementAuthorizationSnapshot, ManagementScope,
    },
    client::model::ClientOid,
    openid_connect::{API_RESOURCE, ScopeSet, resource::OAuthResourceRepository},
    user::UserOid,
};

use super::policy::{
    CurrentManagementAuthority, DEFAULT_RECENT_AAL2_TTL, ManagementAuthorizationRequest,
    ManagementTarget, ManagementTargetKind, evaluate_management_authority,
};
use crate::error::{AppError, codes::common};

/// Who holds the access token: a signed-in user, or a client acting for itself.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ManagementPrincipal {
    User(UserOid),
    Client(ClientOid),
}

/// The request-scoped facts a management decision depends on.
pub struct ManagementAccessRequest<'a> {
    pub actor: &'a ActorContext,
    pub principal: ManagementPrincipal,
    pub token_scopes: &'a BTreeSet<ManagementScope>,
    pub snapshot: Option<&'a ManagementAuthorizationSnapshot>,
}

/// Management scopes the principal could request, and those the current
/// token is effectively allowed to use.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct EffectiveManagementPermissions {
    pub requestable: Vec<ManagementScope>,
    pub effective: Vec<ManagementScope>,
}

#[derive(Clone)]
pub struct ManagementAccessService {
    authority: Arc<dyn ManagementAuthorityRepository>,
    resources: Arc<dyn OAuthResourceRepository>,
}

impl ManagementAccessService {
    pub fn new(
        authority: Arc<dyn ManagementAuthorityRepository>,
        resources: Arc<dyn OAuthResourceRepository>,
    ) -> Self {
        Self {
            authority,
            resources,
        }
    }

    /// Live authority of `principal`; `None` when it no longer exists.
    pub async fn current_authority(
        &self,
        principal: ManagementPrincipal,
    ) -> Result<Option<CurrentManagementAuthority>, AppError> {
        Ok(match principal {
            ManagementPrincipal::User(user) => self
                .authority
                .find_user_permission_authority(user)
                .await?
                .map(CurrentManagementAuthority::UserPermissions),
            ManagementPrincipal::Client(client) => self
                .authority
                .find_client_scope_authority(client)
                .await?
                .map(CurrentManagementAuthority::ClientScopes),
        })
    }

    /// Live machine ceiling of `client`; `None` when the client is gone.
    pub async fn client_scope_authority(
        &self,
        client: ClientOid,
    ) -> Result<Option<ClientScopeAuthority>, AppError> {
        Ok(self.authority.find_client_scope_authority(client).await?)
    }

    /// Require `required` on `target` for this request.
    pub async fn authorize(
        &self,
        request: &ManagementAccessRequest<'_>,
        required: ManagementScope,
        mut target: ManagementTarget,
    ) -> Result<(), AppError> {
        let current = self.current_authority(request.principal).await?;
        // The flag means "target is a full recoverable capability holder",
        // never membership in a fixed role or built-in group.
        target.is_instance_owner = target.kind == ManagementTargetKind::User
            && self
                .authority
                .find_user_permission_authority(UserOid(target.oid))
                .await?
                .is_some_and(|authority| authority.has_full_management_permissions());
        let policy_version = self.authority.current_policy_version().await?;
        evaluate_management_authority(&ManagementAuthorizationRequest {
            actor: request.actor,
            token_scopes: request.token_scopes,
            required,
            target,
            current_authority: current.as_ref(),
            snapshot: request.snapshot,
            credential_client_boundary: None,
            current_policy_version: policy_version,
            now: Utc::now(),
            recent_aal2_ttl: DEFAULT_RECENT_AAL2_TTL,
        })?;
        Ok(())
    }

    /// Management scopes the principal may request through the first-party
    /// API resource, and which of them the current token may use now.
    pub async fn effective_permissions(
        &self,
        request: &ManagementAccessRequest<'_>,
    ) -> Result<EffectiveManagementPermissions, AppError> {
        let Some(current) = self.current_authority(request.principal).await? else {
            return Ok(EffectiveManagementPermissions::default());
        };
        let eligible = match &current {
            CurrentManagementAuthority::UserPermissions(authority) => &authority.permissions,
            CurrentManagementAuthority::ClientScopes(authority) => &authority.permissions,
        };
        let resource = self
            .resources
            .find_by_uri(API_RESOURCE)
            .await
            .map_err(common::error::ResourceLookupFailed::map_source())?
            .ok_or_else(|| common::error::ResourceLookupFailed.into_error())?;
        if !resource.enabled {
            return Ok(EffectiveManagementPermissions::default());
        }
        let allowed = ScopeSet::parse(&resource.scopes.join(" "))
            .map_err(AppError::map_internal("authorization.api_resource_scopes"))?
            .management_scopes();
        let requestable = eligible
            .iter()
            .copied()
            .filter(|scope| allowed.contains(scope))
            .collect::<BTreeSet<_>>();
        let policy_version = self.authority.current_policy_version().await?;
        let effective = requestable
            .iter()
            .copied()
            .filter(|scope| {
                evaluate_management_authority(&ManagementAuthorizationRequest {
                    actor: request.actor,
                    token_scopes: request.token_scopes,
                    required: *scope,
                    target: ManagementTarget::instance(),
                    current_authority: Some(&current),
                    snapshot: request.snapshot,
                    credential_client_boundary: None,
                    current_policy_version: policy_version,
                    now: Utc::now(),
                    recent_aal2_ttl: DEFAULT_RECENT_AAL2_TTL,
                })
                .is_ok()
            })
            .collect();
        Ok(EffectiveManagementPermissions {
            requestable: requestable.into_iter().collect(),
            effective,
        })
    }
}
