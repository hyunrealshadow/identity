//! Shared management-scope policy helpers for OAuth issuance and validation.
//!
//! These helpers never infer authority from a scope name. They filter exact
//! trusted catalog entries against authoritative human RBAC state and the live
//! `client_scope` ceiling for the GraphQL resource. There is no separate
//! machine-management grant or client-management switch.

use std::sync::Arc;
use uuid::Uuid;

use identity_domain::{
    auth::ACR_AAL2,
    authorization::{
        ManagementAuthorityRepository, authority::UserPermissionAuthority, catalog::ManagementScope,
    },
    client_authorization::{
        AccessTokenPrincipal, AdministratorRoleData, ManagementAuthorizationSnapshotData,
        ManagementGrantKindData,
    },
    openid_connect::{API_RESOURCE, OpenIdConnectClient, ScopeSet, model::claim::JwtClaimNames},
};
use josekit::jwt;
use serde_json::{Value, from_value};

use crate::{
    application::openid_connect::provider::OpenIdProviderService,
    error::{AppError, codes::openid_connect::OpenIdConnectErrorCode},
};

/// Use the session's effective ACR. Historical AMR values survive the elevated
/// session window and must never promote a downgraded session back to AAL2.
#[must_use]
pub(crate) fn human_authentication_is_aal2(acr: Option<&str>, _amr: &[String]) -> bool {
    acr == Some(ACR_AAL2)
}

/// Ports needed to revalidate a management authorization snapshot against
/// current authoritative state.
pub(crate) struct ManagementLivePorts<'a> {
    pub binding_repo: Option<&'a Arc<dyn ManagementAuthorityRepository>>,
    pub provider_service: &'a Arc<OpenIdProviderService>,
}

/// Shared live validation for management authorization snapshots. Used by both
/// UserInfo/GraphQL bearer validation and token introspection so the two paths
/// never diverge: grant identity+fingerprint, catalog policy fingerprint, the
/// exact resource-owned client ceiling and resource scope membership are all
/// rechecked. No record optimistic-lock version participates.
pub(crate) async fn validate_management_authorization(
    ports: ManagementLivePorts<'_>,
    live_client: &OpenIdConnectClient,
    persisted: &ManagementAuthorizationSnapshotData,
    persisted_scope: &str,
    scope: &ScopeSet,
    principal: AccessTokenPrincipal,
) -> Result<(), AppError> {
    let invalid = || AppError::from_code(OpenIdConnectErrorCode::InvalidToken);
    if !scope.has_management_scopes() {
        return Err(invalid());
    }
    let snapshot_management = persisted.management_scopes();
    if !scope
        .management_scopes()
        .iter()
        .copied()
        .all(|scope| snapshot_management.contains(&scope))
    {
        return Err(invalid());
    }

    let snapshot = persisted.to_snapshot().map_err(|_| invalid())?;
    match persisted.grant_kind {
        ManagementGrantKindData::UserRbac => {
            if principal != AccessTokenPrincipal::User {
                return Err(invalid());
            }
            let repository = ports.binding_repo.ok_or_else(|| {
                invalid().with_param("reason", "user permission authority support unavailable")
            })?;
            repository
                .validate_snapshot(&snapshot)
                .await
                .map_err(|_| invalid())?;
        }
        // Historical machine/binding snapshots remain decodable but never
        // authorize new or continued access after the cutover.
        _ => {
            return Err(invalid());
        }
    }

    let client_fingerprint = ports
        .provider_service
        .client_authority_fingerprint(live_client)
        .await
        .map_err(|_| invalid())?;
    if client_fingerprint.as_uuid() != persisted.client_policy_version {
        return Err(invalid());
    }

    let client_scopes = ports
        .provider_service
        .client_scopes_for_resource(live_client, API_RESOURCE)
        .await
        .map_err(|_| invalid())?;
    if scope
        .names()
        .into_iter()
        .any(|name| !client_scopes.contains(name))
    {
        return Err(invalid());
    }
    let selection = ports
        .provider_service
        .select_resources(
            &[API_RESOURCE.to_owned()],
            &[API_RESOURCE.to_owned()],
            persisted_scope,
        )
        .await
        .map_err(|_| invalid())?;
    let selected = ScopeSet::parse(&selection.scope).map_err(|_| invalid())?;
    if selection.resources.len() != 1
        || selection.resources[0] != API_RESOURCE
        || selected.management_scopes() != scope.management_scopes()
    {
        return Err(invalid());
    }

    Ok(())
}

const MANAGEMENT_CLAIM_NAMES: [&str; 7] = [
    JwtClaimNames::MANAGEMENT_GRANT_KIND,
    JwtClaimNames::MANAGEMENT_GRANT_OID,
    JwtClaimNames::MANAGEMENT_GRANT_VERSION,
    JwtClaimNames::MANAGEMENT_POLICY_VERSION,
    JwtClaimNames::MANAGEMENT_CLIENT_POLICY_VERSION,
    JwtClaimNames::MANAGEMENT_ROLE,
    JwtClaimNames::MANAGEMENT_PERMISSIONS,
];

#[must_use]
pub(crate) fn has_management_claims(payload: &jwt::JwtPayload) -> bool {
    MANAGEMENT_CLAIM_NAMES
        .iter()
        .any(|name| payload.claim(name).is_some())
}

pub(crate) fn signed_management_snapshot(
    payload: &jwt::JwtPayload,
) -> Result<Option<ManagementAuthorizationSnapshotData>, AppError> {
    if !has_management_claims(payload) {
        return Ok(None);
    }
    let invalid = || AppError::from_code(OpenIdConnectErrorCode::InvalidToken);
    let grant_kind = payload
        .claim(JwtClaimNames::MANAGEMENT_GRANT_KIND)
        .and_then(Value::as_str)
        .ok_or_else(invalid)?;
    let grant_kind = from_value::<ManagementGrantKindData>(Value::String(grant_kind.to_owned()))
        .map_err(|_| invalid())?;
    let grant_oid = payload
        .claim(JwtClaimNames::MANAGEMENT_GRANT_OID)
        .and_then(Value::as_str)
        .ok_or_else(invalid)?
        .to_owned();
    let grant_version = payload
        .claim(JwtClaimNames::MANAGEMENT_GRANT_VERSION)
        .and_then(Value::as_str)
        .and_then(|value| Uuid::parse_str(value).ok())
        .filter(|value| !value.is_nil())
        .ok_or_else(invalid)?;
    let policy_version = payload
        .claim(JwtClaimNames::MANAGEMENT_POLICY_VERSION)
        .and_then(Value::as_str)
        .and_then(|value| Uuid::parse_str(value).ok())
        .filter(|value| !value.is_nil())
        .ok_or_else(invalid)?;
    let role_value = payload
        .claim(JwtClaimNames::MANAGEMENT_ROLE)
        .cloned()
        .ok_or_else(invalid)?;
    let role = from_value::<Option<AdministratorRoleData>>(role_value).map_err(|_| invalid())?;
    let permissions_value = payload
        .claim(JwtClaimNames::MANAGEMENT_PERMISSIONS)
        .cloned()
        .ok_or_else(invalid)?;
    let permissions = from_value::<Vec<String>>(permissions_value).map_err(|_| invalid())?;
    let client_policy_version = payload
        .claim(JwtClaimNames::MANAGEMENT_CLIENT_POLICY_VERSION)
        .and_then(Value::as_str)
        .and_then(|value| Uuid::parse_str(value).ok())
        .filter(|value| !value.is_nil())
        .ok_or_else(invalid)?;
    Ok(Some(ManagementAuthorizationSnapshotData {
        grant_kind,
        grant_oid,
        grant_version,
        policy_version,
        role,
        permissions,
        client_policy_version,
    }))
}

pub(crate) fn validate_signed_management_snapshot(
    persisted: &ManagementAuthorizationSnapshotData,
    payload: &jwt::JwtPayload,
) -> Result<(), AppError> {
    let signed = signed_management_snapshot(payload)?
        .ok_or_else(|| AppError::from_code(OpenIdConnectErrorCode::InvalidToken))?;
    if &signed != persisted {
        return Err(AppError::from_code(OpenIdConnectErrorCode::InvalidToken));
    }
    Ok(())
}

/// Management requests must use the authorization code response and exactly
/// the single GraphQL resource. Empty, external and multi-resource requests are
/// rejected rather than silently scoped down.
#[must_use]
pub(crate) fn is_single_graphql_resource(resources: &[String]) -> bool {
    resources.len() == 1 && resources[0] == API_RESOURCE
}

/// Human authorization-code clipping. A missing effective permission authority
/// or a human authentication weaker than the catalog requirement yields an
/// empty set; it never falls back to all requested management scopes and never
/// consults a role name or built-in group membership.
#[must_use]
pub(crate) fn allowed_human_management_scopes(
    requested: &ScopeSet,
    authority: Option<&UserPermissionAuthority>,
    human_aal2: bool,
) -> Vec<ManagementScope> {
    let Some(authority) = authority else {
        return Vec::new();
    };
    let mut allowed = Vec::new();
    for scope in requested.management_scopes() {
        if !authority.authorizes(scope) {
            continue;
        }
        if scope.human_authentication().requires_aal2() && !human_aal2 {
            continue;
        }
        allowed.push(scope);
    }
    allowed
}

/// Replaces the management subset of a parsed scope with the exact clipped set
/// and keeps every non-management scope unchanged.
#[must_use]
pub(crate) fn clipped_scope(
    requested: &ScopeSet,
    granted_management: impl IntoIterator<Item = ManagementScope>,
) -> ScopeSet {
    let mut result = requested.clone();
    result.replace_management_scopes(granted_management);
    result
}

#[cfg(test)]
mod tests {
    use uuid::Uuid;

    use identity_domain::{
        authorization::{
            authority::UserPermissionAuthority, catalog::ManagementScope, ids::AuthorizationVersion,
        },
        openid_connect::ScopeSet,
        user::UserOid,
    };

    use super::{
        allowed_human_management_scopes, clipped_scope, human_authentication_is_aal2,
        is_single_graphql_resource,
    };

    fn authority(
        permissions: impl IntoIterator<Item = ManagementScope>,
    ) -> UserPermissionAuthority {
        UserPermissionAuthority::new(
            UserOid(Uuid::new_v4()),
            AuthorizationVersion::new(),
            permissions,
        )
    }

    #[test]
    fn clipping_uses_exact_effective_permissions_and_never_role_names() {
        let requested = ScopeSet::parse(
            "openid management.user.read management.user.create management.administrator.write",
        )
        .unwrap();
        assert_eq!(
            allowed_human_management_scopes(
                &requested,
                Some(&authority([ManagementScope::UsersRead])),
                true
            ),
            vec![ManagementScope::UsersRead]
        );
        assert_eq!(
            allowed_human_management_scopes(
                &requested,
                Some(&authority([
                    ManagementScope::UsersRead,
                    ManagementScope::UsersCreate
                ])),
                true
            ),
            vec![ManagementScope::UsersRead, ManagementScope::UsersCreate]
        );
    }

    #[test]
    fn missing_authority_or_aal1_yields_an_empty_management_set() {
        let requested = ScopeSet::parse("openid management.user.read").unwrap();
        assert!(allowed_human_management_scopes(&requested, None, true).is_empty());
        assert!(
            allowed_human_management_scopes(
                &requested,
                Some(&authority([ManagementScope::UsersRead])),
                false
            )
            .is_empty()
        );
        assert!(human_authentication_is_aal2(Some("aal2"), &[]));
        assert!(!human_authentication_is_aal2(None, &["mfa".to_owned()]));
        assert!(!human_authentication_is_aal2(
            Some("aal1"),
            &["mfa".to_owned()]
        ));
    }

    #[test]
    fn clipping_keeps_base_scopes_and_removes_unapproved_management() {
        let requested =
            ScopeSet::parse("openid profile management.user.read management.user.create").unwrap();
        let clipped = clipped_scope(&requested, [ManagementScope::UsersRead]);
        assert_eq!(
            clipped.to_scope_string(),
            "openid profile management.user.read"
        );
    }

    #[test]
    fn graphql_resource_must_be_the_only_target() {
        assert!(is_single_graphql_resource(&[
            "urn:identity:graphql".to_owned()
        ]));
        assert!(!is_single_graphql_resource(&[]));
        assert!(!is_single_graphql_resource(&[
            "urn:identity:graphql".to_owned(),
            "https://api.example.com".to_owned()
        ]));
    }
}
