//! Shared business RBAC issuance and online-validation policy.
//!
//! The helpers here never infer authority from a scope name, role key or
//! audience. They validate the immutable snapshot persisted with a credential
//! against current authoritative state, then intersect the token's already
//! granted business scopes with the current projection. They cannot add a
//! scope that was not originally granted.

use std::{collections::BTreeSet, sync::Arc};

use identity_domain::{
    authorization::catalog::is_management_scope_name,
    client_authorization::{
        AccessTokenPrincipal, AuthorizationSnapshotData, BusinessAuthorizationSnapshotData,
        ManagementAuthorizationSnapshotData,
    },
    openid_connect::{OpenIdConnectClient, ScopeSet},
    rbac::{
        ACCOUNT_SELF_SERVICE_SCOPES, RbacAuthorizationRepository, STANDARD_OIDC_SCOPES,
        effective_scope_names,
    },
    user::UserOid,
};

use josekit::jwt;
use serde_json::{Value, from_value, to_value};

use crate::{
    application::openid_connect::provider::OpenIdProviderService,
    error::{AppError, codes::openid_connect::OpenIdConnectErrorCode},
};

/// Signed JWT claim carrying the exact business snapshot. Management uses its
/// own explicit claim set; the two are never combined in one credential.
pub(crate) const RBAC_CLAIM: &str = "rbac";

#[must_use]
pub(crate) fn business_snapshot(
    snapshot: Option<&AuthorizationSnapshotData>,
) -> Option<&BusinessAuthorizationSnapshotData> {
    snapshot.and_then(AuthorizationSnapshotData::as_business)
}

#[must_use]
pub(crate) fn management_snapshot(
    snapshot: Option<&AuthorizationSnapshotData>,
) -> Option<&ManagementAuthorizationSnapshotData> {
    snapshot.and_then(AuthorizationSnapshotData::as_management)
}

#[must_use]
pub(crate) fn has_business_claims(payload: &jwt::JwtPayload) -> bool {
    payload.claim(RBAC_CLAIM).is_some()
}

pub(crate) fn signed_business_snapshot(
    payload: &jwt::JwtPayload,
) -> Result<Option<BusinessAuthorizationSnapshotData>, AppError> {
    let Some(value) = payload.claim(RBAC_CLAIM).cloned() else {
        return Ok(None);
    };
    from_value::<BusinessAuthorizationSnapshotData>(value)
        .map(Some)
        .map_err(AppError::map_source(OpenIdConnectErrorCode::InvalidToken))
}

pub(crate) fn validate_signed_business_snapshot(
    persisted: &BusinessAuthorizationSnapshotData,
    payload: &jwt::JwtPayload,
) -> Result<(), AppError> {
    let signed = signed_business_snapshot(payload)?
        .ok_or_else(|| AppError::from_code(OpenIdConnectErrorCode::InvalidToken))?;
    if &signed != persisted {
        return Err(AppError::from_code(OpenIdConnectErrorCode::InvalidToken));
    }
    Ok(())
}

#[must_use]
pub(crate) fn signed_business_claim(snapshot: &BusinessAuthorizationSnapshotData) -> Option<Value> {
    to_value(snapshot).ok()
}

/// Scope names that are neither protocol controls nor account/session
/// self-service scopes. Management names are rejected by callers before this
/// helper is used.
#[must_use]
pub(crate) fn business_scope_names(scope: &ScopeSet) -> BTreeSet<String> {
    scope
        .names()
        .into_iter()
        .filter(|name| {
            !STANDARD_OIDC_SCOPES.contains(name)
                && !ACCOUNT_SELF_SERVICE_SCOPES.contains(name)
                && !is_management_scope_name(name)
        })
        .map(|name| (*name).to_owned())
        .collect()
}

/// Rebuild a scope string retaining protocol controls and exactly the supplied
/// business scopes. Any self-service or management name is intentionally
/// dropped; callers must have rejected those combinations already.
#[must_use]
pub(crate) fn clip_scope(requested: &ScopeSet, business_scopes: &BTreeSet<String>) -> String {
    let mut names = requested
        .names()
        .into_iter()
        .filter(|name| STANDARD_OIDC_SCOPES.contains(name))
        .map(|name| (*name).to_owned())
        .collect::<Vec<_>>();
    names.extend(business_scopes.iter().cloned());
    names.join(" ")
}

/// Resource permissions carried by a machine token. Protocol controls are
/// excluded; management and custom API scopes are included because machines
/// have no human account/self-service identity.
#[must_use]
pub(crate) fn machine_resource_scope_names(scope: &ScopeSet) -> BTreeSet<String> {
    scope
        .names()
        .into_iter()
        .filter(|name| !STANDARD_OIDC_SCOPES.contains(name))
        .map(|name| (*name).to_owned())
        .collect()
}

/// A delegated human business token may not carry account/session
/// self-service or management scopes. Identity scopes remain protocol controls.
#[must_use]
pub(crate) fn has_non_business_authorization_scope(scope: &ScopeSet) -> bool {
    scope
        .names()
        .into_iter()
        .any(|name| ACCOUNT_SELF_SERVICE_SCOPES.contains(&name) || is_management_scope_name(name))
}

pub(crate) struct BusinessLivePorts<'a> {
    pub repository: Option<&'a Arc<dyn RbacAuthorizationRepository>>,
    pub provider_service: &'a Arc<OpenIdProviderService>,
}

/// The token-side facts checked against live business authorization.
pub(crate) struct BusinessTokenAuthorization<'a> {
    pub live_client: &'a OpenIdConnectClient,
    pub persisted: &'a BusinessAuthorizationSnapshotData,
    pub persisted_scope: &'a str,
    pub scope: &'a ScopeSet,
    pub principal: AccessTokenPrincipal,
    pub subject_user_oid: Option<UserOid>,
    pub audience: &'a [String],
}

/// Live validation used by UserInfo, GraphQL bearer validation and token
/// introspection. Missing ports fail closed for a business snapshot.
pub(crate) async fn validate_business_authorization(
    ports: BusinessLivePorts<'_>,
    token: BusinessTokenAuthorization<'_>,
) -> Result<(), AppError> {
    let BusinessTokenAuthorization {
        live_client,
        persisted,
        persisted_scope,
        scope,
        principal,
        subject_user_oid,
        audience,
    } = token;
    let invalid = || AppError::from_code(OpenIdConnectErrorCode::InvalidToken);
    if principal == AccessTokenPrincipal::User && has_non_business_authorization_scope(scope) {
        return Err(invalid());
    }
    if principal == AccessTokenPrincipal::Client && scope.has_api_scopes() {
        return Err(invalid());
    }
    if audience.len() != 1 || audience[0] != persisted.resource_uri {
        return Err(invalid());
    }
    let snapshot = persisted
        .to_snapshot()
        .map_err(AppError::map_source(OpenIdConnectErrorCode::InvalidToken))?;
    let repository = ports.repository.ok_or_else(invalid)?;
    let state = repository
        .validate_snapshot(&snapshot)
        .await
        .map_err(AppError::map_source(OpenIdConnectErrorCode::InvalidToken))?;

    match (principal, snapshot.user_oid) {
        (AccessTokenPrincipal::User, Some(snapshot_user)) => {
            if subject_user_oid != Some(snapshot_user) {
                return Err(invalid());
            }
            if state.user_enabled == Some(false) || state.user_locked == Some(true) {
                return Err(invalid());
            }
        }
        (AccessTokenPrincipal::Client, None) => {}
        _ => return Err(invalid()),
    }

    // The client ceiling is exact for the token's resource, not a flat list of
    // names that could belong to another resource with the same code.
    let client_scopes = ports
        .provider_service
        .client_scopes_for_resource(live_client, &persisted.resource_uri)
        .await
        .map_err(AppError::map_source(OpenIdConnectErrorCode::InvalidToken))?;
    if scope
        .names()
        .into_iter()
        .any(|name| !client_scopes.contains(name))
    {
        return Err(invalid());
    }

    let resource = [persisted.resource_uri.clone()];
    let selection = ports
        .provider_service
        .select_resources(&resource, &resource, persisted_scope)
        .await
        .map_err(AppError::map_source(OpenIdConnectErrorCode::InvalidToken))?;
    if selection.resources.len() != 1
        || selection.resources[0] != persisted.resource_uri
        || ScopeSet::parse(&selection.scope)
            .map(|selected| selected.to_scope_string())
            .ok()
            .as_deref()
            != Some(persisted_scope)
    {
        return Err(invalid());
    }

    let effective = effective_scope_names(&state)
        .map_err(AppError::map_source(OpenIdConnectErrorCode::InvalidToken))?;
    let required = match principal {
        AccessTokenPrincipal::User => business_scope_names(scope),
        AccessTokenPrincipal::Client => machine_resource_scope_names(scope),
    };
    if !required.iter().all(|scope| effective.contains(scope)) {
        return Err(invalid());
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use identity_domain::{
        client_authorization::{
            BusinessAuthorizationSnapshotData, BusinessBindingSnapshotData,
            BusinessRoleSnapshotData,
        },
        openid_connect::ScopeSet,
    };
    use josekit::jwt::JwtPayload;
    use serde_json::{Value, json};
    use uuid::Uuid;

    use super::{
        RBAC_CLAIM, business_scope_names, clip_scope, has_business_claims,
        signed_business_snapshot, validate_signed_business_snapshot,
    };

    fn snapshot() -> BusinessAuthorizationSnapshotData {
        BusinessAuthorizationSnapshotData {
            resource_oid: "11111111-1111-1111-1111-111111111111".to_owned(),
            resource_uri: "https://api.example.test".to_owned(),
            policy_version: Uuid::new_v4(),
            user_oid: Some("22222222-2222-2222-2222-222222222222".to_owned()),
            user_authorization_version: Some(Uuid::new_v4()),
            bindings: vec![BusinessBindingSnapshotData {
                binding_oid: "33333333-3333-3333-3333-333333333333".to_owned(),
                role_oid: "44444444-4444-4444-4444-444444444444".to_owned(),
            }],
            roles: vec![BusinessRoleSnapshotData {
                role_oid: "44444444-4444-4444-4444-444444444444".to_owned(),
            }],
        }
    }

    #[test]
    fn business_scope_and_protocol_controls_are_separated() {
        let scope = ScopeSet::parse("openid profile orders.read account.read management.user.read")
            .unwrap();
        assert_eq!(
            business_scope_names(&scope),
            ["orders.read".to_owned()].into_iter().collect()
        );
        assert_eq!(
            clip_scope(&scope, &["orders.read".to_owned()].into_iter().collect()),
            "openid profile orders.read"
        );
    }

    #[test]
    fn signed_business_claim_round_trips_and_rejects_tampering() {
        let data = snapshot();
        let mut payload = JwtPayload::new();
        payload.set_claim(RBAC_CLAIM, Some(json!(data))).unwrap();
        assert!(has_business_claims(&payload));
        let signed = signed_business_snapshot(&payload).unwrap().unwrap();
        assert_eq!(signed, data);
        validate_signed_business_snapshot(&data, &payload).unwrap();

        let mut changed = JwtPayload::new();
        changed
            .set_claim(RBAC_CLAIM, Some(Value::Object(Default::default())))
            .unwrap();
        assert!(validate_signed_business_snapshot(&data, &changed).is_err());
    }
}
