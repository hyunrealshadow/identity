//! Approval-time business RBAC clipping.
//!
//! This is the only place a human authorization request is converted into an
//! immutable business snapshot. The stored authorization request/code carries
//! the exact clipped business scope; unknown, unassigned or client-invalid
//! requests fail instead of silently falling back to the historical scope-only
//! path.

use std::collections::BTreeSet;

use identity_domain::{
    client_authorization::BusinessAuthorizationSnapshotData,
    openid_connect::{AuthorizationRequestData, CodeChallengeMethod, ResponseType, ScopeSet},
    rbac::{
        BusinessAuthorizationSnapshot, EffectivePermission, RbacAuthorizationError,
        RbacAuthorizationState, RoleAuthorizationSnapshot, UserRoleBindingSnapshot,
        effective_permissions, effective_scope_names,
    },
    user::UserOid,
};
use uuid::Uuid;

use crate::{
    error::{
        AppError,
        codes::{
            authorization::AuthorizationErrorCode, authorize::AuthorizeErrorCode,
            common::CommonErrorCode,
        },
    },
    observability::{BusinessEvent, EventValue},
    openid_connect::rbac as shared,
};

use super::AuthorizeService;

pub(super) struct RbacApproval {
    pub request: AuthorizationRequestData,
    pub snapshot: Option<BusinessAuthorizationSnapshotData>,
}

impl AuthorizeService {
    /// Clips business scopes for an approving human. Legacy resources and
    /// management requests are returned unchanged. A known requested business
    /// permission that the user cannot currently exercise is removed from the
    /// granted scope rather than granted by default.
    #[tracing::instrument(
        skip_all,
        name = "authorization.rbac.clip",
        fields(
            business_requested = tracing::field::Empty,
            business_granted = tracing::field::Empty
        )
    )]
    pub(super) async fn clip_rbac_for_approval(
        &self,
        request: &AuthorizationRequestData,
        user_oid: Uuid,
    ) -> Result<RbacApproval, AppError> {
        let requested = ScopeSet::parse(&request.scope)
            .map_err(AppError::map_source(AuthorizeErrorCode::ScopeInvalid))?;
        if requested.has_management_scopes() {
            // Management has its own clipping path.
            return Ok(RbacApproval {
                request: request.clone(),
                snapshot: None,
            });
        }
        let requested_business = shared::business_scope_names(&requested);
        // Only requests targeting a business resource are forced through the
        // snapshot path. The first-party GraphQL resource keeps account/session
        // self-service intrinsic and management on its own clipping path.
        let targets_rbac = !request.resources.is_empty()
            && self
                .provider_service
                .has_rbac_resource(&request.resources)
                .await?;
        if !targets_rbac && requested_business.is_empty() {
            return Ok(RbacApproval {
                request: request.clone(),
                snapshot: None,
            });
        }

        if request.resources.len() != 1 {
            return Err(AppError::from_code(CommonErrorCode::InvalidTarget));
        }
        let resource_uri = &request.resources[0];

        // Business authorization is code + S256 PKCE only. Implicit/hybrid
        // response types are rejected here as well as during request parsing.
        if request.response_type != ResponseType::Code {
            return Err(AppError::from_code(AuthorizeErrorCode::ResponseTypeInvalid)
                .with_param("response_type", request.response_type.to_string()));
        }
        if requested.has_api_scopes() {
            return Err(AppError::from_code(AuthorizeErrorCode::ScopeInvalid));
        }
        if request.code_challenge.as_deref().is_none_or(str::is_empty)
            || request.code_challenge_method != Some(CodeChallengeMethod::S256)
        {
            return Err(
                AppError::from_code(AuthorizeErrorCode::CodeChallengeMethodInvalid)
                    .with_param("code_challenge_method", "S256"),
            );
        }

        // Re-read the live client and its current allowed scopes. A client
        // assignment change after request validation must not be bypassed by an
        // already stored request.
        let client_oid = Uuid::parse_str(&request.client_id).map_err(AppError::map_source(
            AuthorizeErrorCode::StoredClientIdInvalid,
        ))?;
        let client = self
            .client_repo
            .find_by_oid(client_oid)
            .await
            .map_err(AppError::map_source(AuthorizeErrorCode::ClientLookupFailed))?
            .ok_or_else(|| AppError::from_code(AuthorizeErrorCode::ClientNotFound))?;

        let client_scopes = self
            .provider_service
            .client_scopes_for_resource(&client, resource_uri)
            .await?;
        let unassigned = requested
            .names()
            .into_iter()
            .filter(|name| !client_scopes.contains(*name))
            .collect::<Vec<_>>();
        if !unassigned.is_empty() {
            return Err(
                AppError::from_code(AuthorizeErrorCode::ScopeNotAssignedToClient)
                    .with_param("scopes", unassigned.join(", ")),
            );
        }

        // Re-resolve accepted scopes and permission mappings against live
        // resource state. Only a request that actually asks for business
        // scopes needs the full-coverage check; an identity-only request keeps
        // its protocol scopes and is still bound to the resource below.
        if !requested_business.is_empty() {
            let selection = self
                .provider_service
                .select_resources(&request.resources, &request.resources, &request.scope)
                .await?;
            if selection.scope != request.scope {
                return Err(AppError::from_code(CommonErrorCode::InvalidTarget));
            }
        }

        let repository = self
            .rbac_authorization_repo
            .as_ref()
            .ok_or_else(|| AppError::from_code(AuthorizationErrorCode::RbacPolicyUnavailable))?;
        let state = repository
            .authorization_state(UserOid(user_oid), resource_uri)
            .await
            .map_err(rbac_authorization_error)?;
        if state.user_enabled == Some(false) || state.user_locked == Some(true) {
            return Err(AppError::from_code(
                AuthorizeErrorCode::ImplicitUserNotFound,
            ));
        }
        // Never mint a business snapshot for a resource that is no longer live.
        if !state.resource.enabled {
            return Err(AppError::from_code(CommonErrorCode::InvalidTarget));
        }

        let requested_count = requested_business.len() as i64;
        let (granted, effective) = if requested_business.is_empty() {
            // Identity-only access needs no business permission projection at
            // all. It is still bound to the resource/user generation below.
            (BTreeSet::new(), Vec::new())
        } else {
            let effective = effective_permissions(&state)
                .map_err(AppError::map_source(AuthorizeErrorCode::ScopeInvalid))?;
            let effective_scopes = effective_scope_names(&state)
                .map_err(AppError::map_source(AuthorizeErrorCode::ScopeInvalid))?;

            // Every requested business name must still be a known, enabled
            // permission of this resource. Missing mappings are configuration
            // or client errors and must not be silently dropped.
            for scope in &requested_business {
                if state.resource.enabled_permission_for_scope(scope).is_none() {
                    return Err(AppError::from_code(CommonErrorCode::InvalidTarget));
                }
            }

            let granted = requested_business
                .into_iter()
                .filter(|scope| effective_scopes.contains(scope))
                .collect::<BTreeSet<_>>();
            (granted, effective)
        };

        let mut clipped_request = request.clone();
        clipped_request.scope = shared::clip_scope(&requested, &granted);
        let snapshot_data = build_approval_snapshot(&state, user_oid, &effective, &granted)?;

        tracing::Span::current().record("business_requested", requested_count);
        tracing::Span::current().record("business_granted", granted.len() as i64);
        self.events.emit(
            BusinessEvent::audit("authorization.rbac.clipped")
                .outcome(if granted.is_empty() {
                    "empty"
                } else {
                    "granted"
                })
                .attribute("client_oid", EventValue::Text(client_oid.to_string()))
                .attribute("business_requested", EventValue::Integer(requested_count))
                .attribute(
                    "business_granted",
                    EventValue::Integer(granted.len() as i64),
                )
                .attribute(
                    "resource_oid",
                    EventValue::Text(state.resource.resource_oid.to_string()),
                ),
        );

        Ok(RbacApproval {
            request: clipped_request,
            snapshot: Some(snapshot_data),
        })
    }
}

/// Build the immutable approval snapshot for exactly the granted business
/// scopes. An empty granted set is valid and still binds the resource/user
/// generation; it only omits binding and role rows.
fn build_approval_snapshot(
    state: &RbacAuthorizationState,
    user_oid: Uuid,
    effective: &[EffectivePermission],
    granted: &BTreeSet<String>,
) -> Result<BusinessAuthorizationSnapshotData, AppError> {
    let mut binding_oids = BTreeSet::new();
    let mut role_oids = BTreeSet::new();
    for permission in effective
        .iter()
        .filter(|permission| granted.contains(&permission.scope))
    {
        for source in &permission.sources {
            binding_oids.insert(source.binding_oid);
            role_oids.insert(source.role_oid);
        }
    }

    let mut bindings = Vec::with_capacity(binding_oids.len());
    for binding_oid in &binding_oids {
        let binding = state
            .bindings
            .iter()
            .find(|binding| binding.oid == *binding_oid)
            .ok_or_else(|| {
                AppError::from_code(AuthorizeErrorCode::ScopeInvalid)
                    .with_source(RbacApprovalError::MissingBinding)
            })?;
        if !binding.is_active() || !role_oids.contains(&binding.role_oid) {
            return Err(AppError::from_code(AuthorizeErrorCode::ScopeInvalid)
                .with_source(RbacApprovalError::InactiveBinding));
        }
        bindings.push(UserRoleBindingSnapshot::from_binding(binding));
    }
    let mut roles = Vec::with_capacity(role_oids.len());
    for role_oid in &role_oids {
        let role = state
            .roles
            .iter()
            .find(|role| role.oid == *role_oid)
            .ok_or_else(|| {
                AppError::from_code(AuthorizeErrorCode::ScopeInvalid)
                    .with_source(RbacApprovalError::MissingRole)
            })?;
        if !role.enabled {
            return Err(AppError::from_code(AuthorizeErrorCode::ScopeInvalid)
                .with_source(RbacApprovalError::DisabledRole));
        }
        roles.push(RoleAuthorizationSnapshot { role_oid: role.oid });
    }

    let user_version = state.user_authorization_version.ok_or_else(|| {
        AppError::from_code(AuthorizeErrorCode::ScopeInvalid)
            .with_source(RbacApprovalError::MissingUserAuthorizationVersion)
    })?;
    let snapshot = BusinessAuthorizationSnapshot::for_user(
        &state.resource,
        UserOid(user_oid),
        user_version,
        bindings,
        roles,
    );
    Ok(BusinessAuthorizationSnapshotData::from_snapshot(&snapshot))
}

/// Internal reason categories for a failed approval snapshot. They are never
/// exposed as public English parameters; the public code stays localized.
#[derive(Debug, thiserror::Error)]
enum RbacApprovalError {
    #[error("effective binding source is missing")]
    MissingBinding,
    #[error("effective binding source is not active")]
    InactiveBinding,
    #[error("effective role source is missing")]
    MissingRole,
    #[error("effective role source is disabled")]
    DisabledRole,
    #[error("user authorization generation is missing")]
    MissingUserAuthorizationVersion,
}

fn rbac_authorization_error(error: RbacAuthorizationError) -> AppError {
    match error {
        RbacAuthorizationError::UserNotFound => {
            AppError::from_code(AuthorizeErrorCode::ImplicitUserNotFound)
        }
        RbacAuthorizationError::ResourceNotFound | RbacAuthorizationError::CorruptRecord => {
            AppError::from_code(CommonErrorCode::InvalidTarget)
        }
        other @ RbacAuthorizationError::Snapshot(_) => {
            AppError::from_code(CommonErrorCode::InvalidTarget).with_source(other)
        }
        other @ RbacAuthorizationError::Storage(_) => {
            AppError::from_code(AuthorizationErrorCode::RbacPolicyUnavailable).with_source(other)
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use identity_domain::{
        authorization::ids::AuthorizationVersion,
        rbac::{RbacAuthorizationState, RbacResourceState, validate_business_snapshot},
        user::UserOid,
    };
    use uuid::Uuid;

    use super::build_approval_snapshot;

    fn version(value: u128) -> AuthorizationVersion {
        AuthorizationVersion::from_uuid(Uuid::from_u128(value))
    }

    fn state(
        user_version: AuthorizationVersion,
        policy_version: AuthorizationVersion,
    ) -> RbacAuthorizationState {
        RbacAuthorizationState {
            resource: RbacResourceState {
                resource_oid: identity_domain::rbac::ResourceOid::new(),
                resource_uri: "https://api.example.test".to_owned(),
                policy_version,
                enabled: true,
                accepted_scopes: Vec::new(),
                permissions: Vec::new(),
            },
            user_oid: Some(UserOid(Uuid::new_v4())),
            user_authorization_version: Some(user_version),
            user_enabled: Some(true),
            user_locked: Some(false),
            bindings: Vec::new(),
            roles: Vec::new(),
            memberships: Vec::new(),
            group_paths: Vec::new(),
        }
    }

    #[test]
    fn identity_only_snapshot_binds_resource_and_user_generation() {
        let user_version = version(4);
        let policy_version = version(7);
        let state = self::state(user_version, policy_version);
        let user_oid = state.user_oid.unwrap();
        let snapshot = build_approval_snapshot(&state, user_oid.0, &[], &BTreeSet::new()).unwrap();

        assert_eq!(snapshot.user_oid, Some(user_oid.0.to_string()));
        assert_eq!(
            snapshot.user_authorization_version,
            Some(user_version.as_uuid())
        );
        assert_eq!(
            snapshot.resource_oid,
            state.resource.resource_oid.0.to_string()
        );
        assert_eq!(snapshot.policy_version, policy_version.as_uuid());
        assert!(snapshot.bindings.is_empty());
        assert!(snapshot.roles.is_empty());
    }

    #[test]
    fn identity_only_snapshot_cannot_be_revived_by_a_later_generation() {
        let user_version = version(4);
        let policy_version = version(7);
        let state = self::state(user_version, policy_version);
        let user_oid = state.user_oid.unwrap();
        let snapshot = build_approval_snapshot(&state, user_oid.0, &[], &BTreeSet::new())
            .unwrap()
            .to_snapshot()
            .unwrap();
        validate_business_snapshot(&snapshot, &state).unwrap();

        let mut later = state;
        later.user_authorization_version = Some(version(5));
        assert!(validate_business_snapshot(&snapshot, &later).is_err());
    }
}
