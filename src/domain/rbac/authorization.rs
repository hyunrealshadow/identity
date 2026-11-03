//! Business RBAC token authorization.
//!
//! A business authorization snapshot binds the exact resource policy version,
//! the opaque whole-user derived authority fingerprint, user-role binding
//! identities and role identities that authorized one issuance. Validation
//! compares the snapshot to current authoritative state; it never treats a
//! newly computed projection as proof that an old code, refresh token or access
//! token is still valid. Record optimistic-lock versions and display metadata
//! are not identity, so a CAS-only or metadata edit cannot by itself invalidate
//! an issued credential.
//!
//! Scope projection is separate from snapshot validation. Validation proves
//! the original grant is still authoritative; projection only decides which
//! of the already-granted business scopes remain effective. Neither direction
//! may add a scope the original grant did not contain.

use std::{
    collections::{BTreeMap, BTreeSet},
    error::Error as StdError,
};

use crate::{
    authorization::ids::AuthorizationVersion,
    client::model::ClientOid,
    rbac::{
        ids::{ResourceOid, RoleOid},
        model::{
            EffectivePermission, EffectivePermissionError, EffectivePermissionSources,
            GroupRolePath, ResourcePermission, Role, RolePermission, UserRoleBinding,
            project_effective_permissions,
        },
        snapshot::{BindingSnapshotError, UserAuthorizationSnapshot, UserRoleBindingSnapshot},
    },
    user::UserOid,
};

/// Current authoritative state for one API resource.
///
/// `accepted_scopes` is a read-only projection of the resource-owned canonical
/// scope rows. `policy_version` is a derived semantic boundary fingerprint, not
/// the resource record's optimistic-lock version.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RbacResourceState {
    pub resource_oid: ResourceOid,
    pub resource_uri: String,
    pub policy_version: AuthorizationVersion,
    pub enabled: bool,
    pub accepted_scopes: Vec<String>,
    pub permissions: Vec<ResourcePermission>,
}

impl RbacResourceState {
    #[must_use]
    pub fn enabled_permission_for_scope(&self, scope: &str) -> Option<&ResourcePermission> {
        self.permissions
            .iter()
            .find(|permission| permission.enabled && permission.scope == scope)
    }
}

/// Current authoritative RBAC facts for one user and one resource.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RbacAuthorizationState {
    pub resource: RbacResourceState,
    pub user_oid: Option<UserOid>,
    pub user_authorization_version: Option<AuthorizationVersion>,
    pub user_enabled: Option<bool>,
    pub user_locked: Option<bool>,
    /// The user's active direct bindings. Repository adapters may return only
    /// active rows; an absent snapshot binding is still rejected as no longer
    /// valid. Group authority is never rewritten into this list.
    pub bindings: Vec<UserRoleBinding>,
    /// Active group paths (`GroupMembership` + `GroupRoleBinding`) for the same
    /// user. They keep their own provenance and are not synthetic bindings.
    pub group_paths: Vec<GroupRolePath>,
    pub roles: Vec<Role>,
    /// Memberships that point at permissions of [`Self::resource`].
    pub memberships: Vec<RolePermission>,
}

/// Role identity carried by a business snapshot. The role's record version is
/// an optimistic lock and is intentionally not part of credential identity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RoleAuthorizationSnapshot {
    pub role_oid: RoleOid,
}

/// Immutable business authorization snapshot carried by codes and tokens.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BusinessAuthorizationSnapshot {
    pub resource_oid: ResourceOid,
    pub resource_uri: String,
    pub policy_version: AuthorizationVersion,
    pub user_oid: Option<UserOid>,
    pub user_authorization_version: Option<AuthorizationVersion>,
    pub bindings: Vec<UserRoleBindingSnapshot>,
    pub roles: Vec<RoleAuthorizationSnapshot>,
}

impl BusinessAuthorizationSnapshot {
    #[must_use]
    pub fn for_user(
        resource: &RbacResourceState,
        user_oid: UserOid,
        user_authorization_version: AuthorizationVersion,
        bindings: Vec<UserRoleBindingSnapshot>,
        roles: Vec<RoleAuthorizationSnapshot>,
    ) -> Self {
        Self {
            resource_oid: resource.resource_oid,
            resource_uri: resource.resource_uri.clone(),
            policy_version: resource.policy_version,
            user_oid: Some(user_oid),
            user_authorization_version: Some(user_authorization_version),
            bindings,
            roles,
        }
    }

    #[must_use]
    pub fn for_machine(resource: &RbacResourceState) -> Self {
        Self {
            resource_oid: resource.resource_oid,
            resource_uri: resource.resource_uri.clone(),
            policy_version: resource.policy_version,
            user_oid: None,
            user_authorization_version: None,
            bindings: Vec::new(),
            roles: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum BusinessSnapshotError {
    #[error("business snapshot resource does not match current state")]
    ResourceMismatch,
    #[error("business snapshot resource URI does not match current state")]
    ResourceUriMismatch,
    #[error("business snapshot resource is disabled")]
    ResourceDisabled,
    #[error(
        "business resource version mismatch: snapshot {snapshot}, current {current}; versions never reset"
    )]
    ResourceVersionMismatch {
        snapshot: AuthorizationVersion,
        current: AuthorizationVersion,
    },
    #[error("a machine business snapshot must not carry a user")]
    UnexpectedUser,
    #[error("a human business snapshot must carry its user")]
    MissingUser,
    #[error("business snapshot user does not match the authorized user")]
    UserMismatch,
    #[error("business snapshot user authorization generation is missing")]
    MissingUserAuthorizationVersion,
    #[error("business snapshot binding validation failed")]
    Binding(#[from] BindingSnapshotError),
    #[error("business role is missing: {0}")]
    RoleNotFound(RoleOid),
    #[error("business role is disabled: {0}")]
    RoleDisabled(RoleOid),
    #[error("business binding references a role missing from the snapshot: {0}")]
    MissingRoleSnapshot(RoleOid),
    #[error("business snapshot contains a duplicate role: {0}")]
    DuplicateRole(RoleOid),
}

/// Exact validation of the original business snapshot against authoritative
/// current state. Any revoked/disabled binding, replaced binding or role
/// identity, changed user authority fingerprint, resource policy change, or
/// semantic role relationship change (which changes the fingerprint)
/// invalidates the credential. A record version or display-metadata edit alone
/// does not.
pub fn validate_business_snapshot(
    snapshot: &BusinessAuthorizationSnapshot,
    state: &RbacAuthorizationState,
) -> Result<(), BusinessSnapshotError> {
    let resource = &state.resource;
    if snapshot.resource_oid != resource.resource_oid {
        return Err(BusinessSnapshotError::ResourceMismatch);
    }
    if snapshot.resource_uri != resource.resource_uri {
        return Err(BusinessSnapshotError::ResourceUriMismatch);
    }
    if !resource.enabled {
        return Err(BusinessSnapshotError::ResourceDisabled);
    }
    if snapshot.policy_version != resource.policy_version {
        return Err(BusinessSnapshotError::ResourceVersionMismatch {
            snapshot: snapshot.policy_version,
            current: resource.policy_version,
        });
    }

    match (snapshot.user_oid, state.user_oid) {
        (None, None) => {
            if snapshot.user_authorization_version.is_some()
                || !snapshot.bindings.is_empty()
                || !snapshot.roles.is_empty()
            {
                return Err(BusinessSnapshotError::UnexpectedUser);
            }
            return Ok(());
        }
        (None, Some(_)) | (Some(_), None) => return Err(BusinessSnapshotError::UserMismatch),
        (Some(snapshot_user), Some(current_user)) => {
            if snapshot_user != current_user {
                return Err(BusinessSnapshotError::UserMismatch);
            }
        }
    }

    let snapshot_version = snapshot
        .user_authorization_version
        .ok_or(BusinessSnapshotError::MissingUserAuthorizationVersion)?;
    UserAuthorizationSnapshot {
        user_authorization_version: snapshot_version,
        bindings: snapshot.bindings.clone(),
    }
    .validate(
        state
            .user_authorization_version
            .ok_or(BusinessSnapshotError::MissingUserAuthorizationVersion)?,
        &state.bindings,
    )?;

    let current_roles: BTreeMap<RoleOid, &Role> =
        state.roles.iter().map(|role| (role.oid, role)).collect();
    let mut snapshot_role_oids = BTreeSet::new();
    for role in &snapshot.roles {
        if !snapshot_role_oids.insert(role.role_oid) {
            return Err(BusinessSnapshotError::DuplicateRole(role.role_oid));
        }
        let Some(current) = current_roles.get(&role.role_oid).copied() else {
            return Err(BusinessSnapshotError::RoleNotFound(role.role_oid));
        };
        if !current.enabled {
            return Err(BusinessSnapshotError::RoleDisabled(role.role_oid));
        }
    }
    for binding in &snapshot.bindings {
        if !snapshot_role_oids.contains(&binding.role_oid) {
            return Err(BusinessSnapshotError::MissingRoleSnapshot(binding.role_oid));
        }
    }

    Ok(())
}

/// Effective business permissions with their explaining sources.
///
/// For a human this is the union of currently active bindings, enabled roles
/// and enabled permissions. For a machine it is the resource's enabled
/// permission catalog only; no user role is ever consulted.
pub fn effective_permissions(
    state: &RbacAuthorizationState,
) -> Result<Vec<EffectivePermission>, EffectivePermissionError> {
    match (state.user_oid, state.user_authorization_version) {
        (Some(user), Some(version)) => project_effective_permissions(EffectivePermissionSources {
            user_oid: user,
            requested_resource: state.resource.resource_oid,
            expected_authorization_version: version,
            current_authorization_version: version,
            bindings: &state.bindings,
            group_paths: &state.group_paths,
            roles: &state.roles,
            memberships: &state.memberships,
            permissions: &state.resource.permissions,
        }),
        (None, _) => Ok(state
            .resource
            .permissions
            .iter()
            .filter(|permission| permission.enabled)
            .map(|permission| EffectivePermission {
                permission_oid: permission.oid,
                resource_oid: permission.resource_oid,
                code: permission.code.as_str().to_owned(),
                scope: permission.scope.clone(),
                sources: Vec::new(),
                group_sources: Vec::new(),
            })
            .collect()),
        (Some(_), None) => Err(EffectivePermissionError::StaleAuthorizationVersion),
    }
}

/// Effective business scope names for the target resource.
pub fn effective_scope_names(
    state: &RbacAuthorizationState,
) -> Result<BTreeSet<String>, EffectivePermissionError> {
    Ok(effective_permissions(state)?
        .into_iter()
        .map(|permission| permission.scope)
        .collect())
}

#[derive(Debug, thiserror::Error)]
pub enum RbacAuthorizationError {
    #[error("business RBAC storage failure")]
    Storage(#[source] Box<dyn StdError + Send + Sync + 'static>),
    #[error("business resource was not found")]
    ResourceNotFound,
    #[error("business resource state is corrupt")]
    CorruptRecord,
    #[error("business user was not found")]
    UserNotFound,
    #[error("business authorization snapshot is stale")]
    Snapshot(#[from] BusinessSnapshotError),
}

/// Authoritative RBAC reads for token issuance and online validation.
///
/// Implementations must perform every read for one call inside one consistent
/// read transaction. They return current state; callers decide whether a
/// persisted snapshot is still valid.
#[async_trait::async_trait]
pub trait RbacAuthorizationRepository: Send + Sync {
    async fn resource_state(
        &self,
        resource_uri: &str,
    ) -> Result<RbacResourceState, RbacAuthorizationError>;

    async fn authorization_state(
        &self,
        user: UserOid,
        resource_uri: &str,
    ) -> Result<RbacAuthorizationState, RbacAuthorizationError>;

    /// Validate the immutable original snapshot against a consistent read and
    /// return the same authoritative state for the subsequent intersection.
    async fn validate_snapshot(
        &self,
        snapshot: &BusinessAuthorizationSnapshot,
    ) -> Result<RbacAuthorizationState, RbacAuthorizationError>;

    /// Exact `client_scope` ceiling for one client and target resource.
    ///
    /// Only live client scope rows whose scope row belongs to the target resource
    /// (or is a protocol scope with no resource) are returned. A duplicate code
    /// in another resource is never included. Implementations must fail closed
    /// on missing client/resource state rather than falling back to a flat list
    /// of client-assigned scope names.
    async fn client_scope_codes(
        &self,
        client: ClientOid,
        resource_uri: &str,
    ) -> Result<BTreeSet<String>, RbacAuthorizationError>;
}

#[cfg(test)]
mod tests {
    use chrono::{TimeZone, Utc};
    use uuid::Uuid;

    use super::{
        BusinessAuthorizationSnapshot, BusinessSnapshotError, RbacAuthorizationState,
        RbacResourceState, RoleAuthorizationSnapshot, effective_scope_names,
        validate_business_snapshot,
    };
    use crate::{
        authorization::ids::AuthorizationVersion,
        rbac::{
            LocalizedMetadata,
            ids::{
                ResourceOid, ResourcePermissionOid, RoleOid, RolePermissionOid, UserRoleBindingOid,
            },
            model::{ResourcePermission, Role, RolePermission, UserRoleBinding},
            snapshot::UserRoleBindingSnapshot,
        },
        user::UserOid,
    };

    fn at() -> chrono::DateTime<Utc> {
        Utc.timestamp_opt(1_000, 0).single().unwrap()
    }

    fn resource() -> RbacResourceState {
        RbacResourceState {
            resource_oid: ResourceOid::new(),
            resource_uri: "https://api.example.test".to_owned(),
            policy_version: AuthorizationVersion::new(),
            enabled: true,
            accepted_scopes: vec!["orders.read".to_owned()],
            permissions: vec![
                ResourcePermission::new(
                    ResourcePermissionOid::new(),
                    ResourceOid(Uuid::nil()),
                    "orders.read",
                    None,
                    at(),
                )
                .unwrap(),
            ],
        }
    }

    fn user_state() -> (
        UserOid,
        Role,
        UserRoleBinding,
        RolePermission,
        RbacResourceState,
        AuthorizationVersion,
    ) {
        let user = UserOid(Uuid::new_v4());
        let mut resource = self::resource();
        let role = Role::new(RoleOid::new(), "Orders", "", at()).unwrap();
        let permission = ResourcePermission::new(
            ResourcePermissionOid::new(),
            resource.resource_oid,
            "orders.read",
            None,
            at(),
        )
        .unwrap();
        resource.permissions = vec![permission.clone()];
        let binding = UserRoleBinding::new(
            UserRoleBindingOid::new(),
            user,
            role.oid,
            None,
            "grant",
            at(),
        )
        .unwrap();
        let membership = RolePermission {
            oid: RolePermissionOid::new(),
            role_oid: role.oid,
            permission_oid: permission.oid,
            created_at: at(),
        };
        // The opaque whole-user fingerprint is derived from semantic relations
        // and is independent of every record's optimistic-lock version.
        let authority_version = AuthorizationVersion::new();
        (user, role, binding, membership, resource, authority_version)
    }

    fn build_state(
        user: UserOid,
        role: &Role,
        binding: &UserRoleBinding,
        membership: &RolePermission,
        resource: RbacResourceState,
        user_authorization_version: AuthorizationVersion,
    ) -> RbacAuthorizationState {
        RbacAuthorizationState {
            resource,
            user_oid: Some(user),
            user_authorization_version: Some(user_authorization_version),
            user_enabled: Some(true),
            user_locked: Some(false),
            bindings: vec![binding.clone()],
            group_paths: Vec::new(),
            roles: vec![role.clone()],
            memberships: vec![membership.clone()],
        }
    }

    fn snapshot(
        user: UserOid,
        role: &Role,
        binding: &UserRoleBinding,
        resource: &RbacResourceState,
        user_authorization_version: AuthorizationVersion,
    ) -> BusinessAuthorizationSnapshot {
        BusinessAuthorizationSnapshot::for_user(
            resource,
            user,
            user_authorization_version,
            vec![UserRoleBindingSnapshot::from_binding(binding)],
            vec![RoleAuthorizationSnapshot { role_oid: role.oid }],
        )
    }

    #[test]
    fn current_snapshot_projects_only_enabled_business_scopes() {
        let (user, role, binding, membership, resource, authority_version) = user_state();
        let state = build_state(
            user,
            &role,
            &binding,
            &membership,
            resource.clone(),
            authority_version,
        );
        let snapshot = snapshot(user, &role, &binding, &resource, authority_version);
        validate_business_snapshot(&snapshot, &state).unwrap();
        assert_eq!(
            effective_scope_names(&state).unwrap(),
            ["orders.read".to_owned()].into_iter().collect()
        );
    }

    #[test]
    fn revoked_binding_disabled_role_or_resource_policy_change_invalidates_the_snapshot() {
        let (user, role, binding, membership, resource, authority_version) = user_state();
        let snapshot = snapshot(user, &role, &binding, &resource, authority_version);

        let mut revoked = binding.clone();
        revoked.revoke(at()).unwrap();
        let state = build_state(
            user,
            &role,
            &revoked,
            &membership,
            resource.clone(),
            authority_version,
        );
        assert!(matches!(
            validate_business_snapshot(&snapshot, &state),
            Err(BusinessSnapshotError::Binding(_))
        ));

        let mut disabled_role = role.clone();
        disabled_role.set_enabled(false, at()).unwrap();
        let state = build_state(
            user,
            &disabled_role,
            &binding,
            &membership,
            resource.clone(),
            authority_version,
        );
        assert_eq!(
            validate_business_snapshot(&snapshot, &state),
            Err(BusinessSnapshotError::RoleDisabled(role.oid))
        );

        let mut bumped_resource = resource.clone();
        bumped_resource.policy_version = AuthorizationVersion::new();
        let state = build_state(
            user,
            &role,
            &binding,
            &membership,
            bumped_resource,
            authority_version,
        );
        assert!(matches!(
            validate_business_snapshot(&snapshot, &state),
            Err(BusinessSnapshotError::ResourceVersionMismatch { .. })
        ));
    }

    #[test]
    fn metadata_and_record_version_changes_preserve_the_credential() {
        let (user, role, binding, membership, resource, authority_version) = user_state();
        let snapshot = snapshot(user, &role, &binding, &resource, authority_version);

        // A metadata edit rotates the role's optimistic-lock version but not
        // its semantic identity or the whole-user authority fingerprint.
        let mut edited_role = role.clone();
        edited_role
            .set_metadata(LocalizedMetadata::single("zh-CN", "订单", "订单权限"), at())
            .unwrap();
        assert_ne!(edited_role.version, role.version);
        assert_eq!(edited_role.oid, role.oid);

        // A CAS-only binding edit rotates its row version without replacing
        // the grant OID or the referenced role OID.
        let mut cas_only_binding = binding.clone();
        cas_only_binding.version = AuthorizationVersion::new();
        cas_only_binding.updated_at = Some(at());
        assert_ne!(cas_only_binding.version, binding.version);

        let state = build_state(
            user,
            &edited_role,
            &cas_only_binding,
            &membership,
            resource,
            authority_version,
        );
        validate_business_snapshot(&snapshot, &state).unwrap();
    }

    #[test]
    fn recreated_binding_or_changed_authority_fingerprint_is_rejected() {
        let (user, role, binding, membership, resource, authority_version) = user_state();
        let snapshot = snapshot(user, &role, &binding, &resource, authority_version);

        let regranted = UserRoleBinding::new(
            UserRoleBindingOid::new(),
            user,
            role.oid,
            None,
            "regrant",
            at(),
        )
        .unwrap();
        let state = build_state(
            user,
            &role,
            &regranted,
            &membership,
            resource.clone(),
            authority_version,
        );
        assert!(matches!(
            validate_business_snapshot(&snapshot, &state),
            Err(BusinessSnapshotError::Binding(_))
        ));

        // Replacing the semantic relationships changes the derived whole-user
        // fingerprint even when every record OID and version were preserved.
        let changed_authority = AuthorizationVersion::new();
        assert_ne!(changed_authority, authority_version);
        let state = build_state(
            user,
            &role,
            &binding,
            &membership,
            resource,
            changed_authority,
        );
        assert!(matches!(
            validate_business_snapshot(&snapshot, &state),
            Err(BusinessSnapshotError::Binding(_))
        ));
    }

    #[test]
    fn machine_snapshot_never_carries_user_state() {
        let resource = resource();
        let snapshot = BusinessAuthorizationSnapshot::for_machine(&resource);
        let state = RbacAuthorizationState {
            resource,
            user_oid: None,
            user_authorization_version: None,
            user_enabled: None,
            user_locked: None,
            bindings: Vec::new(),
            group_paths: Vec::new(),
            roles: Vec::new(),
            memberships: Vec::new(),
        };
        validate_business_snapshot(&snapshot, &state).unwrap();
        assert_eq!(
            effective_scope_names(&state).unwrap(),
            ["orders.read".to_owned()].into_iter().collect()
        );
    }
}
