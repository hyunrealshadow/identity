//! Unified RBAC aggregates.
//!
//! Permission identity is `(resource OID, code)`. The same action code in two
//! API resources is two different permissions and must never merge. Roles are
//! explicit unions of permissions with no inheritance, wildcard, implicit
//! write->read or deny precedence.
//!
//! Every managed row has exactly one UUID `version`. It is an equality token,
//! not a counter: a successful update stores a fresh random UUID and an old
//! credential snapshot can never become valid again.

use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::{
    authorization::ids::AuthorizationVersion,
    rbac::{
        boundary::BusinessScopeBoundaryError,
        ids::{
            GroupMembershipOid, GroupOid, GroupRoleOid, ResourceOid, ResourcePermissionOid,
            RoleOid, RolePermissionOid, UserRoleOid,
        },
        metadata::{LocalizedMetadata, LocalizedTextError},
    },
    user::UserOid,
};

/// Stable machine-facing permission code. Spaces and wildcard characters are
/// not permitted; dots separate action segments.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct PermissionCode(String);

impl PermissionCode {
    pub fn parse(value: impl Into<String>) -> Result<Self, RbacValidationError> {
        let value = value.into();
        let trimmed = value.trim();
        if trimmed.is_empty() || trimmed.chars().count() > 128 {
            return Err(RbacValidationError::InvalidPermissionCode);
        }
        if !trimmed.bytes().all(|byte| {
            byte.is_ascii_lowercase()
                || byte.is_ascii_digit()
                || matches!(byte, b'.' | b'_' | b'-' | b':')
        }) || trimmed.starts_with('.')
            || trimmed.ends_with('.')
        {
            return Err(RbacValidationError::InvalidPermissionCode);
        }
        Ok(Self(trimmed.to_owned()))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for PermissionCode {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

/// Permission projection of one owned scope row. It has no independent
/// definition: `oid`, `code`, `scope` and display metadata are the scope's own
/// values. `scope == code`; there is no second machine identity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResourcePermission {
    pub oid: ResourcePermissionOid,
    pub resource_oid: ResourceOid,
    pub code: PermissionCode,
    /// Always equal to `code`; kept for effective-permission projection.
    pub scope: String,
    /// Independent fallback description.
    pub name: String,
    pub description: Option<String>,
    pub built_in: bool,
    pub metadata: LocalizedMetadata,
    pub enabled: bool,
    pub version: AuthorizationVersion,
    pub created_at: DateTime<Utc>,
    pub updated_at: Option<DateTime<Utc>>,
}

impl ResourcePermission {
    pub fn new(
        oid: ResourcePermissionOid,
        resource_oid: ResourceOid,
        code: impl Into<String>,
        description: Option<String>,
        created_at: DateTime<Utc>,
    ) -> Result<Self, RbacValidationError> {
        let code = PermissionCode::parse(code)?;
        let metadata = LocalizedMetadata::default();
        Self::with_metadata(
            oid,
            resource_oid,
            code.as_str().to_owned(),
            code,
            metadata,
            description,
            created_at,
        )
    }

    pub fn with_metadata(
        oid: ResourcePermissionOid,
        resource_oid: ResourceOid,
        name: String,
        code: PermissionCode,
        metadata: LocalizedMetadata,
        description: Option<String>,
        created_at: DateTime<Utc>,
    ) -> Result<Self, RbacValidationError> {
        Ok(Self {
            oid,
            resource_oid,
            code: code.clone(),
            name,
            scope: code.as_str().to_owned(),
            description,
            built_in: false,
            metadata,
            enabled: true,
            version: AuthorizationVersion::fresh(),
            created_at,
            updated_at: None,
        })
    }

    /// Build the permission projection of a persisted scope row.
    #[allow(clippy::too_many_arguments)]
    pub fn from_scope(
        oid: ResourcePermissionOid,
        resource_oid: ResourceOid,
        code: impl Into<String>,
        name: String,
        metadata: LocalizedMetadata,
        description: Option<String>,
        built_in: bool,
        enabled: bool,
        version: AuthorizationVersion,
        created_at: DateTime<Utc>,
        updated_at: Option<DateTime<Utc>>,
    ) -> Result<Self, RbacValidationError> {
        let code = PermissionCode::parse(code)?;
        Ok(Self {
            oid,
            resource_oid,
            name,
            scope: code.as_str().to_owned(),
            code,
            description,
            built_in,
            metadata,
            enabled,
            version,
            created_at,
            updated_at,
        })
    }

    #[must_use]
    pub fn identity(&self) -> (ResourceOid, &str) {
        (self.resource_oid, self.code.as_str())
    }

    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    #[must_use]
    pub fn is_built_in(&self) -> bool {
        self.built_in
    }

    /// Trusted seed/install path only. No application command can select this.
    #[must_use]
    pub fn trusted_built_in(mut self) -> Self {
        self.built_in = true;
        self
    }

    /// Replace display metadata without changing authorization semantics. The
    /// row version still rotates because it also protects optimistic updates.
    pub fn set_metadata(
        &mut self,
        metadata: LocalizedMetadata,
        now: DateTime<Utc>,
    ) -> Result<(), RbacValidationError> {
        if self.built_in {
            return Err(RbacValidationError::BuiltInDefinition);
        }
        self.metadata = metadata;
        self.version = AuthorizationVersion::fresh();
        self.updated_at = Some(now);
        Ok(())
    }

    pub fn set_enabled(
        &mut self,
        enabled: bool,
        now: DateTime<Utc>,
    ) -> Result<(), RbacLifecycleError> {
        if self.enabled == enabled {
            return Ok(());
        }
        self.enabled = enabled;
        self.version = AuthorizationVersion::fresh();
        self.updated_at = Some(now);
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Role {
    pub oid: RoleOid,
    /// Independent fallback name.
    pub name: String,
    /// Independent fallback description.
    pub description: String,
    pub built_in: bool,
    pub metadata: LocalizedMetadata,
    pub enabled: bool,
    pub version: AuthorizationVersion,
    pub created_at: DateTime<Utc>,
    pub updated_at: Option<DateTime<Utc>>,
}

impl Role {
    pub fn new(
        oid: RoleOid,
        name: impl Into<String>,
        description: impl Into<String>,
        created_at: DateTime<Utc>,
    ) -> Result<Self, RbacValidationError> {
        let name = name.into();
        let description = description.into();
        if name.trim().is_empty() || name.chars().count() > 256 {
            return Err(RbacValidationError::InvalidRoleName);
        }
        Self::with_metadata(
            oid,
            name,
            description,
            LocalizedMetadata::default(),
            created_at,
        )
    }

    pub fn with_metadata(
        oid: RoleOid,
        name: String,
        description: String,
        metadata: LocalizedMetadata,
        created_at: DateTime<Utc>,
    ) -> Result<Self, RbacValidationError> {
        if name.trim().is_empty() || name.chars().count() > 256 {
            return Err(RbacValidationError::InvalidRoleName);
        }
        if description.chars().count() > 1024 {
            return Err(RbacValidationError::InvalidRoleDescription);
        }
        let metadata = LocalizedMetadata::canonicalize(metadata.names, metadata.descriptions)?;
        Ok(Self {
            oid,
            name,
            description,
            built_in: false,
            metadata,
            enabled: true,
            version: AuthorizationVersion::fresh(),
            created_at,
            updated_at: None,
        })
    }

    #[must_use]
    pub fn is_built_in(&self) -> bool {
        self.built_in
    }

    /// Trusted seed/install path only. No application command can select this.
    #[must_use]
    pub fn trusted_built_in(mut self) -> Self {
        self.built_in = true;
        self
    }

    /// Metadata-only edit. The row version rotates for optimistic concurrency;
    /// display edits do not change authority or invalidate issued credentials.
    pub fn set_metadata(
        &mut self,
        metadata: LocalizedMetadata,
        now: DateTime<Utc>,
    ) -> Result<(), RbacValidationError> {
        if self.built_in {
            return Err(RbacValidationError::BuiltInDefinition);
        }
        self.metadata = LocalizedMetadata::canonicalize(metadata.names, metadata.descriptions)?;
        self.version = AuthorizationVersion::fresh();
        self.updated_at = Some(now);
        Ok(())
    }

    pub fn set_enabled(
        &mut self,
        enabled: bool,
        now: DateTime<Utc>,
    ) -> Result<(), RbacLifecycleError> {
        if self.built_in {
            return Err(RbacLifecycleError::BuiltInProtected);
        }
        if self.enabled == enabled {
            return Ok(());
        }
        self.enabled = enabled;
        self.version = AuthorizationVersion::fresh();
        self.updated_at = Some(now);
        Ok(())
    }
}

/// Explicit role -> permission membership.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RolePermission {
    pub oid: RolePermissionOid,
    pub role_oid: RoleOid,
    pub permission_oid: ResourcePermissionOid,
    pub created_at: DateTime<Utc>,
}

/// User-role grant with independent identity and lifecycle. Revoking and
/// granting again creates a new OID/version; the old binding is never revived.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UserRole {
    pub oid: UserRoleOid,
    pub user_oid: UserOid,
    pub role_oid: RoleOid,
    pub granted_by_user_oid: Option<UserOid>,
    pub reason: String,
    pub enabled: bool,
    pub revoked_at: Option<DateTime<Utc>>,
    pub version: AuthorizationVersion,
    pub created_at: DateTime<Utc>,
    pub updated_at: Option<DateTime<Utc>>,
}

impl UserRole {
    pub fn new(
        oid: UserRoleOid,
        user_oid: UserOid,
        role_oid: RoleOid,
        granted_by_user_oid: Option<UserOid>,
        reason: impl Into<String>,
        created_at: DateTime<Utc>,
    ) -> Result<Self, RbacValidationError> {
        let reason = reason.into();
        let reason = reason.trim();
        if reason.chars().count() > 1_000 {
            return Err(RbacValidationError::InvalidBindingReason);
        }
        Ok(Self {
            oid,
            user_oid,
            role_oid,
            granted_by_user_oid,
            reason: reason.to_owned(),
            enabled: true,
            revoked_at: None,
            version: AuthorizationVersion::fresh(),
            created_at,
            updated_at: None,
        })
    }

    #[must_use]
    pub fn is_active(&self) -> bool {
        self.enabled && self.revoked_at.is_none()
    }

    pub fn revoke(&mut self, now: DateTime<Utc>) -> Result<(), RbacLifecycleError> {
        if !self.is_active() {
            return Err(RbacLifecycleError::AlreadyRevoked);
        }
        self.enabled = false;
        self.revoked_at = Some(now);
        self.version = AuthorizationVersion::fresh();
        self.updated_at = Some(now);
        Ok(())
    }
}

/// One role/binding source explaining why a permission is effective.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EffectivePermissionSource {
    pub user_role_oid: UserRoleOid,
    pub role_oid: RoleOid,
}

/// One active group path explaining group-derived authority. It keeps the
/// membership and group-role relation identities distinct from direct
/// `UserRole` sources; a group path is never rewritten as a synthetic
/// direct binding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GroupRolePath {
    pub membership_oid: GroupMembershipOid,
    pub group_oid: GroupOid,
    pub group_role_oid: GroupRoleOid,
    pub role_oid: RoleOid,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EffectiveGroupSource {
    pub membership_oid: GroupMembershipOid,
    pub group_oid: GroupOid,
    pub group_role_oid: GroupRoleOid,
    pub role_oid: RoleOid,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EffectivePermission {
    pub permission_oid: ResourcePermissionOid,
    pub resource_oid: ResourceOid,
    pub code: String,
    pub scope: String,
    /// Direct user-role bindings only.
    pub sources: Vec<EffectivePermissionSource>,
    /// Real group paths; empty when the permission is only held directly.
    pub group_sources: Vec<EffectiveGroupSource>,
}

impl EffectivePermission {
    #[must_use]
    pub fn identity(&self) -> (ResourceOid, &str) {
        (self.resource_oid, self.code.as_str())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum EffectivePermissionError {
    #[error("supplied user authorization version is stale")]
    StaleAuthorizationVersion,
    #[error("a business scope is mapped to more than one permission")]
    DuplicateScopeReference,
}

/// The authoritative snapshot one effective-permission projection reads.
///
/// The caller passes the user authorization version it verified and the
/// authoritative current version. Group paths must come from active
/// memberships, enabled built-in/custom groups and active group-role relations
/// loaded in the same snapshot.
#[derive(Debug, Clone, Copy)]
pub struct EffectivePermissionSources<'a> {
    pub user_oid: UserOid,
    pub requested_resource: ResourceOid,
    pub expected_authorization_version: AuthorizationVersion,
    pub current_authorization_version: AuthorizationVersion,
    pub bindings: &'a [UserRole],
    pub group_paths: &'a [GroupRolePath],
    pub roles: &'a [Role],
    pub memberships: &'a [RolePermission],
    pub permissions: &'a [ResourcePermission],
}

/// Compute the union of direct bindings and real active group paths for one
/// user and one target resource.
///
/// Bindings from another user, disabled or revoked bindings, disabled roles
/// and disabled permissions are excluded. Group provenance is returned
/// separately from direct bindings; no synthetic `UserRole` is created
/// for it.
pub fn project_effective_permissions(
    sources: EffectivePermissionSources<'_>,
) -> Result<Vec<EffectivePermission>, EffectivePermissionError> {
    let EffectivePermissionSources {
        user_oid,
        requested_resource,
        expected_authorization_version,
        current_authorization_version,
        bindings,
        group_paths,
        roles,
        memberships,
        permissions,
    } = sources;
    if expected_authorization_version != current_authorization_version {
        return Err(EffectivePermissionError::StaleAuthorizationVersion);
    }

    let roles_by_oid: BTreeMap<RoleOid, &Role> =
        roles.iter().map(|role| (role.oid, role)).collect();
    let permissions_by_oid: BTreeMap<ResourcePermissionOid, &ResourcePermission> = permissions
        .iter()
        .map(|permission| (permission.oid, permission))
        .collect();
    let memberships_by_role: BTreeMap<RoleOid, Vec<&RolePermission>> =
        memberships
            .iter()
            .fold(BTreeMap::new(), |mut map, membership| {
                map.entry(membership.role_oid).or_default().push(membership);
                map
            });

    let mut merged: BTreeMap<(ResourceOid, String), EffectivePermission> = BTreeMap::new();
    let mut scope_owner: BTreeMap<String, (ResourceOid, String)> = BTreeMap::new();

    for binding in bindings {
        if binding.user_oid != user_oid || !binding.is_active() {
            continue;
        }
        let Some(role) = roles_by_oid.get(&binding.role_oid).copied() else {
            continue;
        };
        if !role.enabled {
            continue;
        }
        for membership in memberships_by_role
            .get(&binding.role_oid)
            .into_iter()
            .flatten()
        {
            let Some(permission) = permissions_by_oid.get(&membership.permission_oid).copied()
            else {
                continue;
            };
            if !permission.enabled || permission.resource_oid != requested_resource {
                continue;
            }
            let identity = (permission.resource_oid, permission.code.as_str().to_owned());
            if let Some(existing) = scope_owner.get(&permission.scope) {
                if existing != &identity {
                    return Err(EffectivePermissionError::DuplicateScopeReference);
                }
            } else {
                scope_owner.insert(permission.scope.clone(), identity.clone());
            }
            let source = EffectivePermissionSource {
                user_role_oid: binding.oid,
                role_oid: role.oid,
            };
            merged
                .entry(identity)
                .and_modify(|effective| {
                    if !effective
                        .sources
                        .iter()
                        .any(|existing| existing.user_role_oid == source.user_role_oid)
                    {
                        effective.sources.push(source.clone());
                    }
                })
                .or_insert_with(|| EffectivePermission {
                    permission_oid: permission.oid,
                    resource_oid: permission.resource_oid,
                    code: permission.code.as_str().to_owned(),
                    scope: permission.scope.clone(),
                    sources: vec![source.clone()],
                    group_sources: Vec::new(),
                });
        }
    }

    for path in group_paths {
        let Some(role) = roles_by_oid.get(&path.role_oid).copied() else {
            continue;
        };
        if !role.enabled {
            continue;
        }
        for membership in memberships_by_role
            .get(&path.role_oid)
            .into_iter()
            .flatten()
        {
            let Some(permission) = permissions_by_oid.get(&membership.permission_oid).copied()
            else {
                continue;
            };
            if !permission.enabled || permission.resource_oid != requested_resource {
                continue;
            }
            let identity = (permission.resource_oid, permission.code.as_str().to_owned());
            if let Some(existing) = scope_owner.get(&permission.scope) {
                if existing != &identity {
                    return Err(EffectivePermissionError::DuplicateScopeReference);
                }
            } else {
                scope_owner.insert(permission.scope.clone(), identity.clone());
            }
            let source = EffectiveGroupSource {
                membership_oid: path.membership_oid,
                group_oid: path.group_oid,
                group_role_oid: path.group_role_oid,
                role_oid: path.role_oid,
            };
            merged
                .entry(identity)
                .and_modify(|effective| {
                    if !effective.group_sources.iter().any(|existing| {
                        existing.membership_oid == source.membership_oid
                            && existing.group_role_oid == source.group_role_oid
                    }) {
                        effective.group_sources.push(source.clone());
                    }
                })
                .or_insert_with(|| EffectivePermission {
                    permission_oid: permission.oid,
                    resource_oid: permission.resource_oid,
                    code: permission.code.as_str().to_owned(),
                    scope: permission.scope.clone(),
                    sources: Vec::new(),
                    group_sources: vec![source.clone()],
                });
        }
    }

    let mut effective: Vec<_> = merged.into_values().collect();
    for permission in &mut effective {
        permission
            .sources
            .sort_by_key(|source| (source.role_oid.0, source.user_role_oid.0));
        permission.group_sources.sort_by_key(|source| {
            (
                source.role_oid.0,
                source.group_oid.0,
                source.membership_oid.0,
                source.group_role_oid.0,
            )
        });
    }
    Ok(effective)
}

/// Project the effective OAuth scope names for one target resource.
pub fn project_scope_names(
    effective: &[EffectivePermission],
) -> Result<Vec<String>, EffectivePermissionError> {
    let mut names = BTreeSet::new();
    for permission in effective {
        if !names.insert(permission.scope.clone()) {
            return Err(EffectivePermissionError::DuplicateScopeReference);
        }
    }
    Ok(names.into_iter().collect())
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum RbacValidationError {
    #[error("the role description exceeds 1024 characters")]
    InvalidRoleDescription,
    #[error("permission code is invalid")]
    InvalidPermissionCode,
    #[error("role name is invalid")]
    InvalidRoleName,
    #[error("optional binding note exceeds the length limit")]
    InvalidBindingReason,
    #[error("business scope reference is invalid")]
    BusinessScope(#[from] BusinessScopeBoundaryError),
    #[error("built-in definitions are immutable at runtime")]
    BuiltInDefinition,
    #[error("localized metadata is invalid")]
    LocalizedMetadata(#[from] LocalizedTextError),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum RbacLifecycleError {
    #[error("binding is not active")]
    NotActive,
    #[error("binding is already revoked")]
    AlreadyRevoked,
    #[error("built-in definitions are immutable at runtime")]
    BuiltInProtected,
}

#[cfg(test)]
mod tests {
    use std::slice;

    use chrono::{TimeZone, Utc};
    use uuid::Uuid;

    use super::{
        EffectivePermissionError, EffectivePermissionSources, PermissionCode, RbacLifecycleError,
        RbacValidationError, ResourcePermission, Role, RolePermission, UserRole,
        project_effective_permissions, project_scope_names,
    };
    use crate::{
        authorization::ids::AuthorizationVersion,
        rbac::{
            LocalizedMetadata,
            ids::{ResourceOid, ResourcePermissionOid, RoleOid, RolePermissionOid, UserRoleOid},
        },
        user::UserOid,
    };

    fn at() -> chrono::DateTime<Utc> {
        Utc.timestamp_opt(1_000, 0).single().unwrap()
    }

    fn permission(resource: ResourceOid, code: &str) -> ResourcePermission {
        ResourcePermission::new(ResourcePermissionOid::new(), resource, code, None, at()).unwrap()
    }

    #[test]
    fn user_role_accepts_blank_reason_as_empty_annotation() {
        let binding = UserRole::new(
            UserRoleOid::new(),
            UserOid(Uuid::new_v4()),
            RoleOid::new(),
            None,
            "   ",
            at(),
        )
        .expect("blank binding reason is optional");
        assert_eq!(binding.reason, "");
        assert!(binding.is_active());
    }

    #[test]
    fn same_action_code_in_two_resources_remains_distinct() {
        let commerce = ResourceOid::new();
        let support = ResourceOid::new();
        let commerce_permission = permission(commerce, "orders.read");
        let support_permission = permission(support, "orders.read");
        assert_ne!(
            commerce_permission.identity(),
            support_permission.identity()
        );

        let role = Role::new(RoleOid::new(), "Orders", "", at()).unwrap();
        let binding = UserRole::new(
            UserRoleOid::new(),
            UserOid(Uuid::new_v4()),
            role.oid,
            None,
            "assign",
            at(),
        )
        .unwrap();
        let memberships = [
            RolePermission {
                oid: RolePermissionOid::new(),
                role_oid: role.oid,
                permission_oid: commerce_permission.oid,
                created_at: at(),
            },
            RolePermission {
                oid: RolePermissionOid::new(),
                role_oid: role.oid,
                permission_oid: support_permission.oid,
                created_at: at(),
            },
        ];
        let version = binding.version;
        let effective = project_effective_permissions(EffectivePermissionSources {
            user_oid: binding.user_oid,
            requested_resource: commerce,
            expected_authorization_version: version,
            current_authorization_version: version,
            bindings: slice::from_ref(&binding),
            group_paths: &[],
            roles: slice::from_ref(&role),
            memberships: &memberships,
            permissions: &[commerce_permission, support_permission],
        })
        .unwrap();
        assert_eq!(effective.len(), 1);
        assert_eq!(effective[0].code, "orders.read");
        assert_eq!(effective[0].scope, "orders.read");
    }

    #[test]
    fn revoked_binding_and_disabled_role_or_permission_do_not_contribute() {
        let user = UserOid(Uuid::new_v4());
        let resource = ResourceOid::new();
        let permission = permission(resource, "orders.read");
        let mut role = Role::new(RoleOid::new(), "Orders", "", at()).unwrap();
        let mut binding =
            UserRole::new(UserRoleOid::new(), user, role.oid, None, "assign", at()).unwrap();
        let membership = RolePermission {
            oid: RolePermissionOid::new(),
            role_oid: role.oid,
            permission_oid: permission.oid,
            created_at: at(),
        };

        let version = binding.version;
        let effective = project_effective_permissions(EffectivePermissionSources {
            user_oid: user,
            requested_resource: resource,
            expected_authorization_version: version,
            current_authorization_version: version,
            bindings: slice::from_ref(&binding),
            group_paths: &[],
            roles: slice::from_ref(&role),
            memberships: slice::from_ref(&membership),
            permissions: slice::from_ref(&permission),
        })
        .unwrap();
        assert_eq!(effective.len(), 1);

        binding.revoke(at()).unwrap();
        assert!(
            project_effective_permissions(EffectivePermissionSources {
                user_oid: user,
                requested_resource: resource,
                expected_authorization_version: binding.version,
                current_authorization_version: binding.version,
                bindings: slice::from_ref(&binding),
                group_paths: &[],
                roles: slice::from_ref(&role),
                memberships: slice::from_ref(&membership),
                permissions: slice::from_ref(&permission)
            })
            .unwrap()
            .is_empty()
        );

        let mut binding =
            UserRole::new(UserRoleOid::new(), user, role.oid, None, "assign", at()).unwrap();
        role.set_enabled(false, at()).unwrap();
        assert!(
            project_effective_permissions(EffectivePermissionSources {
                user_oid: user,
                requested_resource: resource,
                expected_authorization_version: binding.version,
                current_authorization_version: binding.version,
                bindings: slice::from_ref(&binding),
                group_paths: &[],
                roles: slice::from_ref(&role),
                memberships: slice::from_ref(&membership),
                permissions: slice::from_ref(&permission)
            })
            .unwrap()
            .is_empty()
        );

        let role = Role::new(RoleOid::new(), "Orders", "", at()).unwrap();
        let mut permission = self::permission(resource, "orders.read");
        permission.set_enabled(false, at()).unwrap();
        let membership = RolePermission {
            oid: RolePermissionOid::new(),
            role_oid: role.oid,
            permission_oid: permission.oid,
            created_at: at(),
        };
        binding.role_oid = role.oid;
        assert!(
            project_effective_permissions(EffectivePermissionSources {
                user_oid: user,
                requested_resource: resource,
                expected_authorization_version: binding.version,
                current_authorization_version: binding.version,
                bindings: slice::from_ref(&binding),
                group_paths: &[],
                roles: slice::from_ref(&role),
                memberships: slice::from_ref(&membership),
                permissions: slice::from_ref(&permission)
            })
            .unwrap()
            .is_empty()
        );
    }

    #[test]
    fn unions_are_deduplicated_and_explained_by_sources() {
        let user = UserOid(Uuid::new_v4());
        let resource = ResourceOid::new();
        let permission = permission(resource, "orders.read");
        let role_a = Role::new(RoleOid::new(), "Reader", "", at()).unwrap();
        let role_b = Role::new(RoleOid::new(), "Auditor", "", at()).unwrap();
        let binding_a =
            UserRole::new(UserRoleOid::new(), user, role_a.oid, None, "assign", at()).unwrap();
        let binding_b =
            UserRole::new(UserRoleOid::new(), user, role_b.oid, None, "assign", at()).unwrap();
        let memberships = [
            RolePermission {
                oid: RolePermissionOid::new(),
                role_oid: role_a.oid,
                permission_oid: permission.oid,
                created_at: at(),
            },
            RolePermission {
                oid: RolePermissionOid::new(),
                role_oid: role_b.oid,
                permission_oid: permission.oid,
                created_at: at(),
            },
        ];
        let version = binding_a.version;
        let effective = project_effective_permissions(EffectivePermissionSources {
            user_oid: user,
            requested_resource: resource,
            expected_authorization_version: version,
            current_authorization_version: version,
            bindings: &[binding_a, binding_b],
            group_paths: &[],
            roles: &[role_a, role_b],
            memberships: &memberships,
            permissions: slice::from_ref(&permission),
        })
        .unwrap();
        assert_eq!(effective.len(), 1);
        assert_eq!(effective[0].sources.len(), 2);
        assert_eq!(
            project_scope_names(&effective).unwrap(),
            vec!["orders.read".to_owned()]
        );
    }

    #[test]
    fn built_in_role_protection_does_not_depend_on_its_display_name() {
        let mut built_in = Role::new(RoleOid::new(), "Owner", "", at())
            .unwrap()
            .trusted_built_in();
        assert!(matches!(
            built_in.set_metadata(LocalizedMetadata::single("en-US", "Owner", ""), at()),
            Err(RbacValidationError::BuiltInDefinition)
        ));
        assert!(matches!(
            built_in.set_enabled(false, at()),
            Err(RbacLifecycleError::BuiltInProtected)
        ));

        let mut custom = Role::new(RoleOid::new(), "Owner", "", at()).unwrap();
        let version = custom.version;
        custom
            .set_metadata(LocalizedMetadata::single("en-US", "Custom owner", ""), at())
            .expect("custom role with a built-in-looking name stays editable");
        assert_ne!(custom.version, version);
        assert!(!custom.built_in);
        assert_eq!(
            custom.name, "Owner",
            "translation edits preserve default text"
        );
    }

    #[test]
    fn stale_user_version_is_rejected() {
        let user = UserOid(Uuid::new_v4());
        let resource = ResourceOid::new();
        assert_eq!(
            project_effective_permissions(EffectivePermissionSources {
                user_oid: user,
                requested_resource: resource,
                expected_authorization_version: AuthorizationVersion::new(),
                current_authorization_version: AuthorizationVersion::new(),
                bindings: &[],
                group_paths: &[],
                roles: &[],
                memberships: &[],
                permissions: &[]
            }),
            Err(EffectivePermissionError::StaleAuthorizationVersion)
        );
    }

    #[test]
    fn permission_code_is_the_only_machine_identity() {
        assert!(PermissionCode::parse("orders.read").is_ok());
        assert!(PermissionCode::parse("orders.*").is_err());
        assert!(PermissionCode::parse("orders read").is_err());
        let permission = ResourcePermission::new(
            ResourcePermissionOid::new(),
            ResourceOid::new(),
            "users.read",
            None,
            at(),
        )
        .unwrap();
        assert_eq!(permission.code.as_str(), permission.scope);
    }
}
