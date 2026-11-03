//! Immutable authorization snapshots.
//!
//! Tokens, authorization codes and future refresh-token families keep the exact
//! grant OID and a derived authority fingerprint. Validation compares the
//! snapshot to authoritative current semantic state; a recreated/re-granted
//! record with the same permissions is still rejected because its OID and/or
//! fingerprint differ. Record version UUIDs are optimistic-lock tokens only and
//! never appear here.

use std::{
    collections::BTreeSet,
    fmt::{Debug as FmtDebug, Display, Formatter, Result as FmtResult},
};

use uuid::Uuid;

use crate::authorization::{
    administrator::AdministratorBinding,
    authority::UserPermissionAuthority,
    catalog::{AdministratorRole, ManagementScope},
    ids::{AdministratorBindingOid, AuthorizationVersion, PolicyVersion},
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ManagementGrantKind {
    /// Historical only. Existing snapshots remain decodable so history and
    /// revocation records can be read, but they never authorize a runtime
    /// operation after the unified-RBAC cutover.
    AdministratorBinding,
    /// Current human authority: the user's effective permissions and semantic
    /// authorization dependencies, excluding record optimistic locks.
    UserRbac,
}

/// Snapshot carried by an authorization credential. It intentionally does not
/// treat role/permission names as identity; those fields only make audit and
/// diagnostics explainable.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManagementAuthorizationSnapshot {
    pub grant_kind: ManagementGrantKind,
    pub grant_oid: Uuid,
    pub grant_fingerprint: AuthorizationVersion,
    pub policy_version: PolicyVersion,
    pub role: Option<AdministratorRole>,
    pub permissions: BTreeSet<ManagementScope>,
}

impl ManagementAuthorizationSnapshot {
    #[must_use]
    pub fn for_administrator_binding(
        binding: &AdministratorBinding,
        policy_version: PolicyVersion,
    ) -> Self {
        Self {
            grant_kind: ManagementGrantKind::AdministratorBinding,
            grant_oid: binding.oid.0,
            grant_fingerprint: binding.version,
            policy_version,
            role: Some(binding.role),
            permissions: BTreeSet::new(),
        }
    }

    /// Current human snapshot. The grant identity is the user OID; the
    /// fingerprint describes semantic authority and the permission set is exact.
    #[must_use]
    pub fn for_user_permissions(
        authority: &UserPermissionAuthority,
        policy_version: PolicyVersion,
    ) -> Self {
        Self {
            grant_kind: ManagementGrantKind::UserRbac,
            grant_oid: authority.user_oid.0,
            grant_fingerprint: authority.version,
            policy_version,
            role: None,
            permissions: authority.permissions.clone(),
        }
    }
}

#[derive(Clone, PartialEq, Eq, thiserror::Error)]
pub enum SnapshotValidationError {
    #[error("authorization grant not found")]
    GrantNotFound,
    #[error("authorization grant kind does not match the snapshot")]
    GrantKindMismatch,
    #[error("this authorization grant kind is historical and cannot authorize runtime access")]
    RetiredGrantKind,
    #[error("authorization grant is revoked or disabled")]
    Tombstoned,
    #[error("authorization grant OID changed; a recreated grant cannot revive the snapshot")]
    OidMismatch { snapshot: Uuid, current: Uuid },
    #[error("authorization fingerprint mismatch; issued authority is no longer current")]
    VersionMismatch {
        snapshot: AuthorizationVersion,
        current: AuthorizationVersion,
    },
    #[error("authorization policy version mismatch")]
    PolicyVersionMismatch {
        snapshot: PolicyVersion,
        current: PolicyVersion,
    },
    #[error("authorization role no longer matches the snapshot")]
    RoleMismatch,
    #[error("authorization permission set no longer matches the snapshot")]
    PermissionsMismatch,
}

impl FmtDebug for SnapshotValidationError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> FmtResult {
        Display::fmt(self, formatter)
    }
}

/// Historical-only validation.
///
/// Administrator bindings no longer grant instance-management authority. The
/// snapshot kind stays decodable so old revocation/audit records can be read,
/// but every runtime validation fails closed instead of falling back to the
/// retired authority source.
pub fn validate_administrator_snapshot(
    snapshot: &ManagementAuthorizationSnapshot,
    _current: Option<&AdministratorBinding>,
    _current_policy_version: PolicyVersion,
) -> Result<(), SnapshotValidationError> {
    if snapshot.grant_kind != ManagementGrantKind::AdministratorBinding {
        return Err(SnapshotValidationError::GrantKindMismatch);
    }
    Err(SnapshotValidationError::RetiredGrantKind)
}

/// Validate the current whole-user permission snapshot against authoritative
/// state read in the same check. Identity is the user OID plus the derived
/// whole-user authority fingerprint; the exact permission set and catalog
/// policy fingerprint must still match.
pub fn validate_user_permission_snapshot(
    snapshot: &ManagementAuthorizationSnapshot,
    current: Option<&UserPermissionAuthority>,
    current_policy_version: PolicyVersion,
) -> Result<(), SnapshotValidationError> {
    if snapshot.grant_kind != ManagementGrantKind::UserRbac {
        return Err(SnapshotValidationError::GrantKindMismatch);
    }
    let Some(current) = current else {
        return Err(SnapshotValidationError::GrantNotFound);
    };
    if snapshot.grant_oid != current.user_oid.0 {
        return Err(SnapshotValidationError::OidMismatch {
            snapshot: snapshot.grant_oid,
            current: current.user_oid.0,
        });
    }
    if snapshot.grant_fingerprint != current.version {
        return Err(SnapshotValidationError::VersionMismatch {
            snapshot: snapshot.grant_fingerprint,
            current: current.version,
        });
    }
    if snapshot.policy_version != current_policy_version {
        return Err(SnapshotValidationError::PolicyVersionMismatch {
            snapshot: snapshot.policy_version,
            current: current_policy_version,
        });
    }
    if snapshot.role.is_some() {
        return Err(SnapshotValidationError::RoleMismatch);
    }
    if snapshot.permissions != current.permissions {
        return Err(SnapshotValidationError::PermissionsMismatch);
    }
    Ok(())
}

/// Convenience helper used by bindings that only keep a reference snapshot.
#[must_use]
pub fn administrator_snapshot_oid(
    snapshot: &ManagementAuthorizationSnapshot,
) -> Option<AdministratorBindingOid> {
    (snapshot.grant_kind == ManagementGrantKind::AdministratorBinding)
        .then_some(AdministratorBindingOid(snapshot.grant_oid))
}

#[cfg(test)]
mod tests {
    use chrono::{TimeZone, Utc};
    use uuid::Uuid;

    use super::{
        ManagementAuthorizationSnapshot, SnapshotValidationError, validate_administrator_snapshot,
        validate_user_permission_snapshot,
    };
    use crate::{
        authorization::{
            administrator::{AdministratorBinding, AdministratorRole, GrantMetadata, GrantReason},
            authority::UserPermissionAuthority,
            catalog::ManagementScope,
            ids::{AdministratorBindingOid, AuthorizationVersion, PolicyVersion},
        },
        user::UserOid,
    };

    fn metadata() -> GrantMetadata {
        GrantMetadata {
            reason: GrantReason::new("snapshot test").unwrap(),
            granted_by_user_oid: None,
            granted_at: Utc.timestamp_opt(1_000, 0).single().unwrap(),
        }
    }

    #[test]
    fn changed_authority_fingerprint_is_rejected_even_when_permissions_are_unchanged() {
        let user = UserOid(Uuid::new_v4());
        let issued = AuthorizationVersion::new();
        let authority = UserPermissionAuthority::new(user, issued, [ManagementScope::UsersRead]);
        let policy = PolicyVersion::new();
        let snapshot = ManagementAuthorizationSnapshot::for_user_permissions(&authority, policy);
        let current_version = AuthorizationVersion::new();
        let mut current = authority.clone();
        current.version = current_version;
        assert_eq!(
            validate_user_permission_snapshot(&snapshot, Some(&current), policy),
            Err(SnapshotValidationError::VersionMismatch {
                snapshot: issued,
                current: current_version,
            })
        );
    }

    #[test]
    fn retired_administrator_binding_snapshot_never_validates() {
        let binding = AdministratorBinding::new(
            AdministratorBindingOid::new(),
            UserOid(Uuid::new_v4()),
            AdministratorRole::Owner,
            metadata(),
        );
        let policy = PolicyVersion::new();
        let snapshot = ManagementAuthorizationSnapshot::for_administrator_binding(&binding, policy);
        assert_eq!(
            validate_administrator_snapshot(&snapshot, Some(&binding), policy),
            Err(SnapshotValidationError::RetiredGrantKind)
        );
    }

    #[test]
    fn permission_set_and_policy_change_are_rejected() {
        let user = UserOid(Uuid::new_v4());
        let policy = PolicyVersion::new();
        let authority = UserPermissionAuthority::new(
            user,
            AuthorizationVersion::new(),
            [ManagementScope::UsersRead, ManagementScope::AuditRead],
        );
        let snapshot = ManagementAuthorizationSnapshot::for_user_permissions(&authority, policy);
        let mut changed = authority.clone();
        changed.permissions.remove(&ManagementScope::AuditRead);
        assert_eq!(
            validate_user_permission_snapshot(&snapshot, Some(&changed), policy),
            Err(SnapshotValidationError::PermissionsMismatch)
        );
        assert!(matches!(
            validate_user_permission_snapshot(&snapshot, Some(&authority), PolicyVersion::new()),
            Err(SnapshotValidationError::PolicyVersionMismatch { .. })
        ));
    }
}
#[test]
fn fingerprint_failures_do_not_expose_values_in_diagnostics() {
    let issued = Uuid::new_v4();
    let current = Uuid::new_v4();
    for error in [
        SnapshotValidationError::VersionMismatch {
            snapshot: AuthorizationVersion::from_uuid(issued),
            current: AuthorizationVersion::from_uuid(current),
        },
        SnapshotValidationError::PolicyVersionMismatch {
            snapshot: PolicyVersion::from_uuid(issued),
            current: PolicyVersion::from_uuid(current),
        },
    ] {
        let diagnostics = format!("{error} {error:?}");
        assert!(!diagnostics.contains(&issued.to_string()));
        assert!(!diagnostics.contains(&current.to_string()));
    }
}
