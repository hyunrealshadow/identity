//! Business RBAC authorization snapshots.
//!
//! A user-role binding snapshot stores the binding OID and referenced role OID.
//! Revoking a binding and granting the same role again creates a new binding
//! OID, so the old snapshot cannot be revived even if the role identity and
//! permission set are identical. The binding row's optimistic-lock version is
//! not identity: a metadata or CAS-only edit keeps the same grant valid. Whole
//! user authority changes are detected by the derived user authority
//! fingerprint carried separately by [`UserAuthorizationSnapshot`].

use crate::{
    authorization::ids::AuthorizationVersion,
    rbac::{
        ids::{RoleOid, UserRoleOid},
        model::UserRole,
    },
};

/// Binding identity carried by a user authorization snapshot. The binding's
/// record version is an optimistic lock and is intentionally not part of
/// credential identity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UserRoleSnapshot {
    pub user_role_oid: UserRoleOid,
    pub role_oid: RoleOid,
}

impl UserRoleSnapshot {
    #[must_use]
    pub fn from_binding(binding: &UserRole) -> Self {
        Self {
            user_role_oid: binding.oid,
            role_oid: binding.role_oid,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum BindingSnapshotError {
    #[error("user role binding not found")]
    NotFound,
    #[error("user role binding is revoked or disabled")]
    Tombstoned,
    #[error("user role binding OID changed; a re-granted binding cannot revive the snapshot")]
    OidMismatch,
    #[error("user authority fingerprint changed")]
    UserAuthorizationVersionMismatch,
    #[error("user role binding role changed")]
    RoleMismatch,
}

/// Validate one binding snapshot against current authoritative state. Exact OID
/// equality means a recreated/re-granted binding is always rejected.
pub fn validate_binding_snapshot(
    snapshot: &UserRoleSnapshot,
    current: Option<&UserRole>,
) -> Result<(), BindingSnapshotError> {
    let Some(current) = current else {
        return Err(BindingSnapshotError::NotFound);
    };
    if !current.is_active() {
        return Err(BindingSnapshotError::Tombstoned);
    }
    if snapshot.user_role_oid != current.oid {
        return Err(BindingSnapshotError::OidMismatch);
    }
    if snapshot.role_oid != current.role_oid {
        return Err(BindingSnapshotError::RoleMismatch);
    }
    Ok(())
}

/// Whole-user snapshot used by issued RBAC credentials. It binds the opaque
/// derived user authority fingerprint and each active binding identity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UserAuthorizationSnapshot {
    pub user_authorization_version: AuthorizationVersion,
    pub bindings: Vec<UserRoleSnapshot>,
}

impl UserAuthorizationSnapshot {
    pub fn validate(
        &self,
        current_user_version: AuthorizationVersion,
        bindings: &[UserRole],
    ) -> Result<(), BindingSnapshotError> {
        if self.user_authorization_version != current_user_version {
            return Err(BindingSnapshotError::UserAuthorizationVersionMismatch);
        }
        for snapshot in &self.bindings {
            let current = bindings
                .iter()
                .find(|binding| binding.oid == snapshot.user_role_oid);
            validate_binding_snapshot(snapshot, current)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use chrono::{TimeZone, Utc};
    use uuid::Uuid;

    use super::{
        BindingSnapshotError, UserAuthorizationSnapshot, UserRoleSnapshot,
        validate_binding_snapshot,
    };
    use crate::{
        authorization::ids::AuthorizationVersion,
        rbac::{
            ids::{RoleOid, UserRoleOid},
            model::UserRole,
        },
        user::UserOid,
    };

    fn at() -> chrono::DateTime<Utc> {
        Utc.timestamp_opt(1_000, 0).single().unwrap()
    }

    #[test]
    fn revoked_then_regranted_binding_is_a_new_identity() {
        let user = UserOid(Uuid::new_v4());
        let role = RoleOid::new();
        let first = UserRole::new(UserRoleOid::new(), user, role, None, "grant", at()).unwrap();
        let snapshot = UserRoleSnapshot::from_binding(&first);
        let mut first = first;
        first.revoke(at()).unwrap();
        assert_eq!(
            validate_binding_snapshot(&snapshot, Some(&first)),
            Err(BindingSnapshotError::Tombstoned)
        );

        let regranted =
            UserRole::new(UserRoleOid::new(), user, role, None, "regrant", at()).unwrap();
        assert_eq!(
            validate_binding_snapshot(&snapshot, Some(&regranted)),
            Err(BindingSnapshotError::OidMismatch)
        );
    }

    #[test]
    fn record_version_change_does_not_replace_binding_identity() {
        let user = UserOid(Uuid::new_v4());
        let binding = UserRole::new(
            UserRoleOid::new(),
            user,
            RoleOid::new(),
            None,
            "grant",
            at(),
        )
        .unwrap();
        let snapshot = UserRoleSnapshot::from_binding(&binding);

        // The row's optimistic-lock version is CAS metadata, not the grant's
        // identity. Rotating it must not invalidate the issued snapshot.
        let mut cas_only = binding.clone();
        cas_only.version = AuthorizationVersion::new();
        cas_only.updated_at = Some(at());
        assert_ne!(cas_only.version, binding.version);
        validate_binding_snapshot(&snapshot, Some(&cas_only)).unwrap();
    }

    #[test]
    fn binding_role_replacement_is_rejected() {
        let user = UserOid(Uuid::new_v4());
        let binding = UserRole::new(
            UserRoleOid::new(),
            user,
            RoleOid::new(),
            None,
            "grant",
            at(),
        )
        .unwrap();
        let snapshot = UserRoleSnapshot::from_binding(&binding);

        let mut replaced_role = binding.clone();
        replaced_role.role_oid = RoleOid::new();
        assert_eq!(
            validate_binding_snapshot(&snapshot, Some(&replaced_role)),
            Err(BindingSnapshotError::RoleMismatch)
        );
    }

    #[test]
    fn stale_user_authority_fingerprint_is_rejected() {
        let user = UserOid(Uuid::new_v4());
        let binding = UserRole::new(
            UserRoleOid::new(),
            user,
            RoleOid::new(),
            None,
            "grant",
            at(),
        )
        .unwrap();
        let snapshot = UserRoleSnapshot::from_binding(&binding);
        let stale = AuthorizationVersion::new();
        let current = AuthorizationVersion::new();
        assert!(matches!(
            UserAuthorizationSnapshot {
                user_authorization_version: stale,
                bindings: vec![snapshot],
            }
            .validate(current, &[binding]),
            Err(BindingSnapshotError::UserAuthorizationVersionMismatch)
        ));
    }
}
