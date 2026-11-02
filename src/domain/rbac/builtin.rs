//! Trusted stable identities for built-in RBAC definitions.
//!
//! Built-in identities are derived from the version-controlled management
//! catalog, never from database row order, display names, array positions or
//! user input. Role and group seeds use these stable OIDs only to keep install
//! and seed provisioning idempotent; runtime protection of an existing role or
//! group depends on its persisted `built_in` flag, not on an OID or name.
//!
//! Strings are exact UTF-8 seeds:
//! - `identity/rbac/permission/<management scope name>`
//! - `identity/rbac/role/<owner|admin|viewer>`
//! - `identity/rbac/group/<owner|admin|viewer>`

use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::{
    authorization::catalog::{AdministratorRole, ManagementScope},
    rbac::ids::{GroupOid, ResourcePermissionOid, RoleOid},
};

pub const BUILT_IN_PERMISSION_PREFIX: &str = "identity/rbac/permission/";
pub const BUILT_IN_ROLE_PREFIX: &str = "identity/rbac/role/";
pub const BUILT_IN_GROUP_PREFIX: &str = "identity/rbac/group/";

/// Deterministic UUIDv8 from an exact seed. First 16 SHA-256 bytes, UUID
/// version nibble 8 and RFC 4122 variant bits; remaining bytes are preserved so
/// the value is stable across processes and database engines.
#[must_use]
pub fn deterministic_oid(seed: &str) -> Uuid {
    let digest = Sha256::digest(seed.as_bytes());
    let mut bytes = [0u8; 16];
    bytes.copy_from_slice(&digest[..16]);
    bytes[6] = (bytes[6] & 0x0f) | 0x80;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    Uuid::from_bytes(bytes)
}

#[must_use]
pub fn built_in_permission_oid(scope: ManagementScope) -> ResourcePermissionOid {
    ResourcePermissionOid(deterministic_oid(&format!(
        "{BUILT_IN_PERMISSION_PREFIX}{}",
        scope.name()
    )))
}

#[must_use]
pub fn built_in_role_oid(role: AdministratorRole) -> RoleOid {
    RoleOid(deterministic_oid(&format!(
        "{BUILT_IN_ROLE_PREFIX}{}",
        role.as_str()
    )))
}

#[must_use]
pub fn built_in_group_oid(role: AdministratorRole) -> GroupOid {
    GroupOid(deterministic_oid(&format!(
        "{BUILT_IN_GROUP_PREFIX}{}",
        role.as_str()
    )))
}

/// True when `oid` is the deterministic identity for the given trusted scope.
///
/// This is the permission-catalog trust check only. Role and group protection is
/// determined by their persisted built-in flag, never by a fixed OID or name.
#[must_use]
pub fn is_built_in_permission_oid(scope: ManagementScope, oid: ResourcePermissionOid) -> bool {
    built_in_permission_oid(scope) == oid
}

#[cfg(test)]
mod tests {
    use super::{
        built_in_group_oid, built_in_permission_oid, built_in_role_oid, deterministic_oid,
    };
    use crate::authorization::catalog::{AdministratorRole, ManagementScope};

    #[test]
    fn built_in_oids_are_stable_and_distinct() {
        let owner = built_in_role_oid(AdministratorRole::Owner);
        assert_eq!(owner, built_in_role_oid(AdministratorRole::Owner));
        assert_ne!(owner, built_in_role_oid(AdministratorRole::Admin));
        assert_ne!(
            built_in_group_oid(AdministratorRole::Owner).0,
            built_in_role_oid(AdministratorRole::Owner).0
        );
        assert_ne!(
            built_in_permission_oid(ManagementScope::UsersRead),
            built_in_permission_oid(ManagementScope::UsersCreate)
        );
    }

    #[test]
    fn derivation_sets_uuid_v8_and_rfc_variant() {
        let oid = deterministic_oid("identity/rbac/permission/management.user.read");
        assert_eq!(oid.get_version_num(), 8);
        assert_eq!(oid.as_bytes()[8] & 0xc0, 0x80);
    }
}
