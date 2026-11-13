//! Trusted stable identities and seed data for built-in RBAC definitions.
//!
//! Built-in permission identities are derived from the version-controlled
//! management catalog, never from database row order, display names, array
//! positions or user input. Built-in presets are ordinary RBAC roles and groups
//! with fixed OIDs and explicit permission sets; the seed uses the OIDs only to
//! keep provisioning idempotent. Runtime authorization reads effective
//! permissions and protection reads the persisted `built_in` flag, never a
//! preset OID or name.
//!
//! Permission OIDs derive from `identity/rbac/permission/<scope name>`.

use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::{
    authorization::catalog::ManagementScope,
    rbac::ids::{GroupOid, ResourcePermissionOid, RoleOid},
};

pub const BUILT_IN_PERMISSION_PREFIX: &str = "identity/rbac/permission/";

/// A protected built-in role, the protected group that grants it, and the
/// role's exact management permissions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BuiltInPreset {
    pub role_oid: RoleOid,
    pub group_oid: GroupOid,
    pub permissions: &'static [ManagementScope],
}

/// Every management permission. Installation adds the first user to this
/// preset's group.
pub const OWNER_PRESET: BuiltInPreset = BuiltInPreset {
    role_oid: RoleOid(Uuid::from_u128(0xd88dfaf0_ed61_848b_a80c_c0ae8ea58e14)),
    group_oid: GroupOid(Uuid::from_u128(0x186aa775_c709_85ed_a27a_58914dc99b03)),
    permissions: &ManagementScope::ALL,
};

/// Day-to-day administration without instance settings, signing keys or
/// permission delegation.
pub const ADMIN_PRESET: BuiltInPreset = BuiltInPreset {
    role_oid: RoleOid(Uuid::from_u128(0x740631a7_f0f5_8d0b_bbaa_bf98143462c2)),
    group_oid: GroupOid(Uuid::from_u128(0x6e2917f0_034c_8ce9_bc1c_b9b4e044410a)),
    permissions: &ADMIN_PERMISSIONS,
};

/// Read-only management views.
pub const VIEWER_PRESET: BuiltInPreset = BuiltInPreset {
    role_oid: RoleOid(Uuid::from_u128(0x310f313a_4956_834d_8aa1_bdf16ead50c1)),
    group_oid: GroupOid(Uuid::from_u128(0x8e004648_bbad_8f58_b897_c08fe3b5aca7)),
    permissions: &VIEWER_PERMISSIONS,
};

pub const BUILT_IN_PRESETS: [BuiltInPreset; 3] = [OWNER_PRESET, ADMIN_PRESET, VIEWER_PRESET];

const ADMIN_PERMISSIONS: [ManagementScope; 39] = [
    ManagementScope::UsersRead,
    ManagementScope::UsersCreate,
    ManagementScope::UsersUpdate,
    ManagementScope::UsersState,
    ManagementScope::UsersRevokeAccess,
    ManagementScope::SessionsRead,
    ManagementScope::SessionsRevoke,
    ManagementScope::CredentialsRead,
    ManagementScope::CredentialsRevoke,
    ManagementScope::CredentialsReset,
    ManagementScope::ClientsRead,
    ManagementScope::ClientsCreate,
    ManagementScope::ClientsUpdate,
    ManagementScope::ClientsState,
    ManagementScope::ClientsDelete,
    ManagementScope::ClientsScopes,
    ManagementScope::ClientCredentialsRead,
    ManagementScope::ClientCredentialsCreate,
    ManagementScope::ClientCredentialsRotate,
    ManagementScope::ClientCredentialsRevoke,
    ManagementScope::ResourcesRead,
    ManagementScope::ResourcesWrite,
    ManagementScope::ScopesRead,
    ManagementScope::ScopesWrite,
    ManagementScope::SettingsRead,
    ManagementScope::KeysRead,
    ManagementScope::AuditRead,
    ManagementScope::PermissionRead,
    ManagementScope::PermissionWrite,
    ManagementScope::RolesRead,
    ManagementScope::RolesWrite,
    ManagementScope::RoleAssignmentsRead,
    ManagementScope::RoleAssignmentsWrite,
    ManagementScope::GroupsRead,
    ManagementScope::GroupsWrite,
    ManagementScope::GroupMembershipsRead,
    ManagementScope::GroupMembershipsWrite,
    ManagementScope::GroupRolesRead,
    ManagementScope::GroupRolesWrite,
];

const VIEWER_PERMISSIONS: [ManagementScope; 16] = [
    ManagementScope::UsersRead,
    ManagementScope::SessionsRead,
    ManagementScope::CredentialsRead,
    ManagementScope::ClientsRead,
    ManagementScope::ClientCredentialsRead,
    ManagementScope::ResourcesRead,
    ManagementScope::ScopesRead,
    ManagementScope::SettingsRead,
    ManagementScope::KeysRead,
    ManagementScope::AuditRead,
    ManagementScope::PermissionRead,
    ManagementScope::RolesRead,
    ManagementScope::RoleAssignmentsRead,
    ManagementScope::GroupsRead,
    ManagementScope::GroupMembershipsRead,
    ManagementScope::GroupRolesRead,
];

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
    use std::collections::BTreeSet;

    use super::{
        ADMIN_PRESET, BUILT_IN_PRESETS, OWNER_PRESET, VIEWER_PRESET, built_in_permission_oid,
        deterministic_oid,
    };
    use crate::authorization::catalog::ManagementScope;

    #[test]
    fn preset_identities_keep_their_original_derivation() {
        for (preset, name) in [
            (OWNER_PRESET, "owner"),
            (ADMIN_PRESET, "admin"),
            (VIEWER_PRESET, "viewer"),
        ] {
            assert_eq!(
                preset.role_oid.0,
                deterministic_oid(&format!("identity/rbac/role/{name}"))
            );
            assert_eq!(
                preset.group_oid.0,
                deterministic_oid(&format!("identity/rbac/group/{name}"))
            );
        }
        assert_ne!(
            built_in_permission_oid(ManagementScope::UsersRead),
            built_in_permission_oid(ManagementScope::UsersCreate)
        );
    }

    #[test]
    fn preset_permissions_are_unique_and_nested() {
        let sets: Vec<BTreeSet<ManagementScope>> = BUILT_IN_PRESETS
            .iter()
            .map(|preset| {
                let set: BTreeSet<_> = preset.permissions.iter().copied().collect();
                assert_eq!(set.len(), preset.permissions.len());
                set
            })
            .collect();
        assert!(sets[2].is_subset(&sets[1]));
        assert!(sets[1].is_subset(&sets[0]));
        assert!(!sets[1].contains(&ManagementScope::PermissionDelegate));
    }

    #[test]
    fn derivation_sets_uuid_v8_and_rfc_variant() {
        let oid = deterministic_oid("identity/rbac/permission/management.user.read");
        assert_eq!(oid.get_version_num(), 8);
        assert_eq!(oid.as_bytes()[8] & 0xc0, 0x80);
    }
}
