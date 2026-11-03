//! Whole-user effective management authority.
//!
//! Management permissions now come from the same role/permission relations as
//! business permissions. A user's authority is the union of every active direct
//! role binding and every active group membership/group-role path. Display
//! names, built-in role flags and built-in group membership are never
//! consulted: only the exact trusted permission identities are.
//!
//! Codes and tokens carry an opaque authority-state identifier. It must be
//! compared for equality and must not be interpreted as a change counter.

use std::collections::BTreeSet;

use serde::{Deserialize, Deserializer, Serialize, Serializer, de::Error};
use uuid::Uuid;

use crate::{
    authorization::{
        catalog::ManagementScope,
        ids::{AuthorizationVersion, PolicyVersion},
    },
    client::model::ClientOid,
    rbac::built_in_permission_oid,
    user::UserOid,
};

/// Effective management permissions for one user and the associated state.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct UserPermissionAuthority {
    pub user_oid: UserOid,
    pub version: AuthorizationVersion,
    #[serde(
        serialize_with = "serialize_permissions",
        deserialize_with = "deserialize_permissions"
    )]
    pub permissions: BTreeSet<ManagementScope>,
}

impl UserPermissionAuthority {
    #[must_use]
    pub fn new(
        user_oid: UserOid,
        version: AuthorizationVersion,
        permissions: impl IntoIterator<Item = ManagementScope>,
    ) -> Self {
        Self {
            user_oid,
            version,
            permissions: permissions.into_iter().collect(),
        }
    }

    #[must_use]
    pub fn authorizes(&self, scope: ManagementScope) -> bool {
        self.permissions.contains(&scope)
    }

    #[must_use]
    pub fn has_full_management_permissions(&self) -> bool {
        self.permissions == full_management_permissions()
    }
}

/// Live machine authority for the first-party API resource.
///
/// This is not a grant table and not a client-management switch. `permissions`
/// is exactly the set of trusted management scopes present in the client's live
/// `client_scope` rows for the GraphQL resource, and `boundary` is the opaque
/// semantic fingerprint of that ceiling. Issuance may only shrink a token to
/// this set; later ceiling changes permanently withdraw old artifacts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientScopeAuthority {
    pub client_oid: ClientOid,
    pub permissions: BTreeSet<ManagementScope>,
    pub boundary: PolicyVersion,
}

impl ClientScopeAuthority {
    #[must_use]
    pub fn new(
        client_oid: ClientOid,
        permissions: impl IntoIterator<Item = ManagementScope>,
        boundary: PolicyVersion,
    ) -> Self {
        Self {
            client_oid,
            permissions: permissions.into_iter().collect(),
            boundary,
        }
    }

    #[must_use]
    pub fn authorizes(&self, scope: ManagementScope) -> bool {
        self.permissions.contains(&scope)
    }
}

/// The complete trusted current management permission set.
///
/// Recovery protection requires this exact set. It is derived from the compiled
/// catalog, never from database rows, role names or "future permission"
/// wildcards.
#[must_use]
pub fn full_management_permissions() -> BTreeSet<ManagementScope> {
    ManagementScope::ALL.into_iter().collect()
}

/// Trusted deterministic permission identity for a management scope.
///
/// Delegates to the single trusted derivation owned by `domain::rbac`. A
/// database `built_in` boolean or a matching display name never creates this
/// identity by itself. This wrapper exists only so management-authorization
/// call sites keep their local name; it contains no derivation logic.
#[must_use]
pub fn trusted_built_in_permission_oid(scope: ManagementScope) -> Uuid {
    built_in_permission_oid(scope).0
}

/// Exact trusted management permission identity check.
///
/// This mirrors the runtime authority loader's validation. Callers must still
/// check the enabled flag, the resource URI and the role/group lifecycle.
#[must_use]
pub fn is_trusted_management_permission(
    scope: ManagementScope,
    permission_oid: Uuid,
    permission_code: &str,
) -> bool {
    permission_code == scope.name() && permission_oid == trusted_built_in_permission_oid(scope)
}

fn serialize_permissions<S>(
    permissions: &BTreeSet<ManagementScope>,
    serializer: S,
) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    let names = permissions
        .iter()
        .map(|scope| scope.name())
        .collect::<Vec<_>>();
    names.serialize(serializer)
}

fn deserialize_permissions<'de, D>(deserializer: D) -> Result<BTreeSet<ManagementScope>, D::Error>
where
    D: Deserializer<'de>,
{
    let names = Vec::<String>::deserialize(deserializer)?;
    let mut permissions = BTreeSet::new();
    for name in names {
        let scope = ManagementScope::from_name(&name).ok_or_else(|| {
            Error::custom(format!(
                "management permission is not a trusted catalog scope: {name}"
            ))
        })?;
        if !permissions.insert(scope) {
            return Err(Error::custom(format!(
                "duplicate management permission: {name}"
            )));
        }
    }
    Ok(permissions)
}

#[cfg(test)]
mod tests {
    use uuid::Uuid;

    use super::{
        UserPermissionAuthority, full_management_permissions, is_trusted_management_permission,
        trusted_built_in_permission_oid,
    };
    use crate::{
        authorization::{catalog::ManagementScope, ids::AuthorizationVersion},
        user::UserOid,
    };

    #[test]
    fn trusted_permission_oid_is_deterministic_and_versioned() {
        let first = trusted_built_in_permission_oid(ManagementScope::UsersRead);
        let second = trusted_built_in_permission_oid(ManagementScope::UsersRead);
        assert_eq!(first, second);
        assert_eq!(first.get_version_num(), 8);
        let bytes = first.as_bytes();
        assert_eq!(bytes[8] & 0xc0, 0x80);
        assert_ne!(
            first,
            trusted_built_in_permission_oid(ManagementScope::AuditRead)
        );
    }

    #[test]
    fn a_key_or_oid_alone_does_not_create_a_trusted_permission() {
        let oid = trusted_built_in_permission_oid(ManagementScope::UsersRead);
        assert!(is_trusted_management_permission(
            ManagementScope::UsersRead,
            oid,
            "management.user.read"
        ));
        assert!(!is_trusted_management_permission(
            ManagementScope::UsersRead,
            Uuid::new_v4(),
            "management.user.read"
        ));
        assert!(!is_trusted_management_permission(
            ManagementScope::UsersRead,
            oid,
            "management.user.write"
        ));
    }

    #[test]
    fn full_set_has_every_catalog_scope_and_exact_equality_controls_recovery() {
        let user = UserOid(Uuid::new_v4());
        let all = full_management_permissions();
        assert_eq!(all.len(), ManagementScope::ALL.len());
        assert!(
            UserPermissionAuthority::new(user, AuthorizationVersion::new(), all.iter().copied())
                .has_full_management_permissions()
        );
        let mut subset = all;
        subset.remove(&ManagementScope::SettingsWrite);
        assert!(
            !UserPermissionAuthority::new(user, AuthorizationVersion::new(), subset)
                .has_full_management_permissions()
        );
    }

    #[test]
    fn serde_uses_stable_scope_names() {
        let authority = UserPermissionAuthority::new(
            UserOid(Uuid::new_v4()),
            AuthorizationVersion::new(),
            [ManagementScope::UsersRead, ManagementScope::GroupsWrite],
        );
        let encoded = serde_json::to_value(&authority).unwrap();
        assert_eq!(
            encoded["permissions"],
            serde_json::json!(["management.user.read", "management.group.write"])
        );
        assert_eq!(
            serde_json::from_value::<UserPermissionAuthority>(encoded).unwrap(),
            authority
        );
    }
}
