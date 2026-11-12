//! User-role binding and effective-permission query types.

use chrono::{DateTime, Utc};
use identity_domain::{
    rbac::{
        GroupMembershipOid, GroupOid, GroupRoleOid, ResourceOid, ResourcePermissionOid, RoleOid,
        UserRoleOid,
    },
    user::UserOid,
};
use uuid::Uuid;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EffectivePermissionSourceRecord {
    pub user_role_oid: UserRoleOid,
    pub role_oid: RoleOid,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EffectiveGroupPermissionSourceRecord {
    pub group_oid: GroupOid,
    pub membership_oid: GroupMembershipOid,
    pub group_role_oid: GroupRoleOid,
    pub role_oid: RoleOid,
}

/// Where a user's role or permission comes from.
///
/// `Direct` is an active user-role assignment. `Group` is an active membership
/// in an enabled group that holds an active group-role binding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize)]
pub enum AuthorizationSource {
    Direct,
    Group,
}

/// A role a user holds through one group: the membership and the group-role
/// binding that are both active.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InheritedUserRoleRecord {
    pub user_oid: UserOid,
    pub role_oid: RoleOid,
    pub group_oid: GroupOid,
    pub membership_oid: GroupMembershipOid,
    pub group_role_oid: GroupRoleOid,
    /// When the user obtained the role: the later of joining the group and
    /// the group receiving the role.
    pub created_at: DateTime<Utc>,
}

/// One row of a user's role list: a direct assignment (active or revoked
/// history) or a role currently inherited through a group.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UserRoleGrant {
    Direct(UserRoleRecord),
    Group(InheritedUserRoleRecord),
}

impl UserRoleGrant {
    #[must_use]
    pub const fn role_oid(&self) -> RoleOid {
        match self {
            Self::Direct(record) => record.role_oid,
            Self::Group(record) => record.role_oid,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EffectivePermissionRecord {
    /// Canonical scope OID projected as the permission identity.
    pub permission_oid: ResourcePermissionOid,
    pub resource_oid: ResourceOid,
    pub code: String,
    pub scope: String,
    pub sources: Vec<EffectivePermissionSourceRecord>,
    pub group_sources: Vec<EffectiveGroupPermissionSourceRecord>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum EffectivePermissionOrder {
    #[default]
    CodeAsc,
    CodeDesc,
}

impl EffectivePermissionOrder {
    #[must_use]
    pub const fn as_u8(self) -> u8 {
        match self {
            Self::CodeAsc => 0,
            Self::CodeDesc => 1,
        }
    }

    #[must_use]
    pub const fn from_u8(value: u8) -> Option<Self> {
        match value {
            0 => Some(Self::CodeAsc),
            1 => Some(Self::CodeDesc),
            _ => None,
        }
    }

    #[must_use]
    pub const fn is_descending(self) -> bool {
        matches!(self, Self::CodeDesc)
    }
}

#[derive(Debug, Clone)]
pub struct EffectivePermissionPageRequest {
    pub user_oid: UserOid,
    pub resource_oid: ResourceOid,
    /// `None` lists permissions from every source.
    pub source: Option<AuthorizationSource>,
    pub order: EffectivePermissionOrder,
    pub first: Option<u32>,
    pub after: Option<String>,
    pub last: Option<u32>,
    pub before: Option<String>,
}

#[derive(Debug, Clone)]
pub struct EffectivePermissionPageItem {
    pub record: EffectivePermissionRecord,
    pub cursor: String,
}

#[derive(Debug, Clone)]
pub struct EffectivePermissionPage {
    pub items: Vec<EffectivePermissionPageItem>,
    pub has_previous_page: bool,
    pub has_next_page: bool,
    pub user_version: Uuid,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UserRoleRecord {
    pub oid: UserRoleOid,
    pub user_oid: UserOid,
    pub role_oid: RoleOid,
    pub granted_by_user_oid: Option<UserOid>,
    pub reason: String,
    pub enabled: bool,
    pub revoked_at: Option<DateTime<Utc>>,
    pub version: Uuid,
    pub user_version: Uuid,
    pub created_at: DateTime<Utc>,
    pub updated_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum UserRoleOrder {
    CreatedAtAsc,
    #[default]
    CreatedAtDesc,
}

impl UserRoleOrder {
    #[must_use]
    pub const fn as_u8(self) -> u8 {
        match self {
            Self::CreatedAtAsc => 0,
            Self::CreatedAtDesc => 1,
        }
    }

    #[must_use]
    pub const fn from_u8(value: u8) -> Option<Self> {
        match value {
            0 => Some(Self::CreatedAtAsc),
            1 => Some(Self::CreatedAtDesc),
            _ => None,
        }
    }

    #[must_use]
    pub const fn is_descending(self) -> bool {
        matches!(self, Self::CreatedAtDesc)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UserRolePageRequest {
    pub user_oid: UserOid,
    /// `None` lists direct assignments and inherited roles together.
    pub source: Option<AuthorizationSource>,
    pub enabled: Option<bool>,
    pub order: UserRoleOrder,
    pub first: Option<u32>,
    pub after: Option<String>,
    pub last: Option<u32>,
    pub before: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RoleUserPageRequest {
    pub role_oid: RoleOid,
    pub enabled: Option<bool>,
    pub order: UserRoleOrder,
    pub first: Option<u32>,
    pub after: Option<String>,
    pub last: Option<u32>,
    pub before: Option<String>,
}

#[derive(Debug, Clone)]
pub struct UserRolePageItem {
    pub record: UserRoleRecord,
    pub cursor: String,
}

#[derive(Debug, Clone)]
pub struct UserRoleGrantPageItem {
    pub grant: UserRoleGrant,
    pub cursor: String,
}

/// One page of a single user's roles and the user's current version.
#[derive(Debug, Clone)]
pub struct UserRoleGrantPage {
    pub items: Vec<UserRoleGrantPageItem>,
    pub has_previous_page: bool,
    pub has_next_page: bool,
    pub user_version: Uuid,
}

#[derive(Debug, Clone)]
pub struct UserRolePage {
    pub items: Vec<UserRolePageItem>,
    pub has_previous_page: bool,
    pub has_next_page: bool,
    /// Always `None` for `list_role_users`, which can span several users.
    pub user_version: Option<Uuid>,
}

#[derive(Debug, Clone)]
pub struct AssignUserRolesCommand {
    pub user_oid: UserOid,
    pub role_oids: Vec<RoleOid>,
    pub expected_user_version: Uuid,
    pub reason: String,
    pub client_mutation_id: Option<String>,
}

#[derive(Debug, Clone)]
pub struct RevokeUserRolesCommand {
    pub user_oid: UserOid,
    pub role_oids: Vec<RoleOid>,
    pub expected_user_version: Uuid,
    pub reason: String,
    pub client_mutation_id: Option<String>,
}

#[derive(Debug, Clone)]
pub struct UserRoleMutationResult {
    pub user_oid: UserOid,
    pub user_version: Uuid,
    pub user_role_oids: Vec<UserRoleOid>,
    pub created_count: u32,
    pub revoked_count: u32,
}

#[cfg(test)]
mod tests {
    use uuid::Uuid;

    use super::{RoleUserPageRequest, UserRoleOrder, UserRolePageRequest};
    use crate::{
        domain::{rbac::RoleOid, user::UserOid},
        rbac::cursor::{CURSOR_KIND_USER_ROLE, filter_fingerprint},
    };

    fn user_request(user_oid: UserOid, enabled: Option<bool>) -> UserRolePageRequest {
        UserRolePageRequest {
            user_oid,
            source: None,
            enabled,
            order: UserRoleOrder::CreatedAtDesc,
            first: Some(20),
            after: None,
            last: None,
            before: None,
        }
    }

    fn role_request(role_oid: RoleOid, enabled: Option<bool>) -> RoleUserPageRequest {
        RoleUserPageRequest {
            role_oid,
            enabled,
            order: UserRoleOrder::CreatedAtDesc,
            first: Some(20),
            after: None,
            last: None,
            before: None,
        }
    }

    #[test]
    fn binding_cursor_fingerprints_are_bound_to_the_requested_target_and_filter() {
        let user_oid = UserOid(Uuid::new_v4());
        let role_oid = RoleOid(Uuid::new_v4());
        let user_page = user_request(user_oid, None);
        let role_page = role_request(role_oid, None);
        let order = UserRoleOrder::CreatedAtDesc;

        let user_fingerprint = filter_fingerprint(
            CURSOR_KIND_USER_ROLE,
            order.as_u8(),
            &(Some(user_page.user_oid), None::<RoleOid>, user_page.enabled),
        );
        let role_fingerprint = filter_fingerprint(
            CURSOR_KIND_USER_ROLE,
            order.as_u8(),
            &(None::<UserOid>, Some(role_page.role_oid), role_page.enabled),
        );
        let user_disabled_fingerprint = filter_fingerprint(
            CURSOR_KIND_USER_ROLE,
            order.as_u8(),
            &(Some(user_oid), None::<RoleOid>, Some(false)),
        );

        assert_ne!(user_fingerprint, role_fingerprint);
        assert_ne!(user_fingerprint, user_disabled_fingerprint);
    }
}
