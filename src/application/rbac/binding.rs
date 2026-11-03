//! User-role binding and effective-permission query types.

use chrono::{DateTime, Utc};
use identity_domain::{
    rbac::{
        GroupMembershipOid, GroupOid, GroupRoleBindingOid, ResourceOid, ResourcePermissionOid,
        RoleOid, UserRoleBindingOid,
    },
    user::UserOid,
};
use uuid::Uuid;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EffectivePermissionSourceRecord {
    pub binding_oid: UserRoleBindingOid,
    pub role_oid: RoleOid,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EffectiveGroupPermissionSourceRecord {
    pub group_oid: GroupOid,
    pub membership_oid: GroupMembershipOid,
    pub group_role_binding_oid: GroupRoleBindingOid,
    pub role_oid: RoleOid,
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
pub struct UserRoleBindingRecord {
    pub oid: UserRoleBindingOid,
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
pub enum UserRoleBindingOrder {
    CreatedAtAsc,
    #[default]
    CreatedAtDesc,
}

impl UserRoleBindingOrder {
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
    pub enabled: Option<bool>,
    pub order: UserRoleBindingOrder,
    pub first: Option<u32>,
    pub after: Option<String>,
    pub last: Option<u32>,
    pub before: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RoleUserPageRequest {
    pub role_oid: RoleOid,
    pub enabled: Option<bool>,
    pub order: UserRoleBindingOrder,
    pub first: Option<u32>,
    pub after: Option<String>,
    pub last: Option<u32>,
    pub before: Option<String>,
}

#[derive(Debug, Clone)]
pub struct UserRoleBindingPageItem {
    pub record: UserRoleBindingRecord,
    pub cursor: String,
}

#[derive(Debug, Clone)]
pub struct UserRoleBindingPage {
    pub items: Vec<UserRoleBindingPageItem>,
    pub has_previous_page: bool,
    pub has_next_page: bool,
    /// `Some` for `list_user_roles` (including an empty binding page) and
    /// `None` for `list_role_users`, which can span several users.
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
pub struct UserRoleBindingMutationResult {
    pub user_oid: UserOid,
    pub user_version: Uuid,
    pub binding_oids: Vec<UserRoleBindingOid>,
    pub created_count: u32,
    pub revoked_count: u32,
}

#[cfg(test)]
mod tests {
    use uuid::Uuid;

    use super::{RoleUserPageRequest, UserRoleBindingOrder, UserRolePageRequest};
    use crate::{
        domain::{rbac::RoleOid, user::UserOid},
        rbac::cursor::{CURSOR_KIND_BINDING, filter_fingerprint},
    };

    fn user_request(user_oid: UserOid, enabled: Option<bool>) -> UserRolePageRequest {
        UserRolePageRequest {
            user_oid,
            enabled,
            order: UserRoleBindingOrder::CreatedAtDesc,
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
            order: UserRoleBindingOrder::CreatedAtDesc,
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
        let order = UserRoleBindingOrder::CreatedAtDesc;

        let user_fingerprint = filter_fingerprint(
            CURSOR_KIND_BINDING,
            order.as_u8(),
            &(Some(user_page.user_oid), None::<RoleOid>, user_page.enabled),
        );
        let role_fingerprint = filter_fingerprint(
            CURSOR_KIND_BINDING,
            order.as_u8(),
            &(None::<UserOid>, Some(role_page.role_oid), role_page.enabled),
        );
        let user_disabled_fingerprint = filter_fingerprint(
            CURSOR_KIND_BINDING,
            order.as_u8(),
            &(Some(user_oid), None::<RoleOid>, Some(false)),
        );

        assert_ne!(user_fingerprint, role_fingerprint);
        assert_ne!(user_fingerprint, user_disabled_fingerprint);
    }
}
