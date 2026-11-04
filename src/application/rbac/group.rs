//! User-group management types and localized command values.
//!
//! Query values carry the raw localized metadata; presentation fallback is a
//! pure read concern and never changes identity, authorization version or the
//! stored translation array.

use chrono::{DateTime, Utc};
use identity_domain::{
    rbac::{GroupMembershipOid, GroupOid, GroupRoleOid, LocalizedMetadata, LocalizedText, RoleOid},
    user::UserOid,
};
use serde::Serialize;
use uuid::Uuid;

pub const MAX_GROUP_MEMBERSHIPS: usize = 1_000;
pub const MAX_GROUP_ROLES: usize = 1_000;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GroupRecord {
    pub name: String,
    pub description: String,
    pub oid: GroupOid,
    pub built_in: bool,
    pub names: Vec<LocalizedText>,
    pub descriptions: Vec<LocalizedText>,
    pub enabled: bool,
    pub version: Uuid,
    pub created_at: DateTime<Utc>,
    pub updated_at: Option<DateTime<Utc>>,
}

impl GroupRecord {
    /// Present raw localized metadata. Fallback selection belongs to the
    /// consumer; display text never becomes a second identity.
    #[must_use]
    pub fn metadata(&self) -> LocalizedMetadata {
        LocalizedMetadata {
            names: self.names.clone(),
            descriptions: self.descriptions.clone(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GroupMembershipRecord {
    pub oid: GroupMembershipOid,
    pub group_oid: GroupOid,
    pub user_oid: UserOid,
    pub granted_by_user_oid: Option<UserOid>,
    pub reason: String,
    pub enabled: bool,
    pub revoked_at: Option<DateTime<Utc>>,
    pub version: Uuid,
    pub created_at: DateTime<Utc>,
    pub updated_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GroupRoleRecord {
    pub oid: GroupRoleOid,
    pub group_oid: GroupOid,
    pub role_oid: RoleOid,
    pub granted_by_user_oid: Option<UserOid>,
    pub reason: String,
    pub enabled: bool,
    pub revoked_at: Option<DateTime<Utc>>,
    pub version: Uuid,
    pub created_at: DateTime<Utc>,
    pub updated_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize)]
pub struct GroupFilter {
    pub query: Option<String>,
    pub enabled: Option<bool>,
    pub built_in: Option<bool>,
    /// Restricts the result to groups with an active membership for this user.
    pub user_oid: Option<UserOid>,
    /// Restricts the result to groups with an active binding for this role.
    pub role_oid: Option<RoleOid>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum GroupOrder {
    CreatedAtAsc,
    #[default]
    CreatedAtDesc,
}

impl GroupOrder {
    #[must_use]
    pub const fn as_u8(self) -> u8 {
        match self {
            Self::CreatedAtAsc => 0,
            Self::CreatedAtDesc => 1,
        }
    }

    #[must_use]
    pub const fn is_descending(self) -> bool {
        matches!(self, Self::CreatedAtDesc)
    }
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct GroupPageRequest {
    pub filter: GroupFilter,
    pub order: GroupOrder,
    pub first: Option<u32>,
    pub after: Option<String>,
    pub last: Option<u32>,
    pub before: Option<String>,
}

#[derive(Debug, Clone)]
pub struct GroupPageItem {
    pub record: GroupRecord,
    pub cursor: String,
}

#[derive(Debug, Clone)]
pub struct GroupPage {
    pub items: Vec<GroupPageItem>,
    pub has_previous_page: bool,
    pub has_next_page: bool,
}

#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize)]
pub struct GroupMembershipFilter {
    pub enabled: Option<bool>,
    pub user_oid: Option<UserOid>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum GroupMembershipOrder {
    CreatedAtAsc,
    #[default]
    CreatedAtDesc,
}

impl GroupMembershipOrder {
    #[must_use]
    pub const fn as_u8(self) -> u8 {
        match self {
            Self::CreatedAtAsc => 0,
            Self::CreatedAtDesc => 1,
        }
    }

    #[must_use]
    pub const fn is_descending(self) -> bool {
        matches!(self, Self::CreatedAtDesc)
    }
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct GroupMembershipPageRequest {
    pub filter: GroupMembershipFilter,
    pub order: GroupMembershipOrder,
    pub first: Option<u32>,
    pub after: Option<String>,
    pub last: Option<u32>,
    pub before: Option<String>,
}

#[derive(Debug, Clone)]
pub struct GroupMembershipPageItem {
    pub record: GroupMembershipRecord,
    pub cursor: String,
}

#[derive(Debug, Clone)]
pub struct GroupMembershipPage {
    pub items: Vec<GroupMembershipPageItem>,
    pub has_previous_page: bool,
    pub has_next_page: bool,
}

#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize)]
pub struct GroupRoleFilter {
    pub enabled: Option<bool>,
    pub role_oid: Option<RoleOid>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum GroupRoleOrder {
    CreatedAtAsc,
    #[default]
    CreatedAtDesc,
    RoleNameAsc,
    RoleNameDesc,
}

impl GroupRoleOrder {
    #[must_use]
    pub const fn as_u8(self) -> u8 {
        match self {
            Self::CreatedAtAsc => 0,
            Self::CreatedAtDesc => 1,
            Self::RoleNameAsc => 2,
            Self::RoleNameDesc => 3,
        }
    }

    #[must_use]
    pub const fn is_descending(self) -> bool {
        matches!(self, Self::CreatedAtDesc | Self::RoleNameDesc)
    }
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct GroupRolePageRequest {
    pub filter: GroupRoleFilter,
    pub order: GroupRoleOrder,
    pub first: Option<u32>,
    pub after: Option<String>,
    pub last: Option<u32>,
    pub before: Option<String>,
}

#[derive(Debug, Clone)]
pub struct GroupRolePageItem {
    pub record: GroupRoleRecord,
    pub cursor: String,
}

#[derive(Debug, Clone)]
pub struct GroupRolePage {
    pub items: Vec<GroupRolePageItem>,
    pub has_previous_page: bool,
    pub has_next_page: bool,
}

#[derive(Debug, Clone)]
pub struct CreateGroupCommand {
    pub name: String,
    pub description: String,
    pub names: Vec<LocalizedText>,
    pub descriptions: Vec<LocalizedText>,
    pub reason: String,
    pub client_mutation_id: Option<String>,
}

#[derive(Debug, Clone)]
pub struct UpdateGroupCommand {
    pub name: Option<String>,
    pub description: Option<String>,
    pub group_oid: GroupOid,
    pub names: Option<Vec<LocalizedText>>,
    pub descriptions: Option<Vec<LocalizedText>>,
    pub expected_version: Uuid,
    pub reason: String,
    pub client_mutation_id: Option<String>,
}

#[derive(Debug, Clone)]
pub struct GroupStateCommand {
    pub group_oid: GroupOid,
    pub expected_version: Uuid,
    pub reason: String,
    pub client_mutation_id: Option<String>,
}

#[derive(Debug, Clone)]
pub struct DeleteGroupCommand {
    pub group_oid: GroupOid,
    pub expected_version: Uuid,
    pub reason: String,
    pub client_mutation_id: Option<String>,
}

#[derive(Debug, Clone)]
pub struct AddGroupMemberCommand {
    pub group_oid: GroupOid,
    pub user_oid: UserOid,
    pub expected_version: Uuid,
    pub reason: String,
    pub client_mutation_id: Option<String>,
}

#[derive(Debug, Clone)]
pub struct RemoveGroupMemberCommand {
    pub group_oid: GroupOid,
    pub user_oid: UserOid,
    pub expected_version: Uuid,
    pub reason: String,
    pub client_mutation_id: Option<String>,
}

#[derive(Debug, Clone)]
pub struct SetGroupRolesCommand {
    pub group_oid: GroupOid,
    pub role_oids: Vec<RoleOid>,
    pub expected_version: Uuid,
    pub reason: String,
    pub client_mutation_id: Option<String>,
}

#[derive(Debug, Clone)]
pub struct GroupMembershipMutationResult {
    pub group_oid: GroupOid,
    pub group_version: Uuid,
    pub membership: GroupMembershipRecord,
}

#[derive(Debug, Clone)]
pub struct GroupRoleMutationResult {
    pub group_oid: GroupOid,
    pub group_version: Uuid,
    pub role_oids: Vec<RoleOid>,
    pub added_count: u32,
    pub removed_count: u32,
}

#[derive(Debug, Clone)]
pub struct DeleteGroupResult {
    pub group_oid: GroupOid,
    pub deleted: bool,
}
