//! Transactional persistence port for user-group management.
//!
//! Implementations re-verify live management authority in the same transaction
//! as each write, lock the existing lifecycle lock before mutable authority
//! reads, apply UUID version CAS, tombstone removed relations, rotate every
//! affected user version, check last-recovery protection, write the semantic
//! audit fact and only then commit.

use std::{error::Error as StdError, sync::Arc};

use async_trait::async_trait;
use identity_domain::{
    rbac::{GroupMembershipOid, GroupOid, GroupRoleBindingOid, LocalizedText, RoleOid},
    user::UserOid,
};
use uuid::Uuid;

use crate::authorization::ManagementAuthorizationError;

use super::{
    cursor::{RbacPageDirection, RbacSortKey},
    group::{
        DeleteGroupResult, GroupFilter, GroupMembershipFilter, GroupMembershipMutationResult,
        GroupMembershipOrder, GroupMembershipRecord, GroupOrder, GroupRecord,
        GroupRoleBindingRecord, GroupRoleFilter, GroupRoleMutationResult, GroupRoleOrder,
    },
    model::RbacManagementAuthority,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GroupEntityKind {
    Group,
    Membership,
    RoleBinding,
    User,
    Role,
}

#[derive(Debug, thiserror::Error)]
pub enum GroupManagementRepositoryError {
    #[error("group management storage failure")]
    Storage(#[source] Box<dyn StdError + Send + Sync + 'static>),
    #[error("group management authorization recheck failed")]
    Authorization(#[source] ManagementAuthorizationError),
    #[error("group management audit commit failed")]
    AuditFailed(#[source] Box<dyn StdError + Send + Sync + 'static>),
    #[error("the last recoverable authorization administrator would be removed")]
    LastRecoveryProtected,
    #[error("persisted group management record is malformed")]
    CorruptRecord,
    #[error("group management record not found: {0:?}")]
    NotFound(GroupEntityKind),
    #[error("optimistic group version conflict; current version is {current_version}")]
    VersionConflict { current_version: Uuid },
    #[error("built-in group definitions are immutable")]
    BuiltInProtected,
    #[error("the group is disabled")]
    GroupDisabled,
    #[error("an assigned role is disabled: {role_oid}")]
    RoleDisabled { role_oid: RoleOid },
    #[error("the new delegated permission exceeds the actor's pre-change authority: {scope}")]
    DelegationCeilingExceeded { scope: String },
    #[error("the user is already an active member of the group")]
    MembershipAlreadyActive,
    #[error("the user is not an active member of the group")]
    MembershipNotActive,
    #[error("group metadata is invalid: {field}")]
    InvalidMetadata { field: String },
    #[error("the update does not change any field")]
    EmptyUpdate,
    #[error("group collection exceeds the limit of {limit}")]
    LimitExceeded { limit: u32 },
}

#[derive(Debug, Clone)]
pub struct GroupPageEntry {
    pub sort_key: RbacSortKey,
    pub record: GroupRecord,
}

#[derive(Debug, Clone)]
pub struct GroupMembershipPageEntry {
    pub sort_key: RbacSortKey,
    pub record: GroupMembershipRecord,
}

#[derive(Debug, Clone)]
pub struct GroupRolePageEntry {
    pub sort_key: RbacSortKey,
    pub record: GroupRoleBindingRecord,
}

#[derive(Debug, Clone)]
pub struct GroupPageData<T> {
    pub items: Vec<T>,
    pub has_previous_page: bool,
    pub has_next_page: bool,
}

#[derive(Debug, Clone)]
pub struct GroupQuery {
    pub filter: GroupFilter,
    pub order: GroupOrder,
    pub direction: RbacPageDirection,
    pub after: Option<RbacSortKey>,
    pub before: Option<RbacSortKey>,
    pub limit: usize,
}

#[derive(Debug, Clone)]
pub struct GroupMembershipQuery {
    pub group_oid: GroupOid,
    pub filter: GroupMembershipFilter,
    pub order: GroupMembershipOrder,
    pub direction: RbacPageDirection,
    pub after: Option<RbacSortKey>,
    pub before: Option<RbacSortKey>,
    pub limit: usize,
}

#[derive(Debug, Clone)]
pub struct GroupRoleQuery {
    pub group_oid: GroupOid,
    pub filter: GroupRoleFilter,
    pub order: GroupRoleOrder,
    pub direction: RbacPageDirection,
    pub after: Option<RbacSortKey>,
    pub before: Option<RbacSortKey>,
    pub limit: usize,
}

#[derive(Clone)]
pub struct CreateGroupTransaction {
    pub name: String,
    pub description: String,
    pub group_oid: GroupOid,
    pub names: Vec<LocalizedText>,
    pub descriptions: Vec<LocalizedText>,
    pub reason: String,
    pub authority: RbacManagementAuthority,
}

#[derive(Clone)]
pub struct UpdateGroupTransaction {
    pub name: Option<String>,
    pub description: Option<String>,
    pub group_oid: GroupOid,
    pub names: Option<Vec<LocalizedText>>,
    pub descriptions: Option<Vec<LocalizedText>>,
    pub expected_version: Uuid,
    pub reason: String,
    pub authority: RbacManagementAuthority,
}

#[derive(Clone)]
pub struct GroupStateTransaction {
    pub group_oid: GroupOid,
    pub expected_version: Uuid,
    pub reason: String,
    pub authority: RbacManagementAuthority,
}

#[derive(Clone)]
pub struct DeleteGroupTransaction {
    pub group_oid: GroupOid,
    pub expected_version: Uuid,
    pub reason: String,
    pub authority: RbacManagementAuthority,
}

#[derive(Clone)]
pub struct AddGroupMemberTransaction {
    pub group_oid: GroupOid,
    pub user_oid: UserOid,
    pub expected_version: Uuid,
    pub reason: String,
    pub authority: RbacManagementAuthority,
}

#[derive(Clone)]
pub struct RemoveGroupMemberTransaction {
    pub group_oid: GroupOid,
    pub user_oid: UserOid,
    pub expected_version: Uuid,
    pub reason: String,
    pub authority: RbacManagementAuthority,
}

#[derive(Clone)]
pub struct SetGroupRolesTransaction {
    pub group_oid: GroupOid,
    pub role_oids: Vec<RoleOid>,
    pub expected_version: Uuid,
    pub reason: String,
    pub authority: RbacManagementAuthority,
}

#[async_trait]
pub trait GroupManagementRepository: Send + Sync {
    async fn count_groups(
        &self,
        filter: GroupFilter,
    ) -> Result<u64, GroupManagementRepositoryError>;

    async fn list_groups(
        &self,
        query: GroupQuery,
    ) -> Result<GroupPageData<GroupPageEntry>, GroupManagementRepositoryError>;

    async fn find_group(
        &self,
        oid: GroupOid,
    ) -> Result<Option<GroupRecord>, GroupManagementRepositoryError>;

    async fn find_group_membership(
        &self,
        oid: GroupMembershipOid,
    ) -> Result<Option<GroupMembershipRecord>, GroupManagementRepositoryError>;

    async fn find_group_role_binding(
        &self,
        oid: GroupRoleBindingOid,
    ) -> Result<Option<GroupRoleBindingRecord>, GroupManagementRepositoryError>;

    async fn list_group_memberships(
        &self,
        query: GroupMembershipQuery,
    ) -> Result<GroupPageData<GroupMembershipPageEntry>, GroupManagementRepositoryError>;

    async fn list_group_roles(
        &self,
        query: GroupRoleQuery,
    ) -> Result<GroupPageData<GroupRolePageEntry>, GroupManagementRepositoryError>;

    async fn create_group(
        &self,
        command: CreateGroupTransaction,
    ) -> Result<GroupRecord, GroupManagementRepositoryError>;

    async fn update_group(
        &self,
        command: UpdateGroupTransaction,
    ) -> Result<GroupRecord, GroupManagementRepositoryError>;

    async fn set_group_enabled(
        &self,
        command: GroupStateTransaction,
        enabled: bool,
    ) -> Result<GroupRecord, GroupManagementRepositoryError>;

    async fn delete_group(
        &self,
        command: DeleteGroupTransaction,
    ) -> Result<DeleteGroupResult, GroupManagementRepositoryError>;

    async fn add_group_member(
        &self,
        command: AddGroupMemberTransaction,
    ) -> Result<GroupMembershipMutationResult, GroupManagementRepositoryError>;

    async fn remove_group_member(
        &self,
        command: RemoveGroupMemberTransaction,
    ) -> Result<GroupMembershipMutationResult, GroupManagementRepositoryError>;

    async fn set_group_roles(
        &self,
        command: SetGroupRolesTransaction,
    ) -> Result<GroupRoleMutationResult, GroupManagementRepositoryError>;
}

/// Convenience alias used by the composition root and adapters.
pub type SharedGroupManagementRepository = Arc<dyn GroupManagementRepository>;
