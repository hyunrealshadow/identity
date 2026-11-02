//! SeaORM implementation of group-management persistence.
//!
//! The implementation is standalone from the existing business RBAC management
//! repository so group tables, locks and authority checks can evolve without
//! changing A-owned role/permission internals.

mod audit;
mod authority;
mod mutation;
mod query;
mod support;

use async_trait::async_trait;
use identity_application::rbac::{
    AddGroupMemberTransaction, CreateGroupTransaction, DeleteGroupResult, DeleteGroupTransaction,
    GroupManagementRepository, GroupManagementRepositoryError, GroupMembershipMutationResult,
    GroupMembershipPageEntry, GroupMembershipQuery, GroupPageData, GroupPageEntry, GroupQuery,
    GroupRecord, GroupRoleMutationResult, GroupRolePageEntry, GroupRoleQuery,
    GroupStateTransaction, RemoveGroupMemberTransaction, SetGroupRolesTransaction,
    UpdateGroupTransaction,
};
use identity_domain::rbac::GroupOid;
use sea_orm::DatabaseConnection;

pub struct GroupManagementRepositoryImpl {
    db: DatabaseConnection,
}

impl GroupManagementRepositoryImpl {
    #[must_use]
    pub fn new(db: DatabaseConnection) -> Self {
        Self { db }
    }
}

#[async_trait]
impl GroupManagementRepository for GroupManagementRepositoryImpl {
    async fn count_groups(
        &self,
        filter: identity_application::rbac::GroupFilter,
    ) -> Result<u64, GroupManagementRepositoryError> {
        self.group_count(filter).await
    }

    async fn list_groups(
        &self,
        query: GroupQuery,
    ) -> Result<GroupPageData<GroupPageEntry>, GroupManagementRepositoryError> {
        self.group_list(query).await
    }

    async fn find_group(
        &self,
        oid: GroupOid,
    ) -> Result<Option<GroupRecord>, GroupManagementRepositoryError> {
        self.group_find(oid).await
    }

    async fn find_group_membership(
        &self,
        oid: identity_domain::rbac::GroupMembershipOid,
    ) -> Result<
        Option<identity_application::rbac::GroupMembershipRecord>,
        GroupManagementRepositoryError,
    > {
        self.membership_find(oid).await
    }

    async fn find_group_role_binding(
        &self,
        oid: identity_domain::rbac::GroupRoleBindingOid,
    ) -> Result<
        Option<identity_application::rbac::GroupRoleBindingRecord>,
        GroupManagementRepositoryError,
    > {
        self.group_role_find(oid).await
    }

    async fn list_group_memberships(
        &self,
        query: GroupMembershipQuery,
    ) -> Result<GroupPageData<GroupMembershipPageEntry>, GroupManagementRepositoryError> {
        self.membership_list(query).await
    }

    async fn list_group_roles(
        &self,
        query: GroupRoleQuery,
    ) -> Result<GroupPageData<GroupRolePageEntry>, GroupManagementRepositoryError> {
        self.role_list(query).await
    }

    async fn create_group(
        &self,
        command: CreateGroupTransaction,
    ) -> Result<GroupRecord, GroupManagementRepositoryError> {
        self.group_create(command).await
    }

    async fn update_group(
        &self,
        command: UpdateGroupTransaction,
    ) -> Result<GroupRecord, GroupManagementRepositoryError> {
        self.group_update(command).await
    }

    async fn set_group_enabled(
        &self,
        command: GroupStateTransaction,
        enabled: bool,
    ) -> Result<GroupRecord, GroupManagementRepositoryError> {
        self.group_set_enabled(command, enabled).await
    }

    async fn delete_group(
        &self,
        command: DeleteGroupTransaction,
    ) -> Result<DeleteGroupResult, GroupManagementRepositoryError> {
        self.group_delete(command).await
    }

    async fn add_group_member(
        &self,
        command: AddGroupMemberTransaction,
    ) -> Result<GroupMembershipMutationResult, GroupManagementRepositoryError> {
        self.group_member_add(command).await
    }

    async fn remove_group_member(
        &self,
        command: RemoveGroupMemberTransaction,
    ) -> Result<GroupMembershipMutationResult, GroupManagementRepositoryError> {
        self.group_member_remove(command).await
    }

    async fn set_group_roles(
        &self,
        command: SetGroupRolesTransaction,
    ) -> Result<GroupRoleMutationResult, GroupManagementRepositoryError> {
        self.group_roles_set(command).await
    }
}
