//! SeaORM implementation of unified RBAC management persistence.
//!
//! Every write re-checks management authority, locks the live actor and target
//! rows, applies UUID version CAS and appends the semantic audit fact before
//! committing. No SQL error text crosses the application port.

pub(crate) mod audit;
pub(crate) mod authority;
mod catalog;
mod client;
mod delegation;
mod resource;
mod role;
mod scope;
pub(crate) mod support;
mod user_role;

use async_trait::async_trait;
use identity_application::rbac::{
    ApiResourceRecord, AssignUserRolesTransaction, ClientScopePageEntry, ClientScopeQuery,
    ClientScopeSetResult, CreateResourceTransaction, CreateRoleTransaction, CreateScopeTransaction,
    EffectivePermissionPageData, EffectivePermissionQuery, RbacManagementRepository,
    RbacManagementRepositoryError, RbacPageData, ResourcePageEntry, ResourceQuery,
    ResourceStateTransaction, RevokeUserRolesTransaction, RoleFilter, RolePageEntry, RoleQuery,
    RoleRecord, RoleStateTransaction, ScopeFilter, ScopeOid, ScopePageEntry, ScopeQuery,
    ScopeRecord, ScopeStateTransaction, SetClientScopesTransaction, SetRolePermissionsTransaction,
    UpdateResourceTransaction, UpdateRoleTransaction, UpdateScopeTransaction,
    UserRoleMutationResult, UserRolePageData, UserRoleQuery,
};
use identity_domain::{
    client::model::ClientOid,
    rbac::{ResourceOid, RoleOid},
    user::UserOid,
};
use sea_orm::DatabaseConnection;
use uuid::Uuid;

pub struct RbacManagementRepositoryImpl {
    db: DatabaseConnection,
}

impl RbacManagementRepositoryImpl {
    #[must_use]
    pub fn new(db: DatabaseConnection) -> Self {
        Self { db }
    }
}

#[async_trait]
impl RbacManagementRepository for RbacManagementRepositoryImpl {
    async fn count_roles(&self, filter: RoleFilter) -> Result<u64, RbacManagementRepositoryError> {
        self.role_count(filter).await
    }
    async fn count_scopes(
        &self,
        filter: ScopeFilter,
    ) -> Result<u64, RbacManagementRepositoryError> {
        self.scope_count(filter).await
    }
    async fn count_client_scopes(
        &self,
        client_oid: ClientOid,
    ) -> Result<u64, RbacManagementRepositoryError> {
        self.client_scope_count(client_oid).await
    }

    async fn list_resources(
        &self,
        query: ResourceQuery,
    ) -> Result<RbacPageData<ResourcePageEntry>, RbacManagementRepositoryError> {
        self.resource_list(query).await
    }

    async fn find_resource(
        &self,
        oid: ResourceOid,
    ) -> Result<Option<ApiResourceRecord>, RbacManagementRepositoryError> {
        self.resource_find(oid).await
    }

    async fn create_resource(
        &self,
        command: CreateResourceTransaction,
    ) -> Result<ApiResourceRecord, RbacManagementRepositoryError> {
        self.resource_create(command).await
    }

    async fn update_resource(
        &self,
        command: UpdateResourceTransaction,
    ) -> Result<ApiResourceRecord, RbacManagementRepositoryError> {
        self.resource_update(command).await
    }

    async fn set_resource_enabled(
        &self,
        command: ResourceStateTransaction,
        enabled: bool,
    ) -> Result<ApiResourceRecord, RbacManagementRepositoryError> {
        self.resource_set_enabled(command, enabled).await
    }

    async fn list_scopes(
        &self,
        query: ScopeQuery,
    ) -> Result<RbacPageData<ScopePageEntry>, RbacManagementRepositoryError> {
        self.scope_list(query).await
    }

    async fn find_scope(
        &self,
        oid: ScopeOid,
    ) -> Result<Option<ScopeRecord>, RbacManagementRepositoryError> {
        self.scope_find(oid).await
    }

    async fn create_scope(
        &self,
        command: CreateScopeTransaction,
    ) -> Result<ScopeRecord, RbacManagementRepositoryError> {
        self.scope_create(command).await
    }

    async fn update_scope(
        &self,
        command: UpdateScopeTransaction,
    ) -> Result<ScopeRecord, RbacManagementRepositoryError> {
        self.scope_update(command).await
    }

    async fn set_scope_enabled(
        &self,
        command: ScopeStateTransaction,
        enabled: bool,
    ) -> Result<ScopeRecord, RbacManagementRepositoryError> {
        self.scope_set_enabled(command, enabled).await
    }

    async fn list_roles(
        &self,
        query: RoleQuery,
    ) -> Result<RbacPageData<RolePageEntry>, RbacManagementRepositoryError> {
        self.role_list(query).await
    }

    async fn find_role(
        &self,
        oid: RoleOid,
    ) -> Result<Option<RoleRecord>, RbacManagementRepositoryError> {
        self.role_find(oid).await
    }

    async fn create_role(
        &self,
        command: CreateRoleTransaction,
    ) -> Result<RoleRecord, RbacManagementRepositoryError> {
        self.role_create(command).await
    }

    async fn update_role(
        &self,
        command: UpdateRoleTransaction,
    ) -> Result<RoleRecord, RbacManagementRepositoryError> {
        self.role_update(command).await
    }

    async fn set_role_enabled(
        &self,
        command: RoleStateTransaction,
        enabled: bool,
    ) -> Result<RoleRecord, RbacManagementRepositoryError> {
        self.role_set_enabled(command, enabled).await
    }

    async fn set_role_permissions(
        &self,
        command: SetRolePermissionsTransaction,
    ) -> Result<RoleRecord, RbacManagementRepositoryError> {
        self.role_set_permissions(command).await
    }

    async fn list_user_roles(
        &self,
        query: UserRoleQuery,
    ) -> Result<UserRolePageData, RbacManagementRepositoryError> {
        self.user_role_list(query).await
    }

    async fn find_user_version(
        &self,
        user_oid: UserOid,
    ) -> Result<Uuid, RbacManagementRepositoryError> {
        self.user_version(user_oid).await
    }

    async fn find_roles(
        &self,
        oids: Vec<RoleOid>,
    ) -> Result<Vec<RoleRecord>, RbacManagementRepositoryError> {
        self.roles_find(oids).await
    }

    async fn count_effective_permissions(
        &self,
        user_oid: UserOid,
        resource_oid: ResourceOid,
    ) -> Result<u64, RbacManagementRepositoryError> {
        self.effective_count(user_oid, resource_oid).await
    }

    async fn list_effective_permissions(
        &self,
        query: EffectivePermissionQuery,
    ) -> Result<EffectivePermissionPageData, RbacManagementRepositoryError> {
        self.effective_list(query).await
    }

    async fn assign_user_roles(
        &self,
        command: AssignUserRolesTransaction,
    ) -> Result<UserRoleMutationResult, RbacManagementRepositoryError> {
        self.user_role_assign(command).await
    }

    async fn revoke_user_roles(
        &self,
        command: RevokeUserRolesTransaction,
    ) -> Result<UserRoleMutationResult, RbacManagementRepositoryError> {
        self.user_role_revoke(command).await
    }

    async fn list_client_scopes(
        &self,
        query: ClientScopeQuery,
    ) -> Result<RbacPageData<ClientScopePageEntry>, RbacManagementRepositoryError> {
        self.client_scope_list(query).await
    }

    async fn set_client_scopes(
        &self,
        command: SetClientScopesTransaction,
    ) -> Result<ClientScopeSetResult, RbacManagementRepositoryError> {
        self.client_scope_set(command).await
    }
}
