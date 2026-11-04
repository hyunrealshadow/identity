//! Transactional persistence ports for unified RBAC management.
//!
//! Implementations must re-verify management authority inside the same
//! transaction that mutates RBAC data, lock the live actor and target rows,
//! apply UUID version CAS, invalidate affected authorization and write the
//! semantic audit fact before commit. No SQL, SeaORM or HTTP type crosses this
//! boundary.

use std::{error::Error as StdError, sync::Arc};

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use uuid::Uuid;

use crate::authorization::ManagementAuthorizationError;
use identity_domain::{
    client::model::ClientOid,
    rbac::{LocalizedMetadata, LocalizedText, ResourceOid, RoleOid, UserRoleBindingOid},
    user::UserOid,
};

use super::{
    binding::{
        EffectivePermissionOrder, EffectivePermissionRecord, UserRoleBindingMutationResult,
        UserRoleBindingOrder, UserRoleBindingRecord,
    },
    client::{
        ClientScopeAssignment, ClientScopeSetResult, ClientScopeTargetFilter,
        ClientScopeTargetOrder, ClientScopeTargetRecord,
    },
    cursor::{RbacPageDirection, RbacSortKey},
    model::{RbacManagementAuthority, ScopeDescription, ScopeOid},
    resource::{ApiResourceRecord, ResourceFilter, ResourceOrder},
    role::{RoleFilter, RoleOrder, RoleRecord},
    scope::{ScopeFilter, ScopeOrder, ScopeRecord},
};

#[derive(Debug, Clone)]
pub struct RbacPageData<T> {
    pub items: Vec<T>,
    pub has_previous_page: bool,
    pub has_next_page: bool,
}

#[derive(Debug, Clone)]
pub struct ResourcePageEntry {
    pub sort_key: RbacSortKey,
    pub record: ApiResourceRecord,
}

#[derive(Debug, Clone)]
pub struct ScopePageEntry {
    pub sort_key: RbacSortKey,
    pub record: ScopeRecord,
}

#[derive(Debug, Clone)]
pub struct ClientScopePageEntry {
    pub sort_key: RbacSortKey,
    pub record: ScopeRecord,
    pub client_granted: bool,
}

#[derive(Debug, Clone)]
pub struct RolePageEntry {
    pub sort_key: RbacSortKey,
    pub record: RoleRecord,
}

#[derive(Debug, Clone)]
pub struct UserRoleBindingPageEntry {
    pub sort_key: RbacSortKey,
    pub record: UserRoleBindingRecord,
}

#[derive(Debug, Clone)]
pub struct EffectivePermissionPageEntry {
    pub sort_key: RbacSortKey,
    pub record: EffectivePermissionRecord,
}

/// One consistent binding page plus optional single-user version.
///
/// `user_version` is `Some` for a user-filtered page (including an empty page)
/// and `None` for a role-filtered page spanning several users.
#[derive(Debug, Clone)]
pub struct UserRoleBindingPageData {
    pub items: Vec<UserRoleBindingPageEntry>,
    pub has_previous_page: bool,
    pub has_next_page: bool,
    pub user_version: Option<Uuid>,
}

#[derive(Debug, Clone)]
pub struct EffectivePermissionPageData {
    pub items: Vec<EffectivePermissionPageEntry>,
    pub has_previous_page: bool,
    pub has_next_page: bool,
    pub user_version: Uuid,
}

#[derive(Debug, Clone)]
pub struct ClientScopeTargetPageEntry {
    pub sort_key: RbacSortKey,
    pub record: ClientScopeTargetRecord,
}

#[derive(Debug, Clone)]
pub struct ResourceQuery {
    pub filter: ResourceFilter,
    pub order: ResourceOrder,
    pub direction: RbacPageDirection,
    pub after: Option<RbacSortKey>,
    pub before: Option<RbacSortKey>,
    pub limit: usize,
}

#[derive(Debug, Clone)]
pub struct ScopeQuery {
    pub filter: ScopeFilter,
    pub order: ScopeOrder,
    pub direction: RbacPageDirection,
    pub after: Option<RbacSortKey>,
    pub before: Option<RbacSortKey>,
    pub limit: usize,
}

#[derive(Debug, Clone)]
pub struct RoleQuery {
    pub filter: RoleFilter,
    pub order: RoleOrder,
    pub direction: RbacPageDirection,
    pub after: Option<RbacSortKey>,
    pub before: Option<RbacSortKey>,
    pub limit: usize,
}

#[derive(Debug, Clone)]
pub struct UserRoleBindingQuery {
    pub user_oid: Option<UserOid>,
    pub role_oid: Option<RoleOid>,
    pub enabled: Option<bool>,
    pub order: UserRoleBindingOrder,
    pub direction: RbacPageDirection,
    pub after: Option<RbacSortKey>,
    pub before: Option<RbacSortKey>,
    pub limit: usize,
}

#[derive(Debug, Clone)]
pub struct EffectivePermissionQuery {
    pub user_oid: UserOid,
    pub resource_oid: ResourceOid,
    pub order: EffectivePermissionOrder,
    pub direction: RbacPageDirection,
    pub after: Option<RbacSortKey>,
    pub before: Option<RbacSortKey>,
    pub limit: usize,
}

#[derive(Debug, Clone)]
pub struct ClientScopeTargetQuery {
    pub filter: ClientScopeTargetFilter,
    pub order: ClientScopeTargetOrder,
    pub direction: RbacPageDirection,
    pub after: Option<RbacSortKey>,
    pub before: Option<RbacSortKey>,
    pub limit: usize,
}

#[derive(Debug, Clone)]
pub struct ClientScopeQuery {
    pub client_oid: ClientOid,
    pub order: ScopeOrder,
    pub direction: RbacPageDirection,
    pub after: Option<RbacSortKey>,
    pub before: Option<RbacSortKey>,
    pub limit: usize,
}

#[derive(Clone)]
pub struct CreateResourceTransaction {
    pub resource_oid: ResourceOid,
    pub uri: String,
    pub name: String,
    pub reason: String,
    pub authority: RbacManagementAuthority,
}

#[derive(Clone)]
pub struct UpdateResourceTransaction {
    pub resource_oid: ResourceOid,
    pub name: Option<String>,
    pub expected_version: Uuid,
    pub reason: String,
    pub authority: RbacManagementAuthority,
}

#[derive(Clone)]
pub struct ResourceStateTransaction {
    pub resource_oid: ResourceOid,
    pub expected_version: Uuid,
    pub reason: String,
    pub authority: RbacManagementAuthority,
}

#[derive(Clone)]
pub struct CreateScopeTransaction {
    pub scope_oid: ScopeOid,
    pub resource_oid: ResourceOid,
    pub code: String,
    pub name: String,
    pub names: Vec<ScopeDescription>,
    pub description: String,
    pub descriptions: Vec<ScopeDescription>,
    pub reason: String,
    pub authority: RbacManagementAuthority,
}

#[derive(Clone)]
pub struct UpdateScopeTransaction {
    pub scope_oid: ScopeOid,
    pub name: Option<String>,
    pub names: Option<Vec<ScopeDescription>>,
    pub description: Option<String>,
    pub descriptions: Option<Vec<ScopeDescription>>,
    pub expected_version: Uuid,
    pub reason: String,
    pub authority: RbacManagementAuthority,
}

#[derive(Clone)]
pub struct ScopeStateTransaction {
    pub scope_oid: ScopeOid,
    pub expected_version: Uuid,
    pub reason: String,
    pub authority: RbacManagementAuthority,
}

#[derive(Clone)]
pub struct CreateRoleTransaction {
    pub role_oid: RoleOid,
    pub name: String,
    pub description: String,
    pub metadata: LocalizedMetadata,
    pub reason: String,
    pub authority: RbacManagementAuthority,
}

#[derive(Clone)]
pub struct UpdateRoleTransaction {
    pub name: Option<String>,
    pub description: Option<String>,
    pub role_oid: RoleOid,
    /// Partial patch. Omitted names are merged with the locked current row.
    pub names: Option<Vec<LocalizedText>>,
    /// Partial patch. Omitted descriptions are merged with the locked current
    /// row; `Some(empty)` clears them.
    pub descriptions: Option<Vec<LocalizedText>>,
    pub expected_version: Uuid,
    pub reason: String,
    pub authority: RbacManagementAuthority,
}

#[derive(Clone)]
pub struct RoleStateTransaction {
    pub role_oid: RoleOid,
    pub expected_version: Uuid,
    pub reason: String,
    pub authority: RbacManagementAuthority,
}

#[derive(Clone)]
pub struct SetRolePermissionsTransaction {
    pub role_oid: RoleOid,
    pub scope_oids: Vec<ScopeOid>,
    pub expected_version: Uuid,
    pub reason: String,
    pub authority: RbacManagementAuthority,
}

#[derive(Clone)]
pub struct AssignUserRolesTransaction {
    pub user_oid: UserOid,
    pub role_oids: Vec<RoleOid>,
    pub expected_user_version: Uuid,
    pub reason: String,
    pub authority: RbacManagementAuthority,
}

#[derive(Clone)]
pub struct RevokeUserRolesTransaction {
    pub user_oid: UserOid,
    pub role_oids: Vec<RoleOid>,
    pub expected_user_version: Uuid,
    pub reason: String,
    pub authority: RbacManagementAuthority,
}

#[derive(Clone)]
pub struct SetClientScopesTransaction {
    pub client_oid: ClientOid,
    pub scopes: Vec<ClientScopeAssignment>,
    pub expected_version: Uuid,
    pub reason: String,
    pub authority: RbacManagementAuthority,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RbacEntityKind {
    Resource,
    Scope,
    Role,
    Binding,
    User,
    Client,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RbacDuplicateKind {
    ResourceUri,
    ScopeCode,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RbacProtectedKind {
    ReservedResource,
    BuiltInScope,
    BuiltInClient,
    BuiltInRole,
    BuiltInGroup,
}

#[derive(Debug, thiserror::Error)]
pub enum RbacManagementRepositoryError {
    #[error("RBAC storage failure")]
    Storage(#[source] Box<dyn StdError + Send + Sync + 'static>),
    #[error("RBAC authorization recheck failed")]
    Authorization(#[source] ManagementAuthorizationError),
    #[error("RBAC audit commit failed")]
    AuditFailed(#[source] Box<dyn StdError + Send + Sync + 'static>),
    #[error("no recoverable authorization administrator remains")]
    LastRecoverableAdministrator,
    #[error("persisted RBAC record is malformed")]
    CorruptRecord,
    #[error("RBAC record not found: {0:?}")]
    NotFound(RbacEntityKind),
    #[error("optimistic version conflict; current version is {current_version}")]
    VersionConflict { current_version: Uuid },
    #[error("user version is stale; current is {current_version}")]
    UserVersionStale { current_version: Uuid },
    #[error("client management policy version is stale; current is {current_version}")]
    PolicyVersionStale { current_version: Uuid },
    #[error("duplicate RBAC identity: {0:?}")]
    Duplicate(RbacDuplicateKind),
    #[error("protected RBAC object: {0:?}")]
    Protected(RbacProtectedKind),
    #[error("scope is not a non-reserved business scope: {scope}")]
    ScopeNotBusiness { scope: String },
    #[error("scope cannot be granted to a client itself: {scope}")]
    ClientGrantNotAllowed { scope: String },
    #[error("scope code is not a valid permission code: {code}")]
    InvalidPermissionCode { code: String },
    #[error("RBAC collection exceeds the limit of {limit}")]
    LimitExceeded { limit: u32 },
    #[error("role is disabled and cannot be newly assigned: {role_oid}")]
    RoleDisabled { role_oid: RoleOid },
    #[error("user does not have an active binding for role: {role_oid}")]
    RoleNotAssigned { role_oid: RoleOid },
    #[error("the update does not change any field")]
    EmptyUpdate,
    #[error("the built-in definition identity conflicts with an existing custom object")]
    BuiltInIdentityConflict,
    #[error(
        "the operation would grant a permission outside the actor's pre-change authority: {permission}"
    )]
    DelegationCeilingExceeded { permission: String },
    #[error("built-in permission reference is invalid: {permission}")]
    InvalidBuiltInPermissionReference { permission: String },
}

#[async_trait]
pub trait RbacManagementRepository: Send + Sync {
    async fn count_roles(&self, filter: RoleFilter) -> Result<u64, RbacManagementRepositoryError>;
    async fn count_scopes(&self, filter: ScopeFilter)
    -> Result<u64, RbacManagementRepositoryError>;
    async fn count_client_scopes(
        &self,
        client_oid: ClientOid,
    ) -> Result<u64, RbacManagementRepositoryError>;

    async fn list_resources(
        &self,
        query: ResourceQuery,
    ) -> Result<RbacPageData<ResourcePageEntry>, RbacManagementRepositoryError>;

    async fn find_resource(
        &self,
        oid: ResourceOid,
    ) -> Result<Option<ApiResourceRecord>, RbacManagementRepositoryError>;

    async fn create_resource(
        &self,
        command: CreateResourceTransaction,
    ) -> Result<ApiResourceRecord, RbacManagementRepositoryError>;

    async fn update_resource(
        &self,
        command: UpdateResourceTransaction,
    ) -> Result<ApiResourceRecord, RbacManagementRepositoryError>;

    async fn set_resource_enabled(
        &self,
        command: ResourceStateTransaction,
        enabled: bool,
    ) -> Result<ApiResourceRecord, RbacManagementRepositoryError>;

    async fn list_scopes(
        &self,
        query: ScopeQuery,
    ) -> Result<RbacPageData<ScopePageEntry>, RbacManagementRepositoryError>;

    async fn find_scope(
        &self,
        oid: ScopeOid,
    ) -> Result<Option<ScopeRecord>, RbacManagementRepositoryError>;

    async fn create_scope(
        &self,
        command: CreateScopeTransaction,
    ) -> Result<ScopeRecord, RbacManagementRepositoryError>;

    async fn update_scope(
        &self,
        command: UpdateScopeTransaction,
    ) -> Result<ScopeRecord, RbacManagementRepositoryError>;

    async fn set_scope_enabled(
        &self,
        command: ScopeStateTransaction,
        enabled: bool,
    ) -> Result<ScopeRecord, RbacManagementRepositoryError>;

    async fn list_roles(
        &self,
        query: RoleQuery,
    ) -> Result<RbacPageData<RolePageEntry>, RbacManagementRepositoryError>;

    async fn find_role(
        &self,
        oid: RoleOid,
    ) -> Result<Option<RoleRecord>, RbacManagementRepositoryError>;

    async fn create_role(
        &self,
        command: CreateRoleTransaction,
    ) -> Result<RoleRecord, RbacManagementRepositoryError>;

    async fn update_role(
        &self,
        command: UpdateRoleTransaction,
    ) -> Result<RoleRecord, RbacManagementRepositoryError>;

    async fn set_role_enabled(
        &self,
        command: RoleStateTransaction,
        enabled: bool,
    ) -> Result<RoleRecord, RbacManagementRepositoryError>;

    async fn set_role_permissions(
        &self,
        command: SetRolePermissionsTransaction,
    ) -> Result<RoleRecord, RbacManagementRepositoryError>;

    /// One snapshot read: page rows and (for a user filter) the current
    /// generation are returned together so the page and its CAS metadata
    /// cannot diverge.
    async fn list_user_role_bindings(
        &self,
        query: UserRoleBindingQuery,
    ) -> Result<UserRoleBindingPageData, RbacManagementRepositoryError>;

    /// Current core user UUID version for one real user.
    ///
    /// A missing user is `NotFound(User)`, never a fabricated version.
    async fn find_user_version(
        &self,
        user_oid: UserOid,
    ) -> Result<Uuid, RbacManagementRepositoryError>;

    /// Read the bindings identified by server-produced IDs.
    ///
    /// Bounded to 100 entries. This is not a general search API: callers pass
    /// only IDs returned by a guarded mutation or an active connection edge.
    async fn find_user_role_bindings(
        &self,
        binding_oids: Vec<UserRoleBindingOid>,
    ) -> Result<Vec<UserRoleBindingRecord>, RbacManagementRepositoryError>;

    /// Full live permission union for one user and API resource, independent of cursors.
    async fn count_effective_permissions(
        &self,
        user_oid: UserOid,
        resource_oid: ResourceOid,
    ) -> Result<u64, RbacManagementRepositoryError>;

    async fn list_effective_permissions(
        &self,
        query: EffectivePermissionQuery,
    ) -> Result<EffectivePermissionPageData, RbacManagementRepositoryError>;

    async fn assign_user_roles(
        &self,
        command: AssignUserRolesTransaction,
    ) -> Result<UserRoleBindingMutationResult, RbacManagementRepositoryError>;

    async fn revoke_user_roles(
        &self,
        command: RevokeUserRolesTransaction,
    ) -> Result<UserRoleBindingMutationResult, RbacManagementRepositoryError>;

    async fn list_client_scope_targets(
        &self,
        query: ClientScopeTargetQuery,
    ) -> Result<RbacPageData<ClientScopeTargetPageEntry>, RbacManagementRepositoryError>;

    async fn list_client_scopes(
        &self,
        query: ClientScopeQuery,
    ) -> Result<RbacPageData<ClientScopePageEntry>, RbacManagementRepositoryError>;

    async fn set_client_scopes(
        &self,
        command: SetClientScopesTransaction,
    ) -> Result<ClientScopeSetResult, RbacManagementRepositoryError>;
}

/// Convenience alias used by the composition root and adapters.
pub type SharedRbacManagementRepository = Arc<dyn RbacManagementRepository>;

/// Shared helper for `DateTime<Utc>` mapping in repository implementations.
#[must_use]
pub fn utc(value: DateTime<chrono::FixedOffset>) -> DateTime<Utc> {
    value.with_timezone(&Utc)
}
