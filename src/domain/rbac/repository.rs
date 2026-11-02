//! Foundation repository ports for unified RBAC.
//!
//! These ports describe the invariants later application services rely on. They
//! do not include a full CRUD service or GraphQL surface. Optimistic versions
//! are UUID equality tokens; no port exposes a numeric counter.

use std::error::Error as StdError;

use crate::{
    authorization::ids::AuthorizationVersion,
    rbac::{
        ids::{ResourceOid, ResourcePermissionOid, RoleOid, RolePermissionOid, UserRoleBindingOid},
        model::{EffectivePermission, Role, RolePermission, UserRoleBinding},
    },
    user::UserOid,
};

#[derive(Debug, thiserror::Error)]
pub enum RbacRepositoryError {
    #[error("RBAC storage failure")]
    Storage(#[source] Box<dyn StdError + Send + Sync + 'static>),
    #[error("role not found")]
    RoleNotFound,
    #[error("permission not found")]
    PermissionNotFound,
    #[error("user role binding not found")]
    BindingNotFound,
    #[error("duplicate permission identity or scope reference")]
    DuplicatePermission,
    #[error("optimistic version conflict")]
    VersionConflict { current: AuthorizationVersion },
    #[error("authorization version is stale")]
    StaleAuthorizationVersion,
    #[error("persisted RBAC record is malformed")]
    CorruptRecord,
}

#[async_trait::async_trait]
pub trait RoleRepository: Send + Sync {
    async fn find_role(&self, oid: RoleOid) -> Result<Option<Role>, RbacRepositoryError>;

    async fn list_roles(&self) -> Result<Vec<Role>, RbacRepositoryError>;

    async fn insert_role(&self, role: &Role) -> Result<(), RbacRepositoryError>;

    async fn update_role(
        &self,
        role: &Role,
        expected_version: AuthorizationVersion,
    ) -> Result<Role, RbacRepositoryError>;

    async fn list_role_permissions(
        &self,
        role: RoleOid,
    ) -> Result<Vec<RolePermission>, RbacRepositoryError>;

    /// Atomically replace explicit membership. No inheritance or wildcard is
    /// implied by the set.
    async fn replace_role_permissions(
        &self,
        role: RoleOid,
        memberships: &[(RolePermissionOid, ResourcePermissionOid)],
        expected_version: AuthorizationVersion,
    ) -> Result<Role, RbacRepositoryError>;
}

#[async_trait::async_trait]
pub trait UserRoleBindingRepository: Send + Sync {
    async fn find_binding(
        &self,
        oid: UserRoleBindingOid,
    ) -> Result<Option<UserRoleBinding>, RbacRepositoryError>;

    async fn list_active_bindings_for_user(
        &self,
        user: UserOid,
    ) -> Result<Vec<UserRoleBinding>, RbacRepositoryError>;

    async fn insert_binding(&self, binding: &UserRoleBinding) -> Result<(), RbacRepositoryError>;

    async fn revoke_binding(
        &self,
        binding: UserRoleBindingOid,
        expected_version: AuthorizationVersion,
    ) -> Result<UserRoleBinding, RbacRepositoryError>;
}

#[async_trait::async_trait]
pub trait EffectivePermissionRepository: Send + Sync {
    async fn effective_permissions(
        &self,
        user: UserOid,
        resource: ResourceOid,
        expected_user_authorization_version: AuthorizationVersion,
    ) -> Result<Vec<EffectivePermission>, RbacRepositoryError>;
}

#[async_trait::async_trait]
pub trait AuthorizationVersionRepository: Send + Sync {
    async fn current_user_version(
        &self,
        user: UserOid,
    ) -> Result<AuthorizationVersion, RbacRepositoryError>;

    /// Rotate the core user version in the same transaction as the binding or
    /// role change. Versions are fresh UUIDs and are never reused.
    async fn renew_user_version(
        &self,
        user: UserOid,
    ) -> Result<AuthorizationVersion, RbacRepositoryError>;

    async fn current_role_version(
        &self,
        role: RoleOid,
    ) -> Result<AuthorizationVersion, RbacRepositoryError>;

    async fn renew_role_version(
        &self,
        role: RoleOid,
    ) -> Result<AuthorizationVersion, RbacRepositoryError>;
}
