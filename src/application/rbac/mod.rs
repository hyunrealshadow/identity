//! Unified RBAC management.
//!
//! The public surface is re-exported here so GraphQL adapters can use
//! `identity_application::rbac::{...}` without depending on the internal file
//! layout. `Scope` is the single catalog; a business permission is its
//! resource-owned projection. Roles, groups and bindings stay separate from
//! instance management permissions.

pub mod client;
pub mod cursor;
pub mod group;
pub mod group_repository;
pub mod model;
pub mod repository;
pub mod resource;
pub mod role;
pub mod scope;
pub mod service;
pub mod service_group;
pub mod user_role;

pub use client::{
    ClientScopeAssignment, ClientScopePage, ClientScopePageItem, ClientScopePageRequest,
    ClientScopeSetResult, ClientScopeTargetFilter, ClientScopeTargetOrder, ClientScopeTargetPage,
    ClientScopeTargetPageItem, ClientScopeTargetPageRequest, ClientScopeTargetRecord,
    SetClientScopesCommand,
};
pub use group::{
    AddGroupMemberCommand, CreateGroupCommand, DeleteGroupCommand, DeleteGroupResult, GroupFilter,
    GroupMembershipFilter, GroupMembershipMutationResult, GroupMembershipOrder,
    GroupMembershipPage, GroupMembershipPageItem, GroupMembershipPageRequest,
    GroupMembershipRecord, GroupOrder, GroupPage, GroupPageItem, GroupPageRequest, GroupRecord,
    GroupRoleFilter, GroupRoleMutationResult, GroupRoleOrder, GroupRolePage, GroupRolePageItem,
    GroupRolePageRequest, GroupRoleRecord, GroupStateCommand, MAX_GROUP_MEMBERSHIPS,
    MAX_GROUP_ROLES, RemoveGroupMemberCommand, SetGroupRolesCommand, UpdateGroupCommand,
};
pub use group_repository::{
    AddGroupMemberTransaction, CreateGroupTransaction, DeleteGroupTransaction, GroupEntityKind,
    GroupManagementRepository, GroupManagementRepositoryError, GroupMembershipPageEntry,
    GroupMembershipQuery, GroupPageData, GroupPageEntry, GroupQuery, GroupRolePageEntry,
    GroupRoleQuery, GroupStateTransaction, RemoveGroupMemberTransaction, SetGroupRolesTransaction,
    SharedGroupManagementRepository, UpdateGroupTransaction,
};
pub use model::{RbacManagementAuthority, ScopeDescription, ScopeOid};
pub use repository::{
    AssignUserRolesTransaction, ClientScopePageEntry, ClientScopeQuery, ClientScopeTargetPageEntry,
    ClientScopeTargetQuery, CreateResourceTransaction, CreateRoleTransaction,
    CreateScopeTransaction, EffectivePermissionPageData, EffectivePermissionPageEntry,
    EffectivePermissionQuery, RbacDuplicateKind, RbacEntityKind, RbacManagementRepository,
    RbacManagementRepositoryError, RbacPageData, RbacProtectedKind, ResourcePageEntry,
    ResourceQuery, ResourceStateTransaction, RevokeUserRolesTransaction, RolePageEntry, RoleQuery,
    RoleStateTransaction, ScopePageEntry, ScopeQuery, ScopeStateTransaction,
    SetClientScopesTransaction, SetRolePermissionsTransaction, SharedRbacManagementRepository,
    UpdateResourceTransaction, UpdateRoleTransaction, UpdateScopeTransaction, UserRolePageData,
    UserRolePageEntry, UserRoleQuery,
};
pub use resource::{
    ApiResourceRecord, CreateResourceCommand, ResourceFilter, ResourceOrder, ResourcePage,
    ResourcePageItem, ResourcePageRequest, ResourceStateCommand, UpdateResourceCommand,
};
pub use role::{
    CreateRoleCommand, RoleFilter, RoleOrder, RolePage, RolePageItem, RolePageRequest, RoleRecord,
    RoleStateCommand, SetRolePermissionsCommand, UpdateRoleCommand,
};
pub use scope::{
    CreateScopeCommand, ScopeFilter, ScopeOrder, ScopePage, ScopePageItem, ScopePageRequest,
    ScopeRecord, ScopeStateCommand, UpdateScopeCommand,
};
pub use service::RbacManagementService;
pub use service_group::GroupManagementService;
pub use user_role::{
    AssignUserRolesCommand, EffectiveGroupPermissionSourceRecord, EffectivePermissionOrder,
    EffectivePermissionPage, EffectivePermissionPageItem, EffectivePermissionPageRequest,
    EffectivePermissionRecord, EffectivePermissionSourceRecord, RevokeUserRolesCommand,
    RoleUserPageRequest, UserRoleMutationResult, UserRoleOrder, UserRolePage, UserRolePageItem,
    UserRolePageRequest, UserRoleRecord,
};
