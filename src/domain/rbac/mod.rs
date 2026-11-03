//! Unified user/group/role/permission domain.
//!
//! Custom roles can reference trusted built-in management permissions and
//! external resource permissions. Definitions marked built-in are immutable.
//! Standard protocol and account self-service scopes are not role permissions;
//! external scope registration keeps its reserved-namespace boundary.

pub mod authorization;
pub mod boundary;
pub mod builtin;
pub mod group;
pub mod ids;
pub mod metadata;
pub mod model;
pub mod repository;
pub mod snapshot;

pub use authorization::{
    BusinessAuthorizationSnapshot, BusinessSnapshotError, RbacAuthorizationError,
    RbacAuthorizationRepository, RbacAuthorizationState, RbacResourceState,
    RoleAuthorizationSnapshot, effective_permissions, effective_scope_names,
    validate_business_snapshot,
};
pub use boundary::{
    ACCOUNT_SELF_SERVICE_SCOPES, BusinessScopeBoundaryError, STANDARD_OIDC_SCOPES,
    valid_scope_token, validate_business_scope_reference,
};
pub use builtin::{
    BUILT_IN_GROUP_PREFIX, BUILT_IN_PERMISSION_PREFIX, BUILT_IN_ROLE_PREFIX, built_in_group_oid,
    built_in_permission_oid, built_in_role_oid, deterministic_oid, is_built_in_permission_oid,
};
pub use group::{
    Group, GroupLifecycleError, GroupMembership, GroupRoleBinding, GroupValidationError,
    validate_group_descriptions, validate_group_metadata, validate_group_names, validate_locale,
    validate_reason as validate_group_reason,
};
pub use ids::{
    GroupMembershipOid, GroupOid, GroupRoleBindingOid, ResourceOid, ResourcePermissionOid, RoleOid,
    RolePermissionOid, UserRoleBindingOid,
};
pub use metadata::{
    LANGUAGES, LocalizedMetadata, LocalizedText, LocalizedTextError,
    MAX_LOCALIZED_DESCRIPTION_LENGTH, MAX_LOCALIZED_ENTRIES, MAX_LOCALIZED_NAME_LENGTH,
    canonicalize_locale, validate_locale as validate_metadata_locale,
};
pub use model::{
    EffectiveGroupSource, EffectivePermission, EffectivePermissionError, EffectivePermissionSource,
    EffectivePermissionSources, GroupRolePath, PermissionCode, RbacLifecycleError,
    RbacValidationError, ResourcePermission, Role, RolePermission, UserRoleBinding,
    project_effective_permissions, project_scope_names,
};
pub use repository::{
    AuthorizationVersionRepository, EffectivePermissionRepository, RbacRepositoryError,
    RoleRepository, UserRoleBindingRepository,
};
pub use snapshot::{
    BindingSnapshotError, UserAuthorizationSnapshot, UserRoleBindingSnapshot,
    validate_binding_snapshot,
};
