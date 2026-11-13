//! Trusted management capability catalog and runtime authorization.
//!
//! Human authority comes from the unified RBAC graph. This module applies
//! token/client ceilings, authentication requirements and live snapshots to
//! those permissions. Machines use explicit client grants; role/group names
//! never determine admission.

pub mod actor;
pub mod audit;
pub mod authority;
pub mod catalog;
pub mod ids;
pub mod owner;
pub mod reason;
pub mod recovery;
pub mod repository;
pub mod snapshot;

pub use actor::{
    ActorContext, ActorContextError, ActorPrincipal, AuthenticationAssurance,
    HumanAuthenticationContext, PrincipalKind, RequestId, TraceId,
};
pub use audit::{
    AuditSubject, AuditSubjectKind, AuthorizationAuditContext, AuthorizationAuditError,
    AuthorizationAuditJournal, AuthorizationAuditStorageError,
};
pub use authority::{
    ClientScopeAuthority, UserPermissionAuthority, full_management_permissions,
    is_trusted_management_permission, trusted_built_in_permission_oid,
};
pub use catalog::{
    HUMAN_ONLY_SCOPES, HumanAuthenticationRequirement, MANAGEMENT_SCOPE_COUNT,
    MANAGEMENT_SCOPE_PREFIX, MANAGEMENT_SCOPES, ManagementCatalogError, ManagementFlowAllowance,
    ManagementScope, ManagementScopeDefinition, ManagementScopeError, is_management_scope_name,
    is_reserved_management_name, m2m_allowed_scopes, policy_fingerprint, validate_catalog,
};
pub use ids::{AuthorizationVersion, PolicyVersion};
pub use owner::{
    OwnerLifecycleContext, OwnerProtectionError, OwnerTargetContext, ensure_owner_target_allowed,
    ensure_usable_owner_survives, owner_target_context,
};
pub use reason::{GrantReason, GrantReasonError, MAX_GRANT_REASON_LENGTH};
pub use recovery::{OwnerAccessSnapshot, OwnerRecoverabilityError, OwnerRecoverabilityPort};
pub use repository::{
    AuthorizationVersionChange, ManagementAuthorityRepository, ManagementRepositoryError,
    snapshot_identity,
};
pub use snapshot::{
    ManagementAuthorizationSnapshot, SnapshotValidationError, validate_user_permission_snapshot,
};
