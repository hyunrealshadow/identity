//! Authorization error catalog. Reserved range: 27000-27099.

use crate::error::{code::AppErrorCode, kind::ErrorKind};

#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, strum::EnumIter)]
pub enum AuthorizationErrorCode {
    InvalidPrincipal = 27000,
    MissingPrincipal = 27001,
    InsufficientScope = 27002,
    ForbiddenManagementAuthority = 27003,
    TargetForbidden = 27004,
    AuthorizationVersionStale = 27005,
    AuthorizationSnapshotExpired = 27006,
    LastOwnerProtected = 27007,
    OwnerTargetProtected = 27008,
    BindingNotFound = 27009,
    BindingAlreadyRevoked = 27010,
    GrantNotFound = 27011,
    GrantAlreadyRevoked = 27012,
    DuplicatePermissionCode = 27014,
    ReservedManagementScope = 27015,
    InvalidManagementScope = 27016,
    BusinessScopeBoundaryViolation = 27017,
    RbacPolicyUnavailable = 27018,
    AuditWriteFailed = 27019,
    InvalidTarget = 27020,
    MissingHumanAuthentication = 27021,
    HumanOnlyManagementCapability = 27022,
    MachineAssuranceNotAllowed = 27023,
    AuthorizationSnapshotOidMismatch = 27024,
    InvalidPermissionDefinition = 27026,
    InvalidRoleDefinition = 27027,
    VersionConflict = 27028,
}

impl AppErrorCode for AuthorizationErrorCode {
    fn kind(self) -> ErrorKind {
        match self {
            Self::InvalidPrincipal
            | Self::MissingPrincipal
            | Self::AuthorizationVersionStale
            | Self::AuthorizationSnapshotExpired
            | Self::MissingHumanAuthentication
            | Self::AuthorizationSnapshotOidMismatch => ErrorKind::Unauthorized,

            Self::InsufficientScope
            | Self::ForbiddenManagementAuthority
            | Self::TargetForbidden
            | Self::OwnerTargetProtected
            | Self::HumanOnlyManagementCapability
            | Self::MachineAssuranceNotAllowed => ErrorKind::Forbidden,

            Self::LastOwnerProtected
            | Self::BindingAlreadyRevoked
            | Self::GrantAlreadyRevoked
            | Self::DuplicatePermissionCode
            | Self::VersionConflict => ErrorKind::Conflict,

            Self::BindingNotFound | Self::GrantNotFound => ErrorKind::NotFound,

            Self::ReservedManagementScope
            | Self::InvalidManagementScope
            | Self::BusinessScopeBoundaryViolation
            | Self::InvalidTarget
            | Self::InvalidPermissionDefinition
            | Self::InvalidRoleDefinition => ErrorKind::Validation,

            Self::RbacPolicyUnavailable | Self::AuditWriteFailed => ErrorKind::Internal,
        }
    }

    fn code(self) -> u32 {
        match self {
            Self::InvalidPrincipal => 27000,
            Self::MissingPrincipal => 27001,
            Self::InsufficientScope => 27002,
            Self::ForbiddenManagementAuthority => 27003,
            Self::TargetForbidden => 27004,
            Self::AuthorizationVersionStale => 27005,
            Self::AuthorizationSnapshotExpired => 27006,
            Self::LastOwnerProtected => 27007,
            Self::OwnerTargetProtected => 27008,
            Self::BindingNotFound => 27009,
            Self::BindingAlreadyRevoked => 27010,
            Self::GrantNotFound => 27011,
            Self::GrantAlreadyRevoked => 27012,
            Self::DuplicatePermissionCode => 27014,
            Self::ReservedManagementScope => 27015,
            Self::InvalidManagementScope => 27016,
            Self::BusinessScopeBoundaryViolation => 27017,
            Self::RbacPolicyUnavailable => 27018,
            Self::AuditWriteFailed => 27019,
            Self::InvalidTarget => 27020,
            Self::MissingHumanAuthentication => 27021,
            Self::HumanOnlyManagementCapability => 27022,
            Self::MachineAssuranceNotAllowed => 27023,
            Self::AuthorizationSnapshotOidMismatch => 27024,
            Self::InvalidPermissionDefinition => 27026,
            Self::InvalidRoleDefinition => 27027,
            Self::VersionConflict => 27028,
        }
    }
}

/// Machine-readable catalog row. Fluent assets are not edited by the P0
/// foundation; integration adds `E<code>` entries with exactly these parameter
/// names in en-US and zh-CN.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AuthorizationErrorCodeDefinition {
    pub code: AuthorizationErrorCode,
    pub numeric_code: u32,
    pub kind: ErrorKind,
    pub fluent_key: &'static str,
    pub required_params: &'static [&'static str],
    pub optional_params: &'static [&'static str],
    pub usage_module: &'static str,
}

pub const AUTHORIZATION_ERROR_INVENTORY: &[AuthorizationErrorCodeDefinition] = &[
    entry(
        AuthorizationErrorCode::InvalidPrincipal,
        ErrorKind::Unauthorized,
        "E27000",
        &[],
        &["principal_kind"],
        "authorization.policy",
    ),
    entry(
        AuthorizationErrorCode::MissingPrincipal,
        ErrorKind::Unauthorized,
        "E27001",
        &[],
        &["principal_kind"],
        "authorization.guards",
    ),
    entry(
        AuthorizationErrorCode::InsufficientScope,
        ErrorKind::Forbidden,
        "E27002",
        &["required_scope"],
        &[],
        "authorization.guards",
    ),
    entry(
        AuthorizationErrorCode::ForbiddenManagementAuthority,
        ErrorKind::Forbidden,
        "E27003",
        &[],
        &["required_scope"],
        "authorization.policy",
    ),
    entry(
        AuthorizationErrorCode::TargetForbidden,
        ErrorKind::Forbidden,
        "E27004",
        &[],
        &["target_type"],
        "authorization.policy",
    ),
    entry(
        AuthorizationErrorCode::AuthorizationVersionStale,
        ErrorKind::Unauthorized,
        "E27005",
        &[],
        &[],
        "authorization.snapshot",
    ),
    entry(
        AuthorizationErrorCode::AuthorizationSnapshotExpired,
        ErrorKind::Unauthorized,
        "E27006",
        &[],
        &[],
        "authorization.snapshot",
    ),
    entry(
        AuthorizationErrorCode::LastOwnerProtected,
        ErrorKind::Conflict,
        "E27007",
        &[],
        &[],
        "authorization.owner",
    ),
    entry(
        AuthorizationErrorCode::OwnerTargetProtected,
        ErrorKind::Forbidden,
        "E27008",
        &[],
        &[],
        "authorization.owner",
    ),
    entry(
        AuthorizationErrorCode::BindingNotFound,
        ErrorKind::NotFound,
        "E27009",
        &[],
        &[],
        "administrator.repository",
    ),
    entry(
        AuthorizationErrorCode::BindingAlreadyRevoked,
        ErrorKind::Conflict,
        "E27010",
        &[],
        &[],
        "administrator.repository",
    ),
    entry(
        AuthorizationErrorCode::GrantNotFound,
        ErrorKind::NotFound,
        "E27011",
        &[],
        &[],
        "administrator.repository",
    ),
    entry(
        AuthorizationErrorCode::GrantAlreadyRevoked,
        ErrorKind::Conflict,
        "E27012",
        &[],
        &[],
        "administrator.repository",
    ),
    entry(
        AuthorizationErrorCode::DuplicatePermissionCode,
        ErrorKind::Conflict,
        "E27014",
        &[],
        &["permission"],
        "rbac.repository",
    ),
    entry(
        AuthorizationErrorCode::ReservedManagementScope,
        ErrorKind::Validation,
        "E27015",
        &["scope"],
        &[],
        "authorization.catalog",
    ),
    entry(
        AuthorizationErrorCode::InvalidManagementScope,
        ErrorKind::Validation,
        "E27016",
        &["scope"],
        &[],
        "authorization.catalog",
    ),
    entry(
        AuthorizationErrorCode::BusinessScopeBoundaryViolation,
        ErrorKind::Validation,
        "E27017",
        &["scope"],
        &["reason_code"],
        "rbac.boundary",
    ),
    entry(
        AuthorizationErrorCode::RbacPolicyUnavailable,
        ErrorKind::Internal,
        "E27018",
        &[],
        &[],
        "rbac.policy",
    ),
    entry(
        AuthorizationErrorCode::AuditWriteFailed,
        ErrorKind::Internal,
        "E27019",
        &[],
        &[],
        "authorization.audit",
    ),
    entry(
        AuthorizationErrorCode::InvalidTarget,
        ErrorKind::Validation,
        "E27020",
        &[],
        &["target_type"],
        "authorization.policy",
    ),
    entry(
        AuthorizationErrorCode::MissingHumanAuthentication,
        ErrorKind::Unauthorized,
        "E27021",
        &["required_authentication"],
        &[],
        "authorization.policy",
    ),
    entry(
        AuthorizationErrorCode::HumanOnlyManagementCapability,
        ErrorKind::Forbidden,
        "E27022",
        &["scope"],
        &[],
        "authorization.policy",
    ),
    entry(
        AuthorizationErrorCode::MachineAssuranceNotAllowed,
        ErrorKind::Forbidden,
        "E27023",
        &[],
        &[],
        "authorization.policy",
    ),
    entry(
        AuthorizationErrorCode::AuthorizationSnapshotOidMismatch,
        ErrorKind::Unauthorized,
        "E27024",
        &[],
        &[],
        "authorization.snapshot",
    ),
    entry(
        AuthorizationErrorCode::InvalidPermissionDefinition,
        ErrorKind::Validation,
        "E27026",
        &[],
        &["field"],
        "rbac.model",
    ),
    entry(
        AuthorizationErrorCode::InvalidRoleDefinition,
        ErrorKind::Validation,
        "E27027",
        &[],
        &["field"],
        "rbac.model",
    ),
    entry(
        AuthorizationErrorCode::VersionConflict,
        ErrorKind::Conflict,
        "E27028",
        &["current_version"],
        &[],
        "administrator.repository",
    ),
];

const fn entry(
    code: AuthorizationErrorCode,
    kind: ErrorKind,
    fluent_key: &'static str,
    required_params: &'static [&'static str],
    optional_params: &'static [&'static str],
    usage_module: &'static str,
) -> AuthorizationErrorCodeDefinition {
    AuthorizationErrorCodeDefinition {
        code,
        numeric_code: code as u32,
        kind,
        fluent_key,
        required_params,
        optional_params,
        usage_module,
    }
}

#[must_use]
pub fn inventory() -> &'static [AuthorizationErrorCodeDefinition] {
    AUTHORIZATION_ERROR_INVENTORY
}

#[must_use]
pub fn definition(
    code: AuthorizationErrorCode,
) -> Option<&'static AuthorizationErrorCodeDefinition> {
    AUTHORIZATION_ERROR_INVENTORY
        .iter()
        .find(|definition| definition.code == code)
}
