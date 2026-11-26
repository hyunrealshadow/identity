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
    GrantNotFound = 27011,
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

            Self::LastOwnerProtected | Self::DuplicatePermissionCode | Self::VersionConflict => {
                ErrorKind::Conflict
            }

            Self::GrantNotFound => ErrorKind::NotFound,

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
        self as u32
    }

    fn required_params(self) -> &'static [&'static str] {
        match self {
            Self::InsufficientScope => &["required_scope"],
            Self::ReservedManagementScope
            | Self::InvalidManagementScope
            | Self::BusinessScopeBoundaryViolation
            | Self::HumanOnlyManagementCapability => &["scope"],
            Self::MissingHumanAuthentication => &["required_authentication"],
            Self::VersionConflict => &["current_version"],
            _ => &[],
        }
    }

    fn optional_params(self) -> &'static [&'static str] {
        match self {
            Self::InvalidPrincipal | Self::MissingPrincipal => &["principal_kind"],
            Self::ForbiddenManagementAuthority => &["required_scope"],
            Self::TargetForbidden | Self::InvalidTarget => &["target_type"],
            Self::DuplicatePermissionCode => &["permission"],
            Self::BusinessScopeBoundaryViolation => &["reason_code"],
            Self::InvalidPermissionDefinition | Self::InvalidRoleDefinition => &["field"],
            _ => &[],
        }
    }

    fn usage_module(self) -> Option<&'static str> {
        Some(match self {
            Self::InvalidPrincipal
            | Self::ForbiddenManagementAuthority
            | Self::TargetForbidden
            | Self::InvalidTarget
            | Self::MissingHumanAuthentication
            | Self::HumanOnlyManagementCapability
            | Self::MachineAssuranceNotAllowed => "authorization.policy",
            Self::MissingPrincipal | Self::InsufficientScope => "authorization.guards",
            Self::AuthorizationVersionStale
            | Self::AuthorizationSnapshotExpired
            | Self::GrantNotFound
            | Self::AuthorizationSnapshotOidMismatch => "authorization.snapshot",
            Self::LastOwnerProtected | Self::OwnerTargetProtected => "authorization.owner",
            Self::DuplicatePermissionCode => "rbac.repository",
            Self::ReservedManagementScope | Self::InvalidManagementScope => "authorization.catalog",
            Self::BusinessScopeBoundaryViolation => "rbac.boundary",
            Self::RbacPolicyUnavailable => "rbac.policy",
            Self::AuditWriteFailed => "authorization.audit",
            Self::InvalidPermissionDefinition | Self::InvalidRoleDefinition => "rbac.model",
            Self::VersionConflict => "administrator.repository",
        })
    }
}
