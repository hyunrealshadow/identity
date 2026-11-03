//! Mapping from authorization domain failures to stable `AppError` codes.
//!
//! Client-facing messages are rendered from Fluent assets in the infrastructure
//! i18n layer. This module only selects the stable code and safe parameters.

use identity_domain::authorization::{
    administrator::GrantReasonError,
    catalog::{HumanAuthenticationRequirement, ManagementCatalogError, ManagementScopeError},
    owner::OwnerProtectionError,
    repository::ManagementRepositoryError,
    snapshot::SnapshotValidationError,
};

use crate::{
    authorization::policy::ManagementAuthorizationError,
    error::{AppError, codes::authorization::AuthorizationErrorCode},
};

impl From<ManagementAuthorizationError> for AppError {
    fn from(error: ManagementAuthorizationError) -> Self {
        use AuthorizationErrorCode as Code;
        use ManagementAuthorizationError as Error;

        match error {
            Error::MissingPrincipal => AppError::from_code(Code::MissingPrincipal),
            Error::InsufficientScope { required } => AppError::from_code(Code::InsufficientScope)
                .with_param("required_scope", required.name()),
            Error::NoCurrentGrant
            | Error::RoleNotAuthorized { .. }
            | Error::InconsistentAuthority => {
                AppError::from_code(Code::ForbiddenManagementAuthority)
            }
            Error::ClientScopeBoundaryMismatch => {
                AppError::from_code(Code::AuthorizationSnapshotExpired)
            }
            Error::HumanOnlyCapability { scope } => {
                AppError::from_code(Code::HumanOnlyManagementCapability)
                    .with_param("scope", scope.name())
            }
            Error::PermissionNotAuthorized { permission } => {
                AppError::from_code(Code::ForbiddenManagementAuthority)
                    .with_param("permission", permission.name())
            }
            Error::GrantTombstoned | Error::SnapshotExpired => {
                AppError::from_code(Code::AuthorizationSnapshotExpired)
            }
            Error::SnapshotMissing => AppError::from_code(Code::AuthorizationSnapshotExpired),
            Error::SnapshotKindMismatch => {
                AppError::from_code(Code::AuthorizationSnapshotOidMismatch)
            }
            Error::SnapshotStale { .. } | Error::SnapshotVersionInvalid { .. } => {
                AppError::from_code(Code::AuthorizationVersionStale)
            }
            Error::SnapshotOidMismatch => {
                AppError::from_code(Code::AuthorizationSnapshotOidMismatch)
            }
            Error::SnapshotPolicyMismatch
            | Error::SnapshotRoleMismatch
            | Error::SnapshotPermissionsMismatch => {
                AppError::from_code(Code::AuthorizationSnapshotExpired)
            }
            Error::AuthenticationRequired { required } => {
                AppError::from_code(Code::MissingHumanAuthentication)
                    .with_param("required_authentication", required.as_str())
            }
            Error::RecentAuthenticationRequired => {
                AppError::from_code(Code::MissingHumanAuthentication).with_param(
                    "required_authentication",
                    HumanAuthenticationRequirement::RecentAal2.as_str(),
                )
            }
            Error::TargetForbidden => AppError::from_code(Code::TargetForbidden),
            Error::InvalidTarget => AppError::from_code(Code::InvalidTarget),
            Error::InvalidTokenScope { scope } => {
                AppError::from_code(Code::InvalidManagementScope).with_param("scope", scope)
            }
            Error::TokenScopeNotAuthorized => AppError::from_code(Code::InsufficientScope)
                .with_param("required_scope", "management"),
        }
    }
}

impl From<OwnerProtectionError> for AppError {
    fn from(error: OwnerProtectionError) -> Self {
        match error {
            OwnerProtectionError::LastOwnerProtected => {
                AppError::from_code(AuthorizationErrorCode::LastOwnerProtected)
            }
            OwnerProtectionError::OwnerTargetProtected => {
                AppError::from_code(AuthorizationErrorCode::OwnerTargetProtected)
            }
        }
    }
}

impl From<ManagementScopeError> for AppError {
    fn from(error: ManagementScopeError) -> Self {
        match error {
            ManagementScopeError::ReservedPrefix => {
                AppError::from_code(AuthorizationErrorCode::ReservedManagementScope)
                    .with_param("scope", "management")
            }
            ManagementScopeError::Unknown => {
                AppError::from_code(AuthorizationErrorCode::InvalidManagementScope)
                    .with_param("scope", "management")
            }
        }
    }
}

impl From<ManagementCatalogError> for AppError {
    fn from(_: ManagementCatalogError) -> Self {
        AppError::from_code(AuthorizationErrorCode::RbacPolicyUnavailable)
    }
}

impl From<GrantReasonError> for AppError {
    fn from(_: GrantReasonError) -> Self {
        AppError::from_code(AuthorizationErrorCode::InvalidTarget)
            .with_param("target_type", "grant_reason")
    }
}

impl From<SnapshotValidationError> for AppError {
    fn from(error: SnapshotValidationError) -> Self {
        match error {
            SnapshotValidationError::GrantNotFound => {
                AppError::from_code(AuthorizationErrorCode::GrantNotFound)
            }
            SnapshotValidationError::GrantKindMismatch
            | SnapshotValidationError::OidMismatch { .. } => {
                AppError::from_code(AuthorizationErrorCode::AuthorizationSnapshotOidMismatch)
            }
            SnapshotValidationError::RetiredGrantKind | SnapshotValidationError::Tombstoned => {
                AppError::from_code(AuthorizationErrorCode::AuthorizationSnapshotExpired)
            }
            SnapshotValidationError::VersionMismatch { .. } => {
                AppError::from_code(AuthorizationErrorCode::AuthorizationVersionStale)
            }
            SnapshotValidationError::PolicyVersionMismatch { .. }
            | SnapshotValidationError::RoleMismatch
            | SnapshotValidationError::PermissionsMismatch => {
                AppError::from_code(AuthorizationErrorCode::AuthorizationSnapshotExpired)
            }
        }
    }
}

impl From<ManagementRepositoryError> for AppError {
    fn from(error: ManagementRepositoryError) -> Self {
        match error {
            error @ ManagementRepositoryError::Storage(_) => {
                AppError::from_code(AuthorizationErrorCode::RbacPolicyUnavailable)
                    .with_source(error)
            }
            ManagementRepositoryError::CorruptRecord => {
                AppError::from_code(AuthorizationErrorCode::RbacPolicyUnavailable)
            }
            ManagementRepositoryError::StaleSnapshot => {
                AppError::from_code(AuthorizationErrorCode::AuthorizationSnapshotExpired)
            }
            error @ ManagementRepositoryError::AuditFailed(_) => {
                AppError::from_code(AuthorizationErrorCode::AuditWriteFailed).with_source(error)
            }
        }
    }
}
