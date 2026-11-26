//! Mapping from authorization domain failures to stable `AppError` codes.
//!
//! Client-facing messages are rendered from Fluent assets in the infrastructure
//! i18n layer. This module only selects the stable code and safe parameters.

use identity_domain::{
    auth::AuthenticationContextClass,
    authorization::{
        catalog::{HumanAuthenticationRequirement, ManagementCatalogError, ManagementScopeError},
        owner::OwnerProtectionError,
        reason::GrantReasonError,
        repository::ManagementRepositoryError,
        snapshot::SnapshotValidationError,
    },
};

use crate::{
    authorization::policy::{DEFAULT_RECENT_AAL2_TTL, ManagementAuthorizationError},
    error::{AppError, StepUpChallenge, codes::authorization::error as AuthzError},
};

impl From<ManagementAuthorizationError> for AppError {
    fn from(error: ManagementAuthorizationError) -> Self {
        use ManagementAuthorizationError as Error;

        match error {
            Error::MissingPrincipal => AuthzError::MissingPrincipal::new().into(),
            Error::InsufficientScope { required } => {
                AuthzError::InsufficientScope::new(required.name()).into()
            }
            Error::NoCurrentGrant
            | Error::InconsistentAuthority
            | Error::PermissionNotAuthorized { .. } => {
                AuthzError::ForbiddenManagementAuthority::new().into()
            }
            Error::ClientScopeBoundaryMismatch => AuthzError::AuthorizationSnapshotExpired.into(),
            Error::HumanOnlyCapability { scope } => {
                AuthzError::HumanOnlyManagementCapability::new(scope.name()).into()
            }
            Error::SnapshotMissing => AuthzError::AuthorizationSnapshotExpired.into(),
            Error::SnapshotKindMismatch => AuthzError::AuthorizationSnapshotOidMismatch.into(),
            Error::SnapshotStale { .. } | Error::SnapshotVersionInvalid { .. } => {
                AuthzError::AuthorizationVersionStale.into()
            }
            Error::SnapshotOidMismatch => AuthzError::AuthorizationSnapshotOidMismatch.into(),
            Error::SnapshotPolicyMismatch | Error::SnapshotPermissionsMismatch => {
                AuthzError::AuthorizationSnapshotExpired.into()
            }
            Error::AuthenticationRequired { required } => {
                let err: AppError =
                    AuthzError::MissingHumanAuthentication::new(required.as_str()).into();
                if required.requires_aal2() {
                    err.with_step_up(StepUpChallenge {
                        acr: AuthenticationContextClass::MultiFactor,
                        max_age_secs: required
                            .requires_recent_aal2()
                            .then_some(DEFAULT_RECENT_AAL2_TTL.as_secs()),
                    })
                } else {
                    err
                }
            }
            Error::RecentAuthenticationRequired => {
                let err: AppError = AuthzError::MissingHumanAuthentication::new(
                    HumanAuthenticationRequirement::RecentAal2.as_str(),
                )
                .into();
                err.with_step_up(StepUpChallenge {
                    acr: AuthenticationContextClass::MultiFactor,
                    max_age_secs: Some(DEFAULT_RECENT_AAL2_TTL.as_secs()),
                })
            }
            Error::TargetForbidden => AuthzError::TargetForbidden::new().into(),
            Error::InvalidTarget => AuthzError::InvalidTarget::new().into(),
            Error::InvalidTokenScope { scope } => {
                AuthzError::InvalidManagementScope::new(scope).into()
            }
            Error::TokenScopeNotAuthorized => {
                AuthzError::InsufficientScope::new("management").into()
            }
        }
    }
}

impl From<OwnerProtectionError> for AppError {
    fn from(error: OwnerProtectionError) -> Self {
        match error {
            OwnerProtectionError::LastOwnerProtected => AuthzError::LastOwnerProtected.into(),
            OwnerProtectionError::OwnerTargetProtected => AuthzError::OwnerTargetProtected.into(),
        }
    }
}

impl From<ManagementScopeError> for AppError {
    fn from(error: ManagementScopeError) -> Self {
        match error {
            ManagementScopeError::ReservedPrefix => {
                AuthzError::ReservedManagementScope::new("management").into()
            }
            ManagementScopeError::Unknown => {
                AuthzError::InvalidManagementScope::new("management").into()
            }
        }
    }
}

impl From<ManagementCatalogError> for AppError {
    fn from(_: ManagementCatalogError) -> Self {
        AuthzError::RbacPolicyUnavailable.into()
    }
}

impl From<GrantReasonError> for AppError {
    fn from(_: GrantReasonError) -> Self {
        AuthzError::InvalidTarget::new()
            .target_type("grant_reason")
            .into()
    }
}

impl From<SnapshotValidationError> for AppError {
    fn from(error: SnapshotValidationError) -> Self {
        match error {
            SnapshotValidationError::GrantNotFound => AuthzError::GrantNotFound.into(),
            SnapshotValidationError::OidMismatch { .. } => {
                AuthzError::AuthorizationSnapshotOidMismatch.into()
            }
            SnapshotValidationError::VersionMismatch { .. } => {
                AuthzError::AuthorizationVersionStale.into()
            }
            SnapshotValidationError::PolicyVersionMismatch { .. }
            | SnapshotValidationError::PermissionsMismatch => {
                AuthzError::AuthorizationSnapshotExpired.into()
            }
        }
    }
}

impl From<ManagementRepositoryError> for AppError {
    fn from(error: ManagementRepositoryError) -> Self {
        match error {
            error @ ManagementRepositoryError::Storage(_) => {
                AuthzError::RbacPolicyUnavailable.with_source(error)
            }
            ManagementRepositoryError::CorruptRecord => AuthzError::RbacPolicyUnavailable.into(),
            ManagementRepositoryError::StaleSnapshot => {
                AuthzError::AuthorizationSnapshotExpired.into()
            }
            error @ ManagementRepositoryError::AuditFailed(_) => {
                AuthzError::AuditWriteFailed.with_source(error)
            }
        }
    }
}
