//! Business RBAC management error catalog. Reserved range: 17000-17099.
//!
//! These codes describe resource, scope, permission, role, user-role binding
//! and narrow client-delegation management. Semantically identical management
//! scope boundary failures continue to use the existing 27015/27017 codes and
//! transactional audit failures use 27019.

use crate::error::{code::AppErrorCode, kind::ErrorKind};

#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, strum::EnumIter)]
pub enum RbacErrorCode {
    ValidationFailed = 17000,
    ResourceNotFound = 17001,
    ScopeNotFound = 17002,
    PermissionNotFound = 17003,
    RoleNotFound = 17004,
    BindingNotFound = 17005,
    UserNotFound = 17006,
    ClientNotFound = 17007,
    VersionConflict = 17008,
    UserVersionStale = 17009,
    PolicyVersionStale = 17010,
    DuplicateResourceUri = 17011,
    DuplicateScopeCode = 17012,
    DuplicatePermissionCode = 17013,
    DuplicatePermissionScope = 17014,
    ReservedResourceProtected = 17016,
    BuiltInScopeProtected = 17017,
    ScopeNotAcceptedByResource = 17018,
    ScopeReferencedByPermission = 17019,
    PolicyDowngradeBlocked = 17020,
    IncompleteScopeMapping = 17021,
    ClientProtected = 17022,
    ClientScopeNotBusiness = 17023,
    RolePermissionLimitExceeded = 17024,
    UserRoleLimitExceeded = 17025,
    RoleNotAssigned = 17026,
    RoleDisabled = 17027,
    StorageFailed = 17028,
    InvalidResourceUri = 17029,
    InvalidScopeName = 17030,
    InvalidScopeDescription = 17031,
    InvalidPermissionDescription = 17032,
    InvalidRoleName = 17033,
    InvalidReason = 17035,
    InvalidVersion = 17036,
    InvalidCursor = 17037,
    PageSizeInvalid = 17038,
    PageArgumentsConflict = 17039,
    InvalidFilter = 17040,
    InvalidClientMutationId = 17041,
    InvalidCollectionSize = 17042,
    EmptyUpdate = 17043,
    InvalidPermissionCode = 17045,
    InvalidDescriptionLocale = 17046,
    InvalidResourceName = 17047,
    InvalidLocalizedMetadata = 17048,
    BuiltInDefinitionProtected = 17049,
    DelegationCeilingExceeded = 17050,
    BuiltInIdentityConflict = 17051,
    InvalidBuiltInPermissionReference = 17052,
    ClientGrantNotAllowed = 17053,
}

impl AppErrorCode for RbacErrorCode {
    fn kind(self) -> ErrorKind {
        match self {
            Self::ResourceNotFound
            | Self::ScopeNotFound
            | Self::PermissionNotFound
            | Self::RoleNotFound
            | Self::BindingNotFound
            | Self::UserNotFound
            | Self::ClientNotFound => ErrorKind::NotFound,

            Self::VersionConflict
            | Self::UserVersionStale
            | Self::PolicyVersionStale
            | Self::DuplicateResourceUri
            | Self::DuplicateScopeCode
            | Self::DuplicatePermissionCode
            | Self::DuplicatePermissionScope
            | Self::ScopeReferencedByPermission
            | Self::PolicyDowngradeBlocked
            | Self::IncompleteScopeMapping
            | Self::RoleNotAssigned
            | Self::RoleDisabled => ErrorKind::Conflict,

            Self::ReservedResourceProtected
            | Self::BuiltInScopeProtected
            | Self::ClientProtected
            | Self::BuiltInDefinitionProtected
            | Self::DelegationCeilingExceeded => ErrorKind::Forbidden,

            Self::StorageFailed | Self::BuiltInIdentityConflict => ErrorKind::Internal,

            Self::ValidationFailed
            | Self::ScopeNotAcceptedByResource
            | Self::ClientScopeNotBusiness
            | Self::RolePermissionLimitExceeded
            | Self::UserRoleLimitExceeded
            | Self::InvalidResourceUri
            | Self::InvalidScopeName
            | Self::InvalidScopeDescription
            | Self::InvalidPermissionDescription
            | Self::InvalidRoleName
            | Self::InvalidReason
            | Self::InvalidVersion
            | Self::InvalidCursor
            | Self::PageSizeInvalid
            | Self::PageArgumentsConflict
            | Self::InvalidFilter
            | Self::InvalidClientMutationId
            | Self::InvalidCollectionSize
            | Self::EmptyUpdate
            | Self::InvalidPermissionCode
            | Self::InvalidDescriptionLocale
            | Self::InvalidResourceName
            | Self::InvalidLocalizedMetadata
            | Self::InvalidBuiltInPermissionReference
            | Self::ClientGrantNotAllowed => ErrorKind::Validation,
        }
    }

    fn code(self) -> u32 {
        self as u32
    }

    fn required_params(self) -> &'static [&'static str] {
        match self {
            Self::VersionConflict | Self::UserVersionStale | Self::PolicyVersionStale => {
                &["current_version"]
            }
            Self::ScopeNotAcceptedByResource
            | Self::ScopeReferencedByPermission
            | Self::ClientScopeNotBusiness
            | Self::ClientGrantNotAllowed => &["scope"],
            Self::IncompleteScopeMapping => &["missing_count"],
            Self::RolePermissionLimitExceeded
            | Self::UserRoleLimitExceeded
            | Self::PageSizeInvalid
            | Self::InvalidClientMutationId
            | Self::InvalidCollectionSize => &["max"],
            Self::InvalidFilter => &["field"],
            _ => &[],
        }
    }

    fn optional_params(self) -> &'static [&'static str] {
        match self {
            Self::ValidationFailed => &["field"],
            Self::DuplicateResourceUri | Self::InvalidResourceUri => &["uri"],
            Self::DuplicateScopeCode | Self::DuplicatePermissionCode => &["code"],
            Self::DuplicatePermissionScope => &["scope"],
            Self::ReservedResourceProtected
            | Self::ScopeNotAcceptedByResource
            | Self::PolicyDowngradeBlocked => &["resource"],
            Self::BuiltInScopeProtected | Self::InvalidScopeName => &["name"],
            Self::ClientProtected => &["client"],
            Self::RoleNotAssigned | Self::RoleDisabled => &["role_id"],
            Self::InvalidScopeDescription
            | Self::InvalidPermissionDescription
            | Self::InvalidRoleName
            | Self::InvalidFilter
            | Self::InvalidPermissionCode
            | Self::InvalidDescriptionLocale
            | Self::InvalidResourceName => &["max"],
            Self::InvalidReason => &["min", "max"],
            Self::InvalidLocalizedMetadata => &["field", "locale", "max"],
            Self::BuiltInDefinitionProtected => &["kind", "key"],
            Self::DelegationCeilingExceeded | Self::InvalidBuiltInPermissionReference => {
                &["permission"]
            }
            Self::BuiltInIdentityConflict => &["key"],
            _ => &[],
        }
    }

    fn usage_module(self) -> Option<&'static str> {
        match self {
            Self::ResourceNotFound
            | Self::DuplicateResourceUri
            | Self::ReservedResourceProtected
            | Self::ScopeReferencedByPermission
            | Self::PolicyDowngradeBlocked
            | Self::IncompleteScopeMapping
            | Self::InvalidResourceUri
            | Self::InvalidResourceName => Some("rbac.resource"),
            Self::ScopeNotFound
            | Self::DuplicateScopeCode
            | Self::BuiltInScopeProtected
            | Self::InvalidScopeName
            | Self::InvalidScopeDescription
            | Self::InvalidDescriptionLocale => Some("rbac.scope"),
            Self::PermissionNotFound
            | Self::DuplicatePermissionCode
            | Self::DuplicatePermissionScope
            | Self::ScopeNotAcceptedByResource
            | Self::InvalidPermissionDescription
            | Self::InvalidPermissionCode => Some("rbac.permission"),
            Self::RoleNotFound | Self::RolePermissionLimitExceeded | Self::InvalidRoleName => {
                Some("rbac.role")
            }
            Self::BindingNotFound
            | Self::UserNotFound
            | Self::UserVersionStale
            | Self::UserRoleLimitExceeded
            | Self::RoleNotAssigned
            | Self::RoleDisabled => Some("rbac.binding"),
            Self::ClientNotFound
            | Self::PolicyVersionStale
            | Self::ClientProtected
            | Self::ClientScopeNotBusiness
            | Self::ClientGrantNotAllowed => Some("rbac.client"),
            Self::InvalidLocalizedMetadata => Some("rbac.metadata"),
            Self::BuiltInDefinitionProtected
            | Self::BuiltInIdentityConflict
            | Self::InvalidBuiltInPermissionReference => Some("rbac.builtin"),
            Self::DelegationCeilingExceeded => Some("rbac.delegation"),
            Self::ValidationFailed
            | Self::VersionConflict
            | Self::StorageFailed
            | Self::InvalidReason
            | Self::InvalidVersion
            | Self::InvalidCursor
            | Self::PageSizeInvalid
            | Self::PageArgumentsConflict
            | Self::InvalidFilter
            | Self::InvalidClientMutationId
            | Self::InvalidCollectionSize
            | Self::EmptyUpdate => None,
        }
    }
}
