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

impl RbacErrorCode {
    pub const fn kind(self) -> ErrorKind {
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
}

impl AppErrorCode for RbacErrorCode {
    fn kind(self) -> ErrorKind {
        Self::kind(self)
    }

    fn code(self) -> u32 {
        self as u32
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RbacErrorCodeDefinition {
    pub code: RbacErrorCode,
    pub numeric_code: u32,
    pub kind: ErrorKind,
    pub fluent_key: &'static str,
    pub required_params: &'static [&'static str],
    pub optional_params: &'static [&'static str],
    pub usage_module: &'static str,
}

pub const RBAC_ERROR_INVENTORY: &[RbacErrorCodeDefinition] = &[
    entry(
        RbacErrorCode::ValidationFailed,
        "E17000",
        &[],
        &["field"],
        "rbac",
    ),
    entry(
        RbacErrorCode::ResourceNotFound,
        "E17001",
        &[],
        &[],
        "rbac.resource",
    ),
    entry(
        RbacErrorCode::ScopeNotFound,
        "E17002",
        &[],
        &[],
        "rbac.scope",
    ),
    entry(
        RbacErrorCode::PermissionNotFound,
        "E17003",
        &[],
        &[],
        "rbac.permission",
    ),
    entry(RbacErrorCode::RoleNotFound, "E17004", &[], &[], "rbac.role"),
    entry(
        RbacErrorCode::BindingNotFound,
        "E17005",
        &[],
        &[],
        "rbac.binding",
    ),
    entry(
        RbacErrorCode::UserNotFound,
        "E17006",
        &[],
        &[],
        "rbac.binding",
    ),
    entry(
        RbacErrorCode::ClientNotFound,
        "E17007",
        &[],
        &[],
        "rbac.client",
    ),
    entry(
        RbacErrorCode::VersionConflict,
        "E17008",
        &["current_version"],
        &[],
        "rbac",
    ),
    entry(
        RbacErrorCode::UserVersionStale,
        "E17009",
        &["current_version"],
        &[],
        "rbac.binding",
    ),
    entry(
        RbacErrorCode::PolicyVersionStale,
        "E17010",
        &["current_version"],
        &[],
        "rbac.client",
    ),
    entry(
        RbacErrorCode::DuplicateResourceUri,
        "E17011",
        &[],
        &["uri"],
        "rbac.resource",
    ),
    entry(
        RbacErrorCode::DuplicateScopeCode,
        "E17012",
        &[],
        &["code"],
        "rbac.scope",
    ),
    entry(
        RbacErrorCode::DuplicatePermissionCode,
        "E17013",
        &[],
        &["code"],
        "rbac.permission",
    ),
    entry(
        RbacErrorCode::DuplicatePermissionScope,
        "E17014",
        &[],
        &["scope"],
        "rbac.permission",
    ),
    entry(
        RbacErrorCode::ReservedResourceProtected,
        "E17016",
        &[],
        &["resource"],
        "rbac.resource",
    ),
    entry(
        RbacErrorCode::BuiltInScopeProtected,
        "E17017",
        &[],
        &["name"],
        "rbac.scope",
    ),
    entry(
        RbacErrorCode::ScopeNotAcceptedByResource,
        "E17018",
        &["scope"],
        &["resource"],
        "rbac.permission",
    ),
    entry(
        RbacErrorCode::ScopeReferencedByPermission,
        "E17019",
        &["scope"],
        &[],
        "rbac.resource",
    ),
    entry(
        RbacErrorCode::PolicyDowngradeBlocked,
        "E17020",
        &[],
        &["resource"],
        "rbac.resource",
    ),
    entry(
        RbacErrorCode::IncompleteScopeMapping,
        "E17021",
        &["missing_count"],
        &[],
        "rbac.resource",
    ),
    entry(
        RbacErrorCode::ClientProtected,
        "E17022",
        &[],
        &["client"],
        "rbac.client",
    ),
    entry(
        RbacErrorCode::ClientScopeNotBusiness,
        "E17023",
        &["scope"],
        &[],
        "rbac.client",
    ),
    entry(
        RbacErrorCode::RolePermissionLimitExceeded,
        "E17024",
        &["max"],
        &[],
        "rbac.role",
    ),
    entry(
        RbacErrorCode::UserRoleLimitExceeded,
        "E17025",
        &["max"],
        &[],
        "rbac.binding",
    ),
    entry(
        RbacErrorCode::RoleNotAssigned,
        "E17026",
        &[],
        &["role_id"],
        "rbac.binding",
    ),
    entry(
        RbacErrorCode::RoleDisabled,
        "E17027",
        &[],
        &["role_id"],
        "rbac.binding",
    ),
    entry(RbacErrorCode::StorageFailed, "E17028", &[], &[], "rbac"),
    entry(
        RbacErrorCode::InvalidResourceUri,
        "E17029",
        &[],
        &["uri"],
        "rbac.resource",
    ),
    entry(
        RbacErrorCode::InvalidScopeName,
        "E17030",
        &[],
        &["name"],
        "rbac.scope",
    ),
    entry(
        RbacErrorCode::InvalidScopeDescription,
        "E17031",
        &[],
        &["max"],
        "rbac.scope",
    ),
    entry(
        RbacErrorCode::InvalidPermissionDescription,
        "E17032",
        &[],
        &["max"],
        "rbac.permission",
    ),
    entry(
        RbacErrorCode::InvalidRoleName,
        "E17033",
        &[],
        &["max"],
        "rbac.role",
    ),
    entry(
        RbacErrorCode::InvalidReason,
        "E17035",
        &[],
        &["min", "max"],
        "rbac",
    ),
    entry(RbacErrorCode::InvalidVersion, "E17036", &[], &[], "rbac"),
    entry(RbacErrorCode::InvalidCursor, "E17037", &[], &[], "rbac"),
    entry(
        RbacErrorCode::PageSizeInvalid,
        "E17038",
        &["max"],
        &[],
        "rbac",
    ),
    entry(
        RbacErrorCode::PageArgumentsConflict,
        "E17039",
        &[],
        &[],
        "rbac",
    ),
    entry(
        RbacErrorCode::InvalidFilter,
        "E17040",
        &["field"],
        &["max"],
        "rbac",
    ),
    entry(
        RbacErrorCode::InvalidClientMutationId,
        "E17041",
        &["max"],
        &[],
        "rbac",
    ),
    entry(
        RbacErrorCode::InvalidCollectionSize,
        "E17042",
        &["max"],
        &[],
        "rbac",
    ),
    entry(RbacErrorCode::EmptyUpdate, "E17043", &[], &[], "rbac"),
    entry(
        RbacErrorCode::InvalidPermissionCode,
        "E17045",
        &[],
        &["max"],
        "rbac.permission",
    ),
    entry(
        RbacErrorCode::InvalidDescriptionLocale,
        "E17046",
        &[],
        &["max"],
        "rbac.scope",
    ),
    entry(
        RbacErrorCode::InvalidResourceName,
        "E17047",
        &[],
        &["max"],
        "rbac.resource",
    ),
    entry(
        RbacErrorCode::InvalidLocalizedMetadata,
        "E17048",
        &[],
        &["field", "locale", "max"],
        "rbac.metadata",
    ),
    entry(
        RbacErrorCode::BuiltInDefinitionProtected,
        "E17049",
        &[],
        &["kind", "key"],
        "rbac.builtin",
    ),
    entry(
        RbacErrorCode::DelegationCeilingExceeded,
        "E17050",
        &[],
        &["permission"],
        "rbac.delegation",
    ),
    entry(
        RbacErrorCode::BuiltInIdentityConflict,
        "E17051",
        &[],
        &["key"],
        "rbac.builtin",
    ),
    entry(
        RbacErrorCode::InvalidBuiltInPermissionReference,
        "E17052",
        &[],
        &["permission"],
        "rbac.builtin",
    ),
    entry(
        RbacErrorCode::ClientGrantNotAllowed,
        "E17053",
        &["scope"],
        &[],
        "rbac.client",
    ),
];

const fn entry(
    code: RbacErrorCode,
    fluent_key: &'static str,
    required_params: &'static [&'static str],
    optional_params: &'static [&'static str],
    usage_module: &'static str,
) -> RbacErrorCodeDefinition {
    RbacErrorCodeDefinition {
        code,
        numeric_code: code as u32,
        kind: code.kind(),
        fluent_key,
        required_params,
        optional_params,
        usage_module,
    }
}

#[must_use]
pub fn inventory() -> &'static [RbacErrorCodeDefinition] {
    RBAC_ERROR_INVENTORY
}

#[must_use]
pub fn definition(code: RbacErrorCode) -> Option<&'static RbacErrorCodeDefinition> {
    RBAC_ERROR_INVENTORY
        .iter()
        .find(|definition| definition.code == code)
}
