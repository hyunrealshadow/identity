//! User-group management error catalog. Reserved range: 19000-19099.
//!
//! Cursor and page-argument failures keep using the shared business RBAC codes
//! (17037/17038/17039); every group-specific failure is defined here.

use crate::error::{code::AppErrorCode, kind::ErrorKind};

#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, strum::EnumIter)]
pub enum GroupErrorCode {
    ValidationFailed = 19000,
    GroupNotFound = 19001,
    MembershipNotFound = 19002,
    RoleBindingNotFound = 19003,
    VersionConflict = 19004,
    InvalidName = 19006,
    InvalidDescription = 19007,
    InvalidLocale = 19008,
    BuiltInProtected = 19010,
    Disabled = 19011,
    InvalidReason = 19012,
    InvalidVersion = 19013,
    InvalidClientMutationId = 19014,
    EmptyUpdate = 19015,
    InvalidCollectionSize = 19016,
    RoleNotFound = 19017,
    RoleDisabled = 19018,
    DelegationCeilingExceeded = 19019,
    MembershipAlreadyActive = 19020,
    MembershipNotActive = 19021,
    StorageFailed = 19022,
    InvalidFilter = 19025,
    UserNotFound = 19026,
    InvalidMetadata = 19027,
    DuplicateLocale = 19028,
    NameRequired = 19029,
}

impl GroupErrorCode {
    pub const fn kind(self) -> ErrorKind {
        match self {
            Self::GroupNotFound
            | Self::MembershipNotFound
            | Self::RoleBindingNotFound
            | Self::RoleNotFound
            | Self::UserNotFound => ErrorKind::NotFound,

            Self::VersionConflict
            | Self::Disabled
            | Self::RoleDisabled
            | Self::MembershipAlreadyActive
            | Self::MembershipNotActive => ErrorKind::Conflict,

            Self::BuiltInProtected | Self::DelegationCeilingExceeded => ErrorKind::Forbidden,

            Self::StorageFailed => ErrorKind::Internal,

            Self::ValidationFailed
            | Self::InvalidName
            | Self::InvalidDescription
            | Self::InvalidLocale
            | Self::InvalidReason
            | Self::InvalidVersion
            | Self::InvalidClientMutationId
            | Self::EmptyUpdate
            | Self::InvalidCollectionSize
            | Self::InvalidFilter
            | Self::InvalidMetadata
            | Self::DuplicateLocale
            | Self::NameRequired => ErrorKind::Validation,
        }
    }
}

impl AppErrorCode for GroupErrorCode {
    fn kind(self) -> ErrorKind {
        Self::kind(self)
    }

    fn code(self) -> u32 {
        match self {
            Self::ValidationFailed => 19000,
            Self::GroupNotFound => 19001,
            Self::MembershipNotFound => 19002,
            Self::RoleBindingNotFound => 19003,
            Self::VersionConflict => 19004,
            Self::InvalidName => 19006,
            Self::InvalidDescription => 19007,
            Self::InvalidLocale => 19008,
            Self::BuiltInProtected => 19010,
            Self::Disabled => 19011,
            Self::InvalidReason => 19012,
            Self::InvalidVersion => 19013,
            Self::InvalidClientMutationId => 19014,
            Self::EmptyUpdate => 19015,
            Self::InvalidCollectionSize => 19016,
            Self::RoleNotFound => 19017,
            Self::RoleDisabled => 19018,
            Self::DelegationCeilingExceeded => 19019,
            Self::MembershipAlreadyActive => 19020,
            Self::MembershipNotActive => 19021,
            Self::StorageFailed => 19022,
            Self::InvalidFilter => 19025,
            Self::UserNotFound => 19026,
            Self::InvalidMetadata => 19027,
            Self::DuplicateLocale => 19028,
            Self::NameRequired => 19029,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GroupErrorCodeDefinition {
    pub code: GroupErrorCode,
    pub numeric_code: u32,
    pub kind: ErrorKind,
    pub fluent_key: &'static str,
    pub required_params: &'static [&'static str],
    pub optional_params: &'static [&'static str],
    pub usage_module: &'static str,
}

pub const GROUP_ERROR_INVENTORY: &[GroupErrorCodeDefinition] = &[
    entry(
        GroupErrorCode::ValidationFailed,
        "E19000",
        &[],
        &["field"],
        "rbac.group",
    ),
    entry(
        GroupErrorCode::GroupNotFound,
        "E19001",
        &[],
        &[],
        "rbac.group",
    ),
    entry(
        GroupErrorCode::MembershipNotFound,
        "E19002",
        &[],
        &[],
        "rbac.group.membership",
    ),
    entry(
        GroupErrorCode::RoleBindingNotFound,
        "E19003",
        &[],
        &[],
        "rbac.group.roles",
    ),
    entry(
        GroupErrorCode::VersionConflict,
        "E19004",
        &["current_version"],
        &[],
        "rbac.group",
    ),
    entry(
        GroupErrorCode::InvalidName,
        "E19006",
        &[],
        &["max"],
        "rbac.group",
    ),
    entry(
        GroupErrorCode::InvalidDescription,
        "E19007",
        &[],
        &["max"],
        "rbac.group",
    ),
    entry(
        GroupErrorCode::InvalidLocale,
        "E19008",
        &[],
        &["max"],
        "rbac.group",
    ),
    entry(
        GroupErrorCode::BuiltInProtected,
        "E19010",
        &[],
        &["key"],
        "rbac.group",
    ),
    entry(
        GroupErrorCode::Disabled,
        "E19011",
        &[],
        &[],
        "rbac.group.membership",
    ),
    entry(
        GroupErrorCode::InvalidReason,
        "E19012",
        &["max"],
        &[],
        "rbac.group",
    ),
    entry(
        GroupErrorCode::InvalidVersion,
        "E19013",
        &[],
        &[],
        "rbac.group",
    ),
    entry(
        GroupErrorCode::InvalidClientMutationId,
        "E19014",
        &["max"],
        &[],
        "rbac.group",
    ),
    entry(
        GroupErrorCode::EmptyUpdate,
        "E19015",
        &[],
        &[],
        "rbac.group",
    ),
    entry(
        GroupErrorCode::InvalidCollectionSize,
        "E19016",
        &["max"],
        &[],
        "rbac.group",
    ),
    entry(
        GroupErrorCode::RoleNotFound,
        "E19017",
        &[],
        &[],
        "rbac.group.roles",
    ),
    entry(
        GroupErrorCode::RoleDisabled,
        "E19018",
        &[],
        &[],
        "rbac.group.roles",
    ),
    entry(
        GroupErrorCode::DelegationCeilingExceeded,
        "E19019",
        &["scope"],
        &[],
        "rbac.group.delegation",
    ),
    entry(
        GroupErrorCode::MembershipAlreadyActive,
        "E19020",
        &[],
        &[],
        "rbac.group.membership",
    ),
    entry(
        GroupErrorCode::MembershipNotActive,
        "E19021",
        &[],
        &[],
        "rbac.group.membership",
    ),
    entry(
        GroupErrorCode::StorageFailed,
        "E19022",
        &[],
        &[],
        "rbac.group",
    ),
    entry(
        GroupErrorCode::InvalidFilter,
        "E19025",
        &["field"],
        &["max"],
        "rbac.group",
    ),
    entry(
        GroupErrorCode::UserNotFound,
        "E19026",
        &[],
        &[],
        "rbac.group.membership",
    ),
    entry(
        GroupErrorCode::InvalidMetadata,
        "E19027",
        &["field"],
        &[],
        "rbac.group",
    ),
    entry(
        GroupErrorCode::DuplicateLocale,
        "E19028",
        &[],
        &["locale"],
        "rbac.group",
    ),
    entry(
        GroupErrorCode::NameRequired,
        "E19029",
        &[],
        &[],
        "rbac.group",
    ),
];

const fn entry(
    code: GroupErrorCode,
    fluent_key: &'static str,
    required_params: &'static [&'static str],
    optional_params: &'static [&'static str],
    usage_module: &'static str,
) -> GroupErrorCodeDefinition {
    GroupErrorCodeDefinition {
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
pub fn inventory() -> &'static [GroupErrorCodeDefinition] {
    GROUP_ERROR_INVENTORY
}

#[must_use]
pub fn definition(code: GroupErrorCode) -> Option<&'static GroupErrorCodeDefinition> {
    GROUP_ERROR_INVENTORY
        .iter()
        .find(|definition| definition.code == code)
}
