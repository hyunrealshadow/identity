//! User management error catalog. Reserved range: 16000-16099.
//!
//! These codes describe P2 instance-user management operations only. They are
//! deliberately separate from account self-service (15000), authentication
//! (11000) and management authorization (27000). Semantically identical
//! username and email failures reuse the account inventory (15001-15006); the
//! six former 16001-16006 slots remain reserved and are not reissued.
//! Semantically identical authorization failures reuse the 27000 inventory.

use crate::error::{code::AppErrorCode, kind::ErrorKind};

#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, strum::EnumIter)]
pub enum UserManagementErrorCode {
    ValidationFailed = 16000,
    UserNotFound = 16007,
    VersionConflict = 16008,
    InvalidVersion = 16009,
    ReasonTooLong = 16011,
    PageSizeInvalid = 16012,
    PageArgumentsConflict = 16013,
    InvalidFilter = 16014,
    InvalidDateRange = 16015,
    InvalidCursor = 16016,
    InvalidTheme = 16017,
    InvalidClientMutationId = 16018,
    StorageFailed = 16019,
    AccessInvalidationFailed = 16020,
}

impl AppErrorCode for UserManagementErrorCode {
    fn kind(self) -> ErrorKind {
        match self {
            Self::VersionConflict => ErrorKind::Conflict,
            Self::UserNotFound => ErrorKind::NotFound,
            Self::StorageFailed | Self::AccessInvalidationFailed => ErrorKind::Internal,
            Self::ValidationFailed
            | Self::InvalidVersion
            | Self::ReasonTooLong
            | Self::PageSizeInvalid
            | Self::PageArgumentsConflict
            | Self::InvalidFilter
            | Self::InvalidDateRange
            | Self::InvalidCursor
            | Self::InvalidTheme
            | Self::InvalidClientMutationId => ErrorKind::Validation,
        }
    }

    fn code(self) -> u32 {
        match self {
            Self::ValidationFailed => 16000,
            Self::UserNotFound => 16007,
            Self::VersionConflict => 16008,
            Self::InvalidVersion => 16009,
            Self::ReasonTooLong => 16011,
            Self::PageSizeInvalid => 16012,
            Self::PageArgumentsConflict => 16013,
            Self::InvalidFilter => 16014,
            Self::InvalidDateRange => 16015,
            Self::InvalidCursor => 16016,
            Self::InvalidTheme => 16017,
            Self::InvalidClientMutationId => 16018,
            Self::StorageFailed => 16019,
            Self::AccessInvalidationFailed => 16020,
        }
    }
}

/// Machine-readable inventory used by the infrastructure i18n catalog.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UserManagementErrorCodeDefinition {
    pub code: UserManagementErrorCode,
    pub numeric_code: u32,
    pub kind: ErrorKind,
    pub fluent_key: &'static str,
    pub required_params: &'static [&'static str],
    pub optional_params: &'static [&'static str],
    pub usage_module: &'static str,
}

pub const USER_MANAGEMENT_ERROR_INVENTORY: &[UserManagementErrorCodeDefinition] = &[
    entry(
        UserManagementErrorCode::ValidationFailed,
        ErrorKind::Validation,
        "E16000",
        &[],
        &["field"],
        "user.management",
    ),
    entry(
        UserManagementErrorCode::UserNotFound,
        ErrorKind::NotFound,
        "E16007",
        &[],
        &[],
        "user.management",
    ),
    entry(
        UserManagementErrorCode::VersionConflict,
        ErrorKind::Conflict,
        "E16008",
        &["current_version"],
        &[],
        "user.management",
    ),
    entry(
        UserManagementErrorCode::InvalidVersion,
        ErrorKind::Validation,
        "E16009",
        &[],
        &[],
        "user.management",
    ),
    entry(
        UserManagementErrorCode::ReasonTooLong,
        ErrorKind::Validation,
        "E16011",
        &["max"],
        &[],
        "user.management",
    ),
    entry(
        UserManagementErrorCode::PageSizeInvalid,
        ErrorKind::Validation,
        "E16012",
        &["max"],
        &[],
        "user.management",
    ),
    entry(
        UserManagementErrorCode::PageArgumentsConflict,
        ErrorKind::Validation,
        "E16013",
        &[],
        &[],
        "user.management",
    ),
    entry(
        UserManagementErrorCode::InvalidFilter,
        ErrorKind::Validation,
        "E16014",
        &["field"],
        &["max"],
        "user.management",
    ),
    entry(
        UserManagementErrorCode::InvalidDateRange,
        ErrorKind::Validation,
        "E16015",
        &[],
        &["field"],
        "user.management",
    ),
    entry(
        UserManagementErrorCode::InvalidCursor,
        ErrorKind::Validation,
        "E16016",
        &[],
        &[],
        "user.management",
    ),
    entry(
        UserManagementErrorCode::InvalidTheme,
        ErrorKind::Validation,
        "E16017",
        &[],
        &[],
        "user.management",
    ),
    entry(
        UserManagementErrorCode::InvalidClientMutationId,
        ErrorKind::Validation,
        "E16018",
        &["max"],
        &[],
        "user.management",
    ),
    entry(
        UserManagementErrorCode::StorageFailed,
        ErrorKind::Internal,
        "E16019",
        &[],
        &[],
        "user.management",
    ),
    entry(
        UserManagementErrorCode::AccessInvalidationFailed,
        ErrorKind::Internal,
        "E16020",
        &[],
        &[],
        "user.management",
    ),
];

const fn entry(
    code: UserManagementErrorCode,
    kind: ErrorKind,
    fluent_key: &'static str,
    required_params: &'static [&'static str],
    optional_params: &'static [&'static str],
    usage_module: &'static str,
) -> UserManagementErrorCodeDefinition {
    UserManagementErrorCodeDefinition {
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
pub fn inventory() -> &'static [UserManagementErrorCodeDefinition] {
    USER_MANAGEMENT_ERROR_INVENTORY
}

#[must_use]
pub fn definition(
    code: UserManagementErrorCode,
) -> Option<&'static UserManagementErrorCodeDefinition> {
    USER_MANAGEMENT_ERROR_INVENTORY
        .iter()
        .find(|definition| definition.code == code)
}
