//! Instance administrator management error catalog. Reserved range: 18000-18019.
//!
//! These codes describe human administrator binding management only. They are
//! deliberately separate from business RBAC (17000), account self-service
//! (15000), user management (16000) and management authorization (27000).
//! Binding not-found/tombstone/version and owner protection, snapshot
//! staleness, human assurance and transactional audit failures reuse the existing
//! [`super::authorization::AuthorizationErrorCode`] inventory
//! (27009/27010/27028, 27007/27008, 27005/27006, 27021 and 27019).

use crate::error::{code::AppErrorCode, kind::ErrorKind};

#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, strum::EnumIter)]
pub enum AdministratorErrorCode {
    ValidationFailed = 18000,
    AlreadyAssigned = 18001,
    ReasonTooLong = 18003,
    PageSizeInvalid = 18004,
    PageArgumentsConflict = 18005,
    InvalidFilter = 18006,
    InvalidCursor = 18007,
    InvalidVersion = 18008,
    StorageFailed = 18009,
    UserNotFound = 18010,
    AccountInactive = 18011,
}

impl AdministratorErrorCode {
    pub const fn kind(self) -> ErrorKind {
        match self {
            Self::UserNotFound => ErrorKind::NotFound,

            Self::AlreadyAssigned => ErrorKind::Conflict,

            Self::AccountInactive => ErrorKind::Forbidden,

            Self::StorageFailed => ErrorKind::Internal,

            Self::ValidationFailed
            | Self::ReasonTooLong
            | Self::PageSizeInvalid
            | Self::PageArgumentsConflict
            | Self::InvalidFilter
            | Self::InvalidCursor
            | Self::InvalidVersion => ErrorKind::Validation,
        }
    }
}

impl AppErrorCode for AdministratorErrorCode {
    fn kind(self) -> ErrorKind {
        Self::kind(self)
    }

    fn code(self) -> u32 {
        match self {
            Self::ValidationFailed => 18000,
            Self::AlreadyAssigned => 18001,
            Self::ReasonTooLong => 18003,
            Self::PageSizeInvalid => 18004,
            Self::PageArgumentsConflict => 18005,
            Self::InvalidFilter => 18006,
            Self::InvalidCursor => 18007,
            Self::InvalidVersion => 18008,
            Self::StorageFailed => 18009,
            Self::UserNotFound => 18010,
            Self::AccountInactive => 18011,
        }
    }
}

/// Machine-readable catalog row. Fluent assets provide exactly these parameter
/// names in both en-US and zh-CN.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AdministratorErrorCodeDefinition {
    pub code: AdministratorErrorCode,
    pub numeric_code: u32,
    pub kind: ErrorKind,
    pub fluent_key: &'static str,
    pub required_params: &'static [&'static str],
    pub optional_params: &'static [&'static str],
    pub usage_module: &'static str,
}

pub const ADMINISTRATOR_ERROR_INVENTORY: &[AdministratorErrorCodeDefinition] = &[
    entry(
        AdministratorErrorCode::ValidationFailed,
        "E18000",
        &[],
        &[],
        "administrator.management",
    ),
    entry(
        AdministratorErrorCode::AlreadyAssigned,
        "E18001",
        &[],
        &[],
        "administrator.management",
    ),
    entry(
        AdministratorErrorCode::ReasonTooLong,
        "E18003",
        &["max"],
        &[],
        "administrator.management",
    ),
    entry(
        AdministratorErrorCode::PageSizeInvalid,
        "E18004",
        &["max"],
        &[],
        "administrator.management",
    ),
    entry(
        AdministratorErrorCode::PageArgumentsConflict,
        "E18005",
        &[],
        &[],
        "administrator.management",
    ),
    entry(
        AdministratorErrorCode::InvalidFilter,
        "E18006",
        &["field"],
        &["max"],
        "administrator.management",
    ),
    entry(
        AdministratorErrorCode::InvalidCursor,
        "E18007",
        &[],
        &[],
        "administrator.management",
    ),
    entry(
        AdministratorErrorCode::InvalidVersion,
        "E18008",
        &[],
        &[],
        "administrator.management",
    ),
    entry(
        AdministratorErrorCode::StorageFailed,
        "E18009",
        &[],
        &[],
        "administrator.management",
    ),
    entry(
        AdministratorErrorCode::UserNotFound,
        "E18010",
        &[],
        &[],
        "administrator.management",
    ),
    entry(
        AdministratorErrorCode::AccountInactive,
        "E18011",
        &[],
        &[],
        "administrator.management",
    ),
];

const fn entry(
    code: AdministratorErrorCode,
    fluent_key: &'static str,
    required_params: &'static [&'static str],
    optional_params: &'static [&'static str],
    usage_module: &'static str,
) -> AdministratorErrorCodeDefinition {
    AdministratorErrorCodeDefinition {
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
pub fn inventory() -> &'static [AdministratorErrorCodeDefinition] {
    ADMINISTRATOR_ERROR_INVENTORY
}

#[must_use]
pub fn definition(
    code: AdministratorErrorCode,
) -> Option<&'static AdministratorErrorCodeDefinition> {
    ADMINISTRATOR_ERROR_INVENTORY
        .iter()
        .find(|definition| definition.code == code)
}

#[cfg(test)]
mod tests {

    use super::AdministratorErrorCode;
    use crate::error::kind::ErrorKind;

    #[test]
    fn administrator_kinds_are_sane() {
        assert_eq!(
            AdministratorErrorCode::AccountInactive.kind(),
            ErrorKind::Forbidden
        );
        assert_eq!(
            AdministratorErrorCode::AlreadyAssigned.kind(),
            ErrorKind::Conflict
        );
        assert_eq!(
            AdministratorErrorCode::StorageFailed.kind(),
            ErrorKind::Internal
        );
    }
}
