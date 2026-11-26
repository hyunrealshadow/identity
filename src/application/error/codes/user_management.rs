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
    /// Only a disabled user may be deleted.
    UserNotDisabled = 16021,
    /// Second factors are cleared only from an account that still has a
    /// password to sign in with.
    UserHasNoPassword = 16022,
    /// The session does not belong to the user.
    SessionNotFound = 16023,
    /// Operators manage their own sign-in methods in the account center.
    SelfCredentialActionNotAllowed = 16024,
    /// An invitation needs email delivery to be configured.
    InvitationUnavailable = 16025,
    /// The user has no outstanding invitation, or has already accepted it.
    InvitationNotPending = 16026,
    /// Another invitation email was sent before the resend interval passed.
    InvitationResendTooSoon = 16027,
    /// The invitation email could not be sent.
    InvitationDeliveryFailed = 16028,
    /// A new user needs either an initial password or an invitation.
    CredentialChoiceRequired = 16029,
    /// Disabled users must be enabled before sending an invitation.
    InvitationUserDisabled = 16030,
}

impl AppErrorCode for UserManagementErrorCode {
    fn required_params(self) -> &'static [&'static str] {
        match self {
            Self::VersionConflict => &["current_version"],
            Self::ReasonTooLong | Self::PageSizeInvalid | Self::InvalidClientMutationId => &["max"],
            Self::InvalidFilter => &["field"],
            Self::InvitationResendTooSoon => &["seconds"],
            _ => &[],
        }
    }

    fn kind(self) -> ErrorKind {
        match self {
            Self::VersionConflict
            | Self::UserNotDisabled
            | Self::UserHasNoPassword
            | Self::SelfCredentialActionNotAllowed
            | Self::InvitationNotPending
            | Self::InvitationUserDisabled => ErrorKind::Conflict,
            Self::InvitationUnavailable => ErrorKind::Forbidden,
            Self::InvitationResendTooSoon => ErrorKind::RateLimit,
            Self::InvitationDeliveryFailed => ErrorKind::Internal,
            Self::SessionNotFound => ErrorKind::NotFound,
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
            | Self::InvalidClientMutationId
            | Self::CredentialChoiceRequired => ErrorKind::Validation,
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
            Self::UserNotDisabled => 16021,
            Self::UserHasNoPassword => 16022,
            Self::SessionNotFound => 16023,
            Self::SelfCredentialActionNotAllowed => 16024,
            Self::InvitationUnavailable => 16025,
            Self::InvitationNotPending => 16026,
            Self::InvitationResendTooSoon => 16027,
            Self::InvitationDeliveryFailed => 16028,
            Self::CredentialChoiceRequired => 16029,
            Self::InvitationUserDisabled => 16030,
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
    entry(
        UserManagementErrorCode::UserNotDisabled,
        ErrorKind::Conflict,
        "E16021",
        &[],
        &[],
        "user.management",
    ),
    entry(
        UserManagementErrorCode::UserHasNoPassword,
        ErrorKind::Conflict,
        "E16022",
        &[],
        &[],
        "user.management",
    ),
    entry(
        UserManagementErrorCode::SessionNotFound,
        ErrorKind::NotFound,
        "E16023",
        &[],
        &[],
        "user.management",
    ),
    entry(
        UserManagementErrorCode::SelfCredentialActionNotAllowed,
        ErrorKind::Conflict,
        "E16024",
        &[],
        &[],
        "user.management",
    ),
    entry(
        UserManagementErrorCode::InvitationUnavailable,
        ErrorKind::Forbidden,
        "E16025",
        &[],
        &[],
        "user.management",
    ),
    entry(
        UserManagementErrorCode::InvitationNotPending,
        ErrorKind::Conflict,
        "E16026",
        &[],
        &[],
        "user.management",
    ),
    entry(
        UserManagementErrorCode::InvitationResendTooSoon,
        ErrorKind::RateLimit,
        "E16027",
        &["seconds"],
        &[],
        "user.management",
    ),
    entry(
        UserManagementErrorCode::InvitationDeliveryFailed,
        ErrorKind::Internal,
        "E16028",
        &[],
        &[],
        "user.management",
    ),
    entry(
        UserManagementErrorCode::CredentialChoiceRequired,
        ErrorKind::Validation,
        "E16029",
        &[],
        &[],
        "user.management",
    ),
    entry(
        UserManagementErrorCode::InvitationUserDisabled,
        ErrorKind::Conflict,
        "E16030",
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
