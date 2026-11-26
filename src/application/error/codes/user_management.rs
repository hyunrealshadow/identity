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

    fn optional_params(self) -> &'static [&'static str] {
        match self {
            Self::ValidationFailed | Self::InvalidDateRange => &["field"],
            Self::InvalidFilter => &["max"],
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
        self as u32
    }
}
