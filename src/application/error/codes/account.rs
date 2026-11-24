use crate::error::{code::AppErrorCode, kind::ErrorKind};

/// Range: 15000-15099
#[derive(Debug, Clone, Copy, PartialEq, Eq, strum::EnumIter)]
pub enum AccountErrorCode {
    ValidationFailed,
    UsernameRequired,
    UsernameInvalid,
    EmailRequired,
    EmailInvalid,
    UsernameExists,
    EmailExists,
    /// Email delivery is not configured, so no verification can be sent.
    EmailVerificationUnavailable,
    EmailVerificationResendTooSoon,
    EmailVerificationLimitReached,
    EmailAlreadyVerified,
    /// The link is unknown, expired, used, or voided by a later change.
    EmailVerificationInvalid,
    EmailVerificationDeliveryFailed,
}

impl AppErrorCode for AccountErrorCode {
    fn required_params(self) -> &'static [&'static str] {
        match self {
            Self::EmailVerificationResendTooSoon => &["seconds"],
            _ => &[],
        }
    }

    fn kind(self) -> ErrorKind {
        match self {
            Self::ValidationFailed
            | Self::UsernameRequired
            | Self::UsernameInvalid
            | Self::EmailRequired
            | Self::EmailInvalid => ErrorKind::Validation,
            Self::UsernameExists | Self::EmailExists | Self::EmailAlreadyVerified => {
                ErrorKind::Conflict
            }
            Self::EmailVerificationUnavailable => ErrorKind::Forbidden,
            Self::EmailVerificationResendTooSoon | Self::EmailVerificationLimitReached => {
                ErrorKind::RateLimit
            }
            Self::EmailVerificationInvalid => ErrorKind::Gone,
            Self::EmailVerificationDeliveryFailed => ErrorKind::Internal,
        }
    }

    fn code(self) -> u32 {
        match self {
            Self::ValidationFailed => 15000,
            Self::UsernameRequired => 15001,
            Self::UsernameInvalid => 15002,
            Self::EmailRequired => 15003,
            Self::EmailInvalid => 15004,
            Self::UsernameExists => 15005,
            Self::EmailExists => 15006,
            Self::EmailVerificationUnavailable => 15007,
            Self::EmailVerificationResendTooSoon => 15008,
            Self::EmailVerificationLimitReached => 15009,
            Self::EmailAlreadyVerified => 15010,
            Self::EmailVerificationInvalid => 15011,
            Self::EmailVerificationDeliveryFailed => 15012,
        }
    }
}
