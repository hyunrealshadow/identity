use crate::error::{code::AppErrorCode, kind::ErrorKind};

/// Range: 11000-11099
#[derive(Debug, Clone, Copy, PartialEq, Eq, strum::EnumIter)]
pub enum AuthErrorCode {
    UserNotFound,
    InvalidCredential,
    UserLocked,
    UserDisabled,
    LoginExpired,
    InvalidLoginState,
    CredentialTypeUnsupported,
    InvalidOtp,
    TooManyAttempts,
    SessionNotFound,
    SessionExpired,
    SessionRevoked,
    IdentifierRequired,
    PasswordTooShort,
    PasswordUnchanged,
    TotpAlreadyEnabled,
    TotpNotEnabled,
    InvalidTotpEnrollment,
    /// Withdrawing device authorizations during an account level action failed.
    DeviceAuthorizationRevocationFailed,
    PasskeyLimitReached,
    InvalidMfaEnrollment,
    MfaNotEnabled,
    PasswordTooLong,
    PasswordTooWeak,
    PasswordTooSimilar,
    PasswordBreached,
    PasswordCheckUnavailable,
    /// A failed password while the interaction conceals whether the account
    /// exists: it does not say which of the two was wrong.
    InvalidAccountOrPassword,
    /// Another sign-in email was requested before the resend interval passed.
    EmailCodeResendTooSoon,
    /// The sign-in email could not be sent.
    EmailDeliveryFailed,
    /// The account cannot replace its password by email: password reset is
    /// off, email cannot be sent, or the account has no password or no
    /// verified email address.
    PasswordResetUnavailable,
    /// The password reset link is wrong, used, or expired.
    PasswordResetLinkInvalid,
    /// Another password reset email was requested before the resend interval
    /// passed.
    PasswordResetResendTooSoon,
    /// The password reset email could not be sent.
    PasswordResetDeliveryFailed,
    /// The new password repeats one of the account's recent passwords.
    PasswordReused,
}

impl AppErrorCode for AuthErrorCode {
    fn required_params(self) -> &'static [&'static str] {
        match self {
            Self::CredentialTypeUnsupported => &["credential_type"],
            Self::SessionNotFound => &["session_id"],
            Self::PasskeyLimitReached => &["limit"],
            Self::EmailCodeResendTooSoon | Self::PasswordResetResendTooSoon => &["seconds"],
            Self::PasswordReused => &["count"],
            _ => &[],
        }
    }

    fn kind(self) -> ErrorKind {
        match self {
            AuthErrorCode::UserNotFound | AuthErrorCode::SessionNotFound => ErrorKind::NotFound,
            AuthErrorCode::InvalidCredential
            | AuthErrorCode::InvalidAccountOrPassword
            | AuthErrorCode::InvalidOtp
            | AuthErrorCode::SessionExpired
            | AuthErrorCode::SessionRevoked => ErrorKind::Unauthorized,
            AuthErrorCode::UserLocked | AuthErrorCode::UserDisabled => ErrorKind::Forbidden,

            AuthErrorCode::LoginExpired => ErrorKind::Gone,
            AuthErrorCode::InvalidLoginState
            | AuthErrorCode::TotpAlreadyEnabled
            | AuthErrorCode::PasskeyLimitReached
            | AuthErrorCode::MfaNotEnabled
            | AuthErrorCode::TotpNotEnabled => ErrorKind::Conflict,
            AuthErrorCode::CredentialTypeUnsupported
            | AuthErrorCode::IdentifierRequired
            | AuthErrorCode::PasswordTooShort
            | AuthErrorCode::PasswordUnchanged
            | AuthErrorCode::PasswordTooLong
            | AuthErrorCode::PasswordTooWeak
            | AuthErrorCode::PasswordTooSimilar
            | AuthErrorCode::PasswordBreached
            | AuthErrorCode::InvalidTotpEnrollment
            | AuthErrorCode::InvalidMfaEnrollment
            | AuthErrorCode::PasswordResetUnavailable
            | AuthErrorCode::PasswordResetLinkInvalid
            | AuthErrorCode::PasswordReused => ErrorKind::Validation,

            AuthErrorCode::TooManyAttempts
            | AuthErrorCode::EmailCodeResendTooSoon
            | AuthErrorCode::PasswordResetResendTooSoon => ErrorKind::RateLimit,

            AuthErrorCode::DeviceAuthorizationRevocationFailed
            | AuthErrorCode::PasswordCheckUnavailable
            | AuthErrorCode::EmailDeliveryFailed
            | AuthErrorCode::PasswordResetDeliveryFailed => ErrorKind::Internal,
        }
    }

    fn code(self) -> u32 {
        match self {
            AuthErrorCode::UserNotFound => 11000,
            AuthErrorCode::InvalidCredential => 11001,
            AuthErrorCode::UserLocked => 11002,
            AuthErrorCode::UserDisabled => 11003,
            AuthErrorCode::LoginExpired => 11004,
            AuthErrorCode::InvalidLoginState => 11005,
            AuthErrorCode::CredentialTypeUnsupported => 11006,
            AuthErrorCode::InvalidOtp => 11007,
            AuthErrorCode::TooManyAttempts => 11008,
            AuthErrorCode::SessionNotFound => 11009,
            AuthErrorCode::SessionExpired => 11010,
            AuthErrorCode::SessionRevoked => 11011,
            AuthErrorCode::IdentifierRequired => 11012,
            AuthErrorCode::PasswordTooShort => 11013,
            AuthErrorCode::PasswordUnchanged => 11014,
            AuthErrorCode::TotpAlreadyEnabled => 11015,
            AuthErrorCode::TotpNotEnabled => 11016,
            AuthErrorCode::InvalidTotpEnrollment => 11017,
            AuthErrorCode::DeviceAuthorizationRevocationFailed => 11018,
            AuthErrorCode::PasskeyLimitReached => 11019,
            AuthErrorCode::InvalidMfaEnrollment => 11020,
            AuthErrorCode::MfaNotEnabled => 11021,
            AuthErrorCode::PasswordTooLong => 11022,
            AuthErrorCode::PasswordTooWeak => 11023,
            AuthErrorCode::PasswordTooSimilar => 11024,
            AuthErrorCode::PasswordBreached => 11025,
            AuthErrorCode::PasswordCheckUnavailable => 11026,
            AuthErrorCode::InvalidAccountOrPassword => 11027,
            AuthErrorCode::EmailCodeResendTooSoon => 11028,
            AuthErrorCode::EmailDeliveryFailed => 11029,
            AuthErrorCode::PasswordResetUnavailable => 11030,
            AuthErrorCode::PasswordResetLinkInvalid => 11031,
            AuthErrorCode::PasswordResetResendTooSoon => 11032,
            AuthErrorCode::PasswordResetDeliveryFailed => 11033,
            AuthErrorCode::PasswordReused => 11034,
        }
    }
}
