use crate::error::{code::AppErrorCode, kind::ErrorKind};

/// Range: 11000-11099
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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
}

impl AppErrorCode for AuthErrorCode {
    fn kind(self) -> ErrorKind {
        match self {
            AuthErrorCode::UserNotFound | AuthErrorCode::SessionNotFound => ErrorKind::NotFound,
            AuthErrorCode::InvalidCredential
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
            | AuthErrorCode::InvalidMfaEnrollment => ErrorKind::Validation,

            AuthErrorCode::TooManyAttempts => ErrorKind::RateLimit,

            AuthErrorCode::DeviceAuthorizationRevocationFailed
            | AuthErrorCode::PasswordCheckUnavailable => ErrorKind::Internal,
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
        }
    }
}
