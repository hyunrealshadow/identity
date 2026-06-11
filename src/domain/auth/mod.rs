pub mod model;
pub use model::SessionOid;
pub mod password;
pub mod repository;
pub mod totp;

use std::time::Duration;

// ─── Login Status ────────────────────────────────────────────────────────────

/// Status values for the `login` table.
pub struct LoginStatus;

impl LoginStatus {
    pub const CREATED: &'static str = "created";
    pub const IDENTIFIER_VERIFIED: &'static str = "identifier_verified";
    /// Password verified; awaiting MFA (TOTP) challenge.
    pub const MFA_REQUIRED: &'static str = "mfa_required";
    pub const AUTHENTICATED: &'static str = "authenticated";
    pub const FAILED: &'static str = "failed";
}

// ─── Session Status ──────────────────────────────────────────────────────────

/// Status values for the `session` table.
pub struct SessionStatus;

impl SessionStatus {
    pub const ACTIVE: &'static str = "active";
    pub const EXPIRED: &'static str = "expired";
    pub const REVOKED: &'static str = "revoked";
}

// ─── ACR (Authentication Context Class Reference) ────────────────────────────

/// ACR value for password-only authentication.
///
/// SAML 2.0 Password class.
pub const ACR_PASSWORD: &str = "urn:oasis:names:tc:SAML:2.0:ac:classes:Password";

/// ACR value for password + TOTP (MFA) authentication.
///
/// SAML 2.0 PasswordProtectedTransport class — conventionally used for MFA.
pub const ACR_MFA: &str = "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport";

// ─── Policy Constants ────────────────────────────────────────────────────────

/// Maximum consecutive failed password attempts before locking.
pub const MAX_FAILED_ATTEMPTS: i32 = 5;

/// Maximum OTP attempts allowed per login flow before the flow is invalidated.
pub const MAX_OTP_ATTEMPTS: i32 = MAX_FAILED_ATTEMPTS;

/// Duration for which an account remains locked after exceeding the failure
/// threshold.
pub const LOCK_DURATION: Duration = Duration::from_secs(15 * 60);

/// Duration after which a login flow expires (from `created_at`).
pub const LOGIN_EXPIRY: Duration = Duration::from_secs(5 * 60);

/// Duration for which a session remains valid.
pub const SESSION_EXPIRY: Duration = Duration::from_secs(7 * 24 * 60 * 60);

/// Duration for which an MFA-elevated ACR remains valid within a session.
///
/// After this duration the session stays active but the `acr` field degrades
/// back to [`ACR_PASSWORD`] and the caller must re-challenge with TOTP to
/// regain the elevated level.
pub const ACR_EXPIRY: Duration = Duration::from_secs(60 * 60); // 1 hour

/// Name of the session cookie.
pub const SESSION_COOKIE_NAME: &str = "sessions";
