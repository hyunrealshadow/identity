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

/// Application AAL1 authentication assurance policy.
///
/// The authentication methods used to satisfy this policy are reported
/// separately through the OIDC `amr` claim.
pub const ACR_AAL1: &str = "urn:identity:acr:aal1";

/// Application AAL2 authentication assurance policy.
///
/// OIDC leaves ACR values deployment-specific. This private URI is advertised
/// through discovery. The methods currently satisfying it are password and TOTP.
pub const ACR_AAL2: &str = "urn:identity:acr:aal2";

// ─── AMR (Authentication Methods References) ────────────────────────────────

pub const AMR_PASSWORD: &str = "pwd";
pub const AMR_OTP: &str = "otp";
pub const AMR_MFA: &str = "mfa";
/// Private value because RFC 8176 does not register a recovery-code AMR.
pub const AMR_RECOVERY_CODE: &str = "urn:identity:amr:recovery-code";

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

/// Duration for which a password authentication may authorize sensitive
/// account operations without asking the user to authenticate again.
pub const RECENT_AUTHENTICATION_TTL: Duration = Duration::from_secs(5 * 60);

/// Duration for which AAL2 authentication remains valid within a session.
///
/// After this duration the session stays active but the `acr` field degrades
/// back to [`ACR_AAL1`] and the caller must perform step-up authentication to
/// regain AAL2.
pub const ELEVATED_AUTHENTICATION_TTL: Duration = Duration::from_secs(60 * 60); // 1 hour
