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

    #[must_use]
    pub fn can_transition(current: &str, next: &str) -> bool {
        current == next
            || matches!(
                (current, next),
                (Self::CREATED, Self::FAILED)
                    | (
                        Self::IDENTIFIER_VERIFIED,
                        Self::MFA_REQUIRED | Self::AUTHENTICATED | Self::FAILED
                    )
                    | (Self::MFA_REQUIRED, Self::AUTHENTICATED | Self::FAILED)
            )
    }
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

/// Returns whether an established authentication context meets a requested
/// assurance level. Higher assurance satisfies lower-assurance requirements;
/// deployment-specific values remain exact matches.
#[must_use]
pub fn acr_satisfies(established: &str, requested: &str) -> bool {
    established == requested || (established == ACR_AAL2 && requested == ACR_AAL1)
}

/// Returns whether an authentication timestamp is not in the future and is
/// within the permitted age.
#[must_use]
pub fn authentication_is_fresh(auth_time: i64, now: i64, max_age_seconds: u64) -> bool {
    now.checked_sub(auth_time)
        .is_some_and(|age| age >= 0 && age <= max_age_seconds.min(i64::MAX as u64) as i64)
}

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

#[cfg(test)]
mod tests {
    use super::{ACR_AAL1, ACR_AAL2, LoginStatus, acr_satisfies, authentication_is_fresh};

    #[test]
    fn aal2_satisfies_aal1_and_aal2() {
        assert!(acr_satisfies(ACR_AAL2, ACR_AAL1));
        assert!(acr_satisfies(ACR_AAL2, ACR_AAL2));
    }

    #[test]
    fn aal1_does_not_satisfy_aal2() {
        assert!(!acr_satisfies(ACR_AAL1, ACR_AAL2));
    }

    #[test]
    fn custom_acr_values_require_an_exact_match() {
        assert!(acr_satisfies("custom", "custom"));
        assert!(!acr_satisfies(ACR_AAL2, "custom"));
    }

    #[test]
    fn freshness_rejects_future_and_old_authentication_times() {
        assert!(authentication_is_fresh(95, 100, 5));
        assert!(!authentication_is_fresh(94, 100, 5));
        assert!(!authentication_is_fresh(101, 100, 5));
        assert!(!authentication_is_fresh(i64::MIN, i64::MAX, u64::MAX));
    }

    #[test]
    fn login_status_rejects_backward_and_skipped_transitions() {
        assert!(LoginStatus::can_transition(
            LoginStatus::IDENTIFIER_VERIFIED,
            LoginStatus::MFA_REQUIRED
        ));
        assert!(LoginStatus::can_transition(
            LoginStatus::MFA_REQUIRED,
            LoginStatus::AUTHENTICATED
        ));
        assert!(!LoginStatus::can_transition(
            LoginStatus::CREATED,
            LoginStatus::AUTHENTICATED
        ));
        assert!(!LoginStatus::can_transition(
            LoginStatus::AUTHENTICATED,
            LoginStatus::MFA_REQUIRED
        ));
    }
}
