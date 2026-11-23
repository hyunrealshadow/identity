use chrono::{DateTime, Utc};
use uuid::Uuid;

use super::{AuthenticationContextClass, LoginStatus, SessionStatus, required_acr};

#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    Hash,
    serde::Serialize,
    serde::Deserialize,
    derive_more::From,
    derive_more::Into,
)]
pub struct SessionOid(pub Uuid);

#[derive(Debug, Clone)]
pub struct Session {
    pub oid: SessionOid,
    pub user_oid: Uuid,
    pub status: SessionStatus,
    pub device_name: Option<String>,
    pub device_type: Option<String>,
    pub os_name: Option<String>,
    pub os_version: Option<String>,
    pub browser_name: Option<String>,
    pub browser_version: Option<String>,
    pub user_agent: Option<String>,
    pub ip_address: Option<String>,
    pub last_active_at: Option<DateTime<Utc>>,
    pub expires_at: Option<DateTime<Utc>>,
    pub revoked_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    /// Authentication context class established by the latest authentication.
    pub acr: Option<AuthenticationContextClass>,
    /// Internal upper bound for the session's multi-factor context.
    /// RFC 9470 clients do not consume this value directly.
    pub acr_expires_at: Option<DateTime<Utc>>,
    /// Authentication methods used by the latest successful authentication event.
    pub amr: Vec<String>,
}

/// Read model for the account picker — one JOIN query, no separate user lookup.
#[derive(Debug, Clone)]
pub struct ActiveSession {
    pub session_oid: SessionOid,
    pub user_oid: Uuid,
    pub user_name: String,
    pub user_email: String,
    pub user_picture: Option<String>,
    pub last_active_at: Option<DateTime<Utc>>,
    pub expires_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    /// Time of the latest successful credential verification. This differs
    /// from session creation when an existing session is reauthenticated.
    pub authenticated_at: DateTime<Utc>,
    /// Authentication context established by the latest authentication event.
    pub acr: Option<AuthenticationContextClass>,
    /// Authentication methods used by the latest successful authentication event.
    pub amr: Vec<String>,
}

impl Session {
    #[must_use]
    pub fn effective_acr(&self, now: DateTime<Utc>) -> Option<AuthenticationContextClass> {
        effective_acr(self.acr, self.acr_expires_at, now)
    }
}

/// A multi-factor class lapses to single-factor once its elevated window ends;
/// the methods recorded in `amr` never promote it again.
#[must_use]
pub fn effective_acr(
    acr: Option<AuthenticationContextClass>,
    acr_expires_at: Option<DateTime<Utc>>,
    now: DateTime<Utc>,
) -> Option<AuthenticationContextClass> {
    match acr {
        Some(class)
            if class.is_multi_factor()
                && acr_expires_at.is_some_and(|expires_at| expires_at <= now) =>
        {
            Some(AuthenticationContextClass::SingleFactor)
        }
        other => other,
    }
}

#[derive(Debug, Clone)]
pub struct Login {
    pub oid: Uuid,
    pub client_oid: Uuid,
    pub client_authorization_oid: Uuid,
    pub session_oid: Option<SessionOid>,
    /// The user this login attempt belongs to.  Set at creation (identifier
    /// step) so that subsequent challenge steps do not need to re-resolve the
    /// identifier string into a user.
    pub user_oid: Option<Uuid>,
    /// The identifier as entered at the identifier step, kept only when the
    /// instance conceals whether accounts exist. Until the first factor
    /// succeeds, the interaction presents this instead of the account, and
    /// `user_oid` may be `None` because no account matched.
    pub submitted_identifier: Option<String>,
    pub status: LoginStatus,
    pub failed_attempts: i32,
    pub created_at: DateTime<Utc>,
    /// Absolute deadline after which this login interaction cannot advance.
    pub expires_at: DateTime<Utc>,
    /// Class established by the full authentication flow (set when
    /// transitioning to `authenticated`).
    pub acr: Option<AuthenticationContextClass>,
    /// Classes the request accepts, in order of preference (`acr_values`, or
    /// the client's `default_acr_values`). Empty when nothing was requested.
    pub requested_acr_values: Vec<AuthenticationContextClass>,
    /// Authentication methods satisfied so far in this login interaction.
    pub amr: Vec<String>,
}

impl Login {
    /// The class a new authentication must establish: the weakest one listed.
    #[must_use]
    pub fn required_acr(&self) -> Option<AuthenticationContextClass> {
        required_acr(&self.requested_acr_values)
    }

    /// The most preferred class. It orders the offered methods and never
    /// makes the requirement stricter.
    #[must_use]
    pub fn preferred_acr(&self) -> Option<AuthenticationContextClass> {
        self.requested_acr_values.first().copied()
    }

    /// The identifier this interaction presents while it conceals whether an
    /// account exists: from the identifier step until the password succeeds.
    #[must_use]
    pub fn concealed_identifier(&self) -> Option<&str> {
        (self.status == LoginStatus::IDENTIFIER_VERIFIED)
            .then_some(self.submitted_identifier.as_deref())
            .flatten()
    }
}
