use chrono::{DateTime, Utc};
use uuid::Uuid;

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
    pub status: String,
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
    /// Authentication Context Class Reference — set at session creation.
    pub acr: Option<String>,
    /// Internal upper bound for the session's AAL2 authentication context.
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
    pub acr: Option<String>,
    /// Authentication methods used by the latest successful authentication event.
    pub amr: Vec<String>,
}

impl Session {
    #[must_use]
    pub fn effective_acr(&self, now: DateTime<Utc>) -> Option<&str> {
        if self.acr.as_deref() == Some(super::ACR_AAL2)
            && self
                .acr_expires_at
                .is_some_and(|expires_at| expires_at <= now)
        {
            Some(super::ACR_AAL1)
        } else {
            self.acr.as_deref()
        }
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
    pub status: String,
    pub failed_attempts: i32,
    pub created_at: DateTime<Utc>,
    /// ACR that was granted after the full authentication flow (set when
    /// transitioning to `authenticated`).
    pub acr: Option<String>,
    /// ACR that was requested at the start of the login flow.
    pub requested_acr: Option<String>,
}
