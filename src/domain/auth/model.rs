use chrono::{DateTime, Utc};
use uuid::Uuid;

#[derive(Debug, Clone)]
pub struct Session {
    pub oid: Uuid,
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
    /// When the elevated ACR expires. After this instant the session is still
    /// active but `acr` should be treated as degraded to password-only level.
    pub acr_expires_at: Option<DateTime<Utc>>,
}

/// Read model for the account picker — one JOIN query, no separate user lookup.
#[derive(Debug, Clone)]
pub struct ActiveSession {
    pub session_oid: Uuid,
    pub user_oid: Uuid,
    pub user_name: String,
    pub user_email: String,
    pub last_active_at: Option<DateTime<Utc>>,
    pub expires_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone)]
pub struct Login {
    pub oid: Uuid,
    pub client_oid: Uuid,
    pub client_authorization_oid: Uuid,
    pub session_oid: Option<Uuid>,
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
