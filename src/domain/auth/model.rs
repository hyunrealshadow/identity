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
    /// When the elevated ACR expires. After this instant the session is still
    /// active but `acr` should be treated as degraded to password-only level.
    pub acr_expires_at: Option<DateTime<Utc>>,
}

/// Read model for the account picker — one JOIN query, no separate user lookup.
#[derive(Debug, Clone)]
pub struct ActiveSession {
    pub session_oid: SessionOid,
    pub user_oid: Uuid,
    pub user_name: String,
    pub user_email: String,
    pub last_active_at: Option<DateTime<Utc>>,
    pub expires_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    /// Effective authentication context, after applying ACR expiry policy.
    pub acr: Option<String>,
}

impl Session {
    #[must_use]
    pub fn effective_acr(&self, now: DateTime<Utc>) -> Option<&str> {
        if self.acr.as_deref() == Some(super::ACR_MFA)
            && self
                .acr_expires_at
                .is_some_and(|expires_at| expires_at <= now)
        {
            Some(super::ACR_PASSWORD)
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

#[cfg(test)]
mod tests {
    use chrono::{Duration, Utc};
    use uuid::Uuid;

    use super::Session;
    use crate::auth::{ACR_MFA, ACR_PASSWORD, SessionOid, SessionStatus};

    fn mfa_session(acr_expires_at: chrono::DateTime<Utc>) -> Session {
        Session {
            oid: SessionOid(Uuid::new_v4()),
            user_oid: Uuid::new_v4(),
            status: SessionStatus::ACTIVE.to_owned(),
            device_name: None,
            device_type: None,
            os_name: None,
            os_version: None,
            browser_name: None,
            browser_version: None,
            user_agent: None,
            ip_address: None,
            last_active_at: None,
            expires_at: None,
            revoked_at: None,
            created_at: Utc::now(),
            acr: Some(ACR_MFA.to_owned()),
            acr_expires_at: Some(acr_expires_at),
        }
    }

    #[test]
    fn effective_acr_degrades_expired_mfa_to_password() {
        let now = Utc::now();
        let session = mfa_session(now - Duration::seconds(1));

        assert_eq!(session.effective_acr(now), Some(ACR_PASSWORD));
    }

    #[test]
    fn effective_acr_keeps_unexpired_mfa() {
        let now = Utc::now();
        let session = mfa_session(now + Duration::minutes(1));

        assert_eq!(session.effective_acr(now), Some(ACR_MFA));
    }
}
