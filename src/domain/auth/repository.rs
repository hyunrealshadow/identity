use async_trait::async_trait;
use chrono::{DateTime, Utc};
use thiserror::Error;
use uuid::Uuid;

use crate::auth::model::{ActiveSession, Login, Session, SessionOid};

#[derive(Debug, Error)]
pub enum SessionRepositoryError {
    #[error("failed to query session")]
    QueryFailed(#[source] Box<dyn std::error::Error + Send + Sync>),

    #[error("failed to query active sessions")]
    ListActiveFailed(#[source] Box<dyn std::error::Error + Send + Sync>),

    #[error("user not found while creating session")]
    UserNotFound,

    #[error("failed to create session")]
    CreateFailed(#[source] Box<dyn std::error::Error + Send + Sync>),

    #[error("session not found for touch")]
    SessionNotFound,

    #[error("failed to update session activity")]
    TouchFailed(#[source] Box<dyn std::error::Error + Send + Sync>),

    #[error("failed to revoke session")]
    RevokeFailed(#[source] Box<dyn std::error::Error + Send + Sync>),
}

#[derive(Debug, Error)]
pub enum LoginRepositoryError {
    #[error("failed to query login")]
    QueryFailed(#[source] Box<dyn std::error::Error + Send + Sync>),

    #[error("user not found while creating login")]
    UserNotFound,

    #[error("failed to create login")]
    CreateFailed(#[source] Box<dyn std::error::Error + Send + Sync>),

    #[error("login not found")]
    LoginNotFound,

    #[error("session not found while updating login")]
    SessionNotFound,

    #[error("failed to update login")]
    UpdateFailed(#[source] Box<dyn std::error::Error + Send + Sync>),

    #[error("failed to increment login failed attempts")]
    IncrementFailedAttempts(#[source] Box<dyn std::error::Error + Send + Sync>),
}

// ─── SessionRepository ───────────────────────────────────────────────────────

#[async_trait]
pub trait SessionRepository: Send + Sync {
    /// Find a session by its OID.
    async fn find_by_oid(&self, oid: SessionOid)
    -> Result<Option<Session>, SessionRepositoryError>;

    /// Find multiple active sessions by their OIDs, joined with user data.
    ///
    /// Returns a flat read model so callers never need a separate user repo.
    async fn find_active_accounts_by_oids(
        &self,
        oids: &[SessionOid],
    ) -> Result<Vec<ActiveSession>, SessionRepositoryError>;

    /// Create a new session and return it.
    #[allow(clippy::too_many_arguments)]
    async fn create(
        &self,
        user_oid: Uuid,
        device_name: Option<String>,
        device_type: Option<String>,
        os_name: Option<String>,
        os_version: Option<String>,
        browser_name: Option<String>,
        browser_version: Option<String>,
        user_agent: Option<String>,
        ip_address: Option<String>,
        expires_at: Option<DateTime<Utc>>,
        acr: Option<String>,
        acr_expires_at: Option<DateTime<Utc>>,
    ) -> Result<Session, SessionRepositoryError>;

    /// Update `last_active_at` for a session (identified by OID).
    async fn touch_by_oid(&self, oid: SessionOid) -> Result<(), SessionRepositoryError>;

    async fn revoke_by_oid(
        &self,
        oid: SessionOid,
        revoked_at: DateTime<Utc>,
    ) -> Result<Option<Session>, SessionRepositoryError>;
}

// ─── LoginRepository ─────────────────────────────────────────────────────────

#[async_trait]
pub trait LoginRepository: Send + Sync {
    /// Find a login by its OID.
    async fn find_by_oid(&self, oid: Uuid) -> Result<Option<Login>, LoginRepositoryError>;

    /// Create a new login record linked to the identified user, and return it.
    async fn create_pending(
        &self,
        client_oid: Uuid,
        client_authorization_oid: Uuid,
        requested_acr: Option<&str>,
    ) -> Result<Login, LoginRepositoryError>;

    /// Bind a resolved user to an existing login and move it forward.
    async fn bind_user(
        &self,
        login_oid: Uuid,
        user_oid: Uuid,
        status: &str,
    ) -> Result<Login, LoginRepositoryError>;

    /// Update login status (and optionally link a session by session OID).
    ///
    /// `acr` is written when the login transitions to `authenticated` so that
    /// the granted ACR is recorded on the login row for audit purposes.
    async fn update_status(
        &self,
        login_oid: Uuid,
        status: &str,
        session_oid: Option<SessionOid>,
        acr: Option<&str>,
    ) -> Result<(), LoginRepositoryError>;

    /// Increment login `failed_attempts` and record a failure reason.
    async fn increment_failed_attempts(
        &self,
        login_oid: Uuid,
        failure_reason: Option<&str>,
    ) -> Result<(), LoginRepositoryError>;
}
