use async_trait::async_trait;
use chrono::{DateTime, Utc};
use thiserror::Error;

use crate::user::{
    CredentialData, CredentialType, Password, User, UserCredential, UserCredentialOid, UserOid,
};

#[derive(Debug, Error)]
pub enum UserRepositoryError {
    #[error("failed to query user")]
    QueryFailed(#[source] Box<dyn std::error::Error + Send + Sync>),

    #[error("user not found")]
    UserNotFound,

    #[error("username already exists")]
    UsernameExists,

    #[error("email already exists")]
    EmailExists,

    #[error("failed to update failed attempts")]
    UpdateFailedAttempts(#[source] Box<dyn std::error::Error + Send + Sync>),

    #[error("failed to reset failed attempts")]
    ResetFailedAttempts(#[source] Box<dyn std::error::Error + Send + Sync>),
}

#[derive(Debug, Error)]
pub enum UserCredentialRepositoryError {
    #[error("failed to query credentials")]
    QueryFailed(#[source] Box<dyn std::error::Error + Send + Sync>),

    #[error("credential not found")]
    CredentialNotFound,

    #[error("failed to serialize credential data")]
    Serialization(#[source] serde_json::Error),

    #[error("failed to update password credential")]
    UpdatePasswordFailed(#[source] Box<dyn std::error::Error + Send + Sync>),

    #[error("failed to consume TOTP counter")]
    ConsumeTotpFailed(#[source] Box<dyn std::error::Error + Send + Sync>),

    #[error("failed to replace credentials")]
    ReplaceFailed(#[source] Box<dyn std::error::Error + Send + Sync>),

    #[error("failed to delete credential")]
    DeleteFailed(#[source] Box<dyn std::error::Error + Send + Sync>),
}

// ─── UserRepository ──────────────────────────────────────────────────────────

#[async_trait]
pub trait UserRepository: Send + Sync {
    /// Find a user by normalized email or normalized username.
    async fn find_by_identifier(&self, identifier: &str) -> Result<User, UserRepositoryError>;

    /// Find a user by external OID.
    async fn find_by_oid(&self, oid: UserOid) -> Result<Option<User>, UserRepositoryError>;

    /// Atomically increment `failed_attempts`, lock the account when the
    /// resulting count reaches `lock_threshold`, and return that count.
    async fn increment_failed_attempts(
        &self,
        user_oid: UserOid,
        lock_threshold: i32,
        lock_until: DateTime<Utc>,
    ) -> Result<i32, UserRepositoryError>;

    /// Reset `failed_attempts` to 0 and clear the lock.
    async fn reset_failed_attempts(&self, user_oid: UserOid) -> Result<(), UserRepositoryError>;
}

// ─── UserCredentialRepository ─────────────────────────────────────────────────

#[async_trait]
pub trait UserCredentialRepository: Send + Sync {
    /// Find credentials for a given user and credential type.
    ///
    /// Rows whose `data` JSON cannot be deserialized into a known
    /// [`CredentialData`] variant are silently skipped.
    async fn find_by_user_oid_and_type(
        &self,
        user_oid: UserOid,
        credential_type: CredentialType,
    ) -> Result<Vec<UserCredential>, UserCredentialRepositoryError>;

    /// Overwrite the stored [`Password`] for a credential (identified by OID).
    ///
    /// Used exclusively for transparent password rehashing; the type is
    /// constrained to [`Password`] so callers cannot accidentally serialize
    /// arbitrary data.
    async fn update_password_by_oid(
        &self,
        credential_oid: UserCredentialOid,
        password: &Password,
    ) -> Result<(), UserCredentialRepositoryError>;

    /// Atomically stores `counter` in the OTP credential's JSONB data only if
    /// it is greater than the previously consumed counter.
    async fn consume_totp_counter(
        &self,
        credential_oid: UserCredentialOid,
        counter: u64,
    ) -> Result<bool, UserCredentialRepositoryError>;

    /// Atomically replaces one or more credential groups owned by the user.
    async fn replace_by_user_oid(
        &self,
        user_oid: UserOid,
        replacements: Vec<(CredentialType, Vec<CredentialData>)>,
    ) -> Result<(), UserCredentialRepositoryError>;

    /// Deletes one credential. Used to consume a recovery code exactly once.
    async fn delete_by_oid(
        &self,
        credential_oid: UserCredentialOid,
    ) -> Result<bool, UserCredentialRepositoryError>;
}
