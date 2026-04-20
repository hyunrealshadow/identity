use async_trait::async_trait;
use chrono::{DateTime, Utc};
use thiserror::Error;

use crate::domain::user::{
    CredentialType, Password, User, UserCredential, UserCredentialOid, UserOid,
};

#[derive(Debug, Error)]
pub enum UserRepositoryError {
    #[error("failed to query user")]
    QueryFailed(#[source] sea_orm::DbErr),

    #[error("user not found")]
    UserNotFound,

    #[error("failed to update failed attempts")]
    UpdateFailedAttempts(#[source] sea_orm::DbErr),

    #[error("failed to reset failed attempts")]
    ResetFailedAttempts(#[source] sea_orm::DbErr),
}

#[derive(Debug, Error)]
pub enum UserCredentialRepositoryError {
    #[error("failed to query credentials")]
    QueryFailed(#[source] sea_orm::DbErr),

    #[error("credential not found")]
    CredentialNotFound,

    #[error("failed to serialize credential data")]
    Serialization(#[source] serde_json::Error),

    #[error("failed to update password credential")]
    UpdatePasswordFailed(#[source] sea_orm::DbErr),
}

// ─── UserRepository ──────────────────────────────────────────────────────────

#[async_trait]
pub trait UserRepository: Send + Sync {
    /// Find a user by normalized email or normalized username.
    async fn find_by_identifier(&self, identifier: &str) -> Result<User, UserRepositoryError>;

    /// Find a user by external OID.
    async fn find_by_oid(&self, oid: UserOid) -> Result<Option<User>, UserRepositoryError>;

    /// Increment `failed_attempts` by 1 and optionally lock the account.
    async fn increment_failed_attempts(
        &self,
        user_oid: UserOid,
        lock_until: Option<DateTime<Utc>>,
    ) -> Result<(), UserRepositoryError>;

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
}
