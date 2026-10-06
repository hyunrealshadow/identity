use std::error::Error as StdError;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use thiserror::Error;

use crate::user::{User, UserOid, UserTheme};

#[derive(Debug, Error)]
pub enum UserRepositoryError {
    #[error("failed to query user")]
    QueryFailed(#[source] Box<dyn StdError + Send + Sync>),

    #[error("user not found")]
    UserNotFound,

    #[error("username already exists")]
    UsernameExists,

    #[error("email already exists")]
    EmailExists,

    #[error("database contains an invalid user theme")]
    InvalidStoredTheme,

    #[error("failed to update failed attempts")]
    UpdateFailedAttempts(#[source] Box<dyn StdError + Send + Sync>),

    #[error("failed to reset failed attempts")]
    ResetFailedAttempts(#[source] Box<dyn StdError + Send + Sync>),
}

// ─── UserRepository ──────────────────────────────────────────────────────────

/// Identifier change requested by an account mutation. The normalized value is
/// computed by the use case from the raw input so the repository never
/// re-implements normalization rules.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UserIdentifierUpdate {
    Username { value: String, normalized: String },
    Email { value: String, normalized: String },
}

/// Sparse profile update. `None` leaves the field unchanged, `Some(None)`
/// clears it, `Some(Some(value))` sets it.
#[derive(Debug, Default, Clone)]
pub struct UserProfilePatch {
    pub given_name: Option<Option<String>>,
    pub family_name: Option<Option<String>>,
    pub middle_name: Option<Option<String>>,
    pub nickname: Option<Option<String>>,
    pub profile: Option<Option<String>>,
    pub picture: Option<Option<String>>,
    pub website: Option<Option<String>>,
    pub gender: Option<Option<String>>,
    pub birthdate: Option<Option<String>>,
    pub zone_info: Option<Option<String>>,
    pub locale: Option<Option<String>>,
    pub theme: Option<Option<UserTheme>>,
    pub address_formatted: Option<Option<String>>,
    pub address_street_address: Option<Option<String>>,
    pub address_locality: Option<Option<String>>,
    pub address_region: Option<Option<String>>,
    pub address_postal_code: Option<Option<String>>,
    pub address_country: Option<Option<String>>,
}

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

    /// Replace the username or email after uniqueness checks.
    async fn update_identifier(
        &self,
        oid: UserOid,
        update: UserIdentifierUpdate,
    ) -> Result<Option<User>, UserRepositoryError>;

    /// Apply a sparse profile patch.
    async fn update_profile(
        &self,
        oid: UserOid,
        patch: UserProfilePatch,
    ) -> Result<Option<User>, UserRepositoryError>;
}
