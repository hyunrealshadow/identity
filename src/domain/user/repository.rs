use async_trait::async_trait;
use chrono::{DateTime, Utc};
use thiserror::Error;

use crate::user::{
    CredentialData, CredentialType, OtpCredentialData, Password, RecoveryCodeCredentialData, User,
    UserCredential, UserCredentialOid, UserOid, UserTheme,
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

    #[error("database contains an invalid user theme")]
    InvalidStoredTheme,

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

    #[error("failed to deserialize credential data")]
    Deserialization(#[source] serde_json::Error),

    #[error("credential data does not match credential type {0}")]
    CredentialTypeMismatch(CredentialType),

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

// ─── UserCredentialRepository ─────────────────────────────────────────────────

#[async_trait]
pub trait UserCredentialRepository: Send + Sync {
    /// Find active credentials for a given user and credential type.
    ///
    /// Corrupt credential payloads are returned as repository errors; treating
    /// them as absent credentials would hide persistence corruption from the
    /// authentication flow.
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

    /// Enables TOTP and installs its recovery codes only when the user has no
    /// active OTP credential. The precondition and both replacements are one
    /// atomic operation.
    async fn enable_totp_if_disabled(
        &self,
        user_oid: UserOid,
        otp: OtpCredentialData,
        recovery_codes: Vec<RecoveryCodeCredentialData>,
    ) -> Result<bool, UserCredentialRepositoryError>;

    /// Replaces recovery codes only while an OTP credential exists.
    /// Implementations must evaluate the precondition and replacement
    /// atomically with other credential-group replacements for the user.
    async fn replace_recovery_codes_if_totp_enabled(
        &self,
        user_oid: UserOid,
        recovery_codes: Vec<RecoveryCodeCredentialData>,
    ) -> Result<bool, UserCredentialRepositoryError>;

    /// Atomically consumes one active recovery-code credential.
    async fn consume_recovery_code_by_oid(
        &self,
        credential_oid: UserCredentialOid,
    ) -> Result<bool, UserCredentialRepositoryError>;
}
