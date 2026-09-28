use async_trait::async_trait;
use thiserror::Error;

use crate::user::{
    CredentialData, CredentialType, OtpCredentialData, Password, RecoveryCodeCredentialData,
    UserCredential, UserCredentialOid, UserOid,
};

pub use identity_domain::user::repository::{
    UserIdentifierUpdate, UserProfilePatch, UserRepository, UserRepositoryError,
};

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
