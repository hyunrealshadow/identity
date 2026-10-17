use std::error::Error as StdError;

use crate::error::AppError;
use crate::user::credential::StoredPasskey;
use async_trait::async_trait;
use serde_json::Error as SerdeJsonError;
use thiserror::Error;
use uuid::Uuid;

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
    QueryFailed(#[source] Box<dyn StdError + Send + Sync>),

    #[error("credential not found")]
    CredentialNotFound,

    #[error("failed to serialize credential data")]
    Serialization(#[source] SerdeJsonError),

    #[error("failed to deserialize credential data")]
    Deserialization(#[source] SerdeJsonError),

    #[error("credential data does not match credential type {0}")]
    CredentialTypeMismatch(CredentialType),

    #[error("failed to update password credential")]
    UpdatePasswordFailed(#[source] Box<dyn StdError + Send + Sync>),

    #[error("failed to consume TOTP counter")]
    ConsumeTotpFailed(#[source] Box<dyn StdError + Send + Sync>),

    #[error("failed to replace credentials")]
    ReplaceFailed(#[source] Box<dyn StdError + Send + Sync>),

    #[error("failed to delete credential")]
    DeleteFailed(#[source] Box<dyn StdError + Send + Sync>),

    #[error("recovery-code enrollment is missing or no longer matches the account")]
    InvalidMfaEnrollment,
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
        expected: &Password,
        password: &Password,
    ) -> Result<(), UserCredentialRepositoryError>;

    /// Compare-and-swap the password and revoke sessions, their grants, device
    /// relations and pending logins in one transaction. Failure changes nothing.
    async fn change_password_and_revoke(
        &self,
        user: UserOid,
        credential: UserCredentialOid,
        expected: &Password,
        password: &Password,
        keep: Option<identity_domain::auth::SessionOid>,
    ) -> Result<u32, UserCredentialRepositoryError> {
        let _ = (user, credential, expected, password, keep);
        Err(UserCredentialRepositoryError::UpdatePasswordFailed(
            Box::new(std::io::Error::other(
                "atomic password changes are not configured",
            )),
        ))
    }

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

    /// Enables TOTP only when disabled, preserving existing recovery codes or
    /// installing the prepared batch if absent, within the same transaction.
    async fn enable_totp_if_disabled(
        &self,
        user_oid: UserOid,
        otp: OtpCredentialData,
        recovery_codes: Vec<RecoveryCodeCredentialData>,
    ) -> Result<bool, UserCredentialRepositoryError>;

    /// Removes TOTP and removes recovery codes only if no active MFA remains.
    /// Serializes with other MFA additions, removals and recovery-code changes.
    async fn disable_totp(&self, user_oid: UserOid) -> Result<bool, UserCredentialRepositoryError>;

    /// Replaces recovery codes only while an OTP or Passkey credential exists.
    /// Implementations must evaluate the precondition and replacement
    /// atomically with other credential-group replacements for the user.
    async fn replace_recovery_codes_if_mfa_enabled(
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

/// Per-credential operations on the existing user credential aggregate.
#[async_trait]
pub trait PasskeyCredentialRepository: Send + Sync {
    async fn list(&self, user: UserOid) -> Result<Vec<StoredPasskey>, AppError>;
    /// Enforces globally unique credential IDs and the per-user active Passkey
    /// limit atomically, preserving existing recovery codes or installing a
    /// prepared batch if absent. Missing or stale recovery enrollment fails.
    async fn insert(
        &self,
        user: UserOid,
        key: StoredPasskey,
        recovery_codes: Vec<RecoveryCodeCredentialData>,
    ) -> Result<(), AppError>;
    /// Compare-and-swap must reject revoked, expired, or concurrently changed credentials.
    async fn update(
        &self,
        user: UserOid,
        before: &StoredPasskey,
        after: &StoredPasskey,
    ) -> Result<bool, AppError>;
    /// Removes a Passkey and clears recovery codes only if no active MFA remains,
    /// atomically with other MFA mutations for the account.
    async fn delete(&self, user: UserOid, id: Uuid) -> Result<bool, AppError>;
}
