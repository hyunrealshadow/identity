use serde::{Deserialize, Serialize};
use strum::{AsRefStr, Display};
use uuid::Uuid;

pub use super::otp::OtpCredentialData;
pub use super::password::Password;
pub use super::recovery_code::RecoveryCodeCredentialData;

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
pub struct UserCredentialOid(pub Uuid);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Display, AsRefStr)]
#[serde(rename_all = "snake_case")]
#[strum(serialize_all = "snake_case")]
pub enum CredentialType {
    Password,
    Otp,
    RecoveryCode,
    Passkey,
}

#[derive(Debug, Clone)]
pub struct UserCredential {
    pub oid: UserCredentialOid,
    pub r#type: CredentialType,
    pub data: CredentialData,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum CredentialData {
    Password(Password),
    Otp(OtpCredentialData),
    RecoveryCode(RecoveryCodeCredentialData),
    Passkey(PasskeyCredentialData),
}

impl CredentialData {
    #[must_use]
    pub const fn credential_type(&self) -> CredentialType {
        match self {
            Self::Password(_) => CredentialType::Password,
            Self::Otp(_) => CredentialType::Otp,
            Self::RecoveryCode(_) => CredentialType::RecoveryCode,
            Self::Passkey(_) => CredentialType::Passkey,
        }
    }
}

/// Maximum number of active Passkeys registered to one account.
pub const MAX_PASSKEYS_PER_USER: usize = 5;

/// SDK-independent persisted data for one account's Passkey.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PasskeyCredentialData {
    pub name: String,
    /// Canonical base64url WebAuthn credential ID, unique across accounts.
    pub credential_id: String,
    /// Opaque verifier data; only the WebAuthn adapter interprets its contents.
    pub key: serde_json::Value,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct StoredPasskey {
    pub id: Uuid,
    #[serde(flatten)]
    pub data: PasskeyCredentialData,
}
