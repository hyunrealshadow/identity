use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone)]
pub struct User {
    pub oid: Uuid,
    pub email: String,
    pub email_normalized: String,
    pub name: String,
    pub name_normalized: String,
    pub email_verified: bool,
    pub failed_attempts: i32,
    pub enabled: bool,
    pub locked: bool,
    pub locked_until: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub updated_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone)]
pub struct UserCredential {
    pub oid: Uuid,
    pub r#type: CredentialType,
    pub data: CredentialData,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CredentialType {
    Password,
    Otp,
    RecoveryCode,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Argon2Variant {
    #[serde(rename = "id")]
    Argon2id,
    #[serde(rename = "i")]
    Argon2i,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Argon2Version {
    #[serde(rename = "1.3")]
    Argon2013,
    #[serde(rename = "1.0")]
    Argon2010,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Argon2Options {
    /// The Argon2 variant (Argon2id recommended).
    pub variant: Argon2Variant,
    pub version: Argon2Version,
    pub time_cost: u32,
    pub memory_cost: u32,
    pub parallelism: u32,
}

/// PHC-compatible stored password for the Argon2 family.
///
/// The `algorithm` field is intentionally omitted here because the
/// outer [`Password`] enum already encodes which algorithm was used.
/// `hash` and `salt` are stored as Base64-encoded strings.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Argon2Password {
    pub hash: String,
    pub salt: String,
    pub options: Argon2Options,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "algorithm")]
pub enum Password {
    #[serde(rename = "argon2")]
    Argon2(Argon2Password),
}

/// TOTP algorithm stored in the credential.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum OtpAlgorithm {
    Sha1,
    Sha256,
    Sha512,
}

impl Default for OtpAlgorithm {
    fn default() -> Self {
        OtpAlgorithm::Sha1
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OtpCredentialData {
    /// Base32-encoded TOTP secret.
    pub secret: String,
    /// Number of OTP digits (typically 6).
    pub digits: u8,
    /// Time step in seconds (typically 30).
    #[serde(default = "default_period")]
    pub period: u32,
    /// HMAC algorithm used by the TOTP generator.
    #[serde(default)]
    pub algorithm: OtpAlgorithm,
}

fn default_period() -> u32 {
    30
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecoveryCodeCredentialData {
    pub code: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebAuthnPublicKeyCredentialData {
    pub public_key: String,
}

#[derive(Debug, Clone)]
pub enum CredentialData {
    Password(Password),
    Otp(OtpCredentialData),
    RecoveryCode(RecoveryCodeCredentialData),
}
