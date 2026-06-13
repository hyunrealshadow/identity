use chrono::{DateTime, Utc};

pub use super::credential::{CredentialData, CredentialType, UserCredential, UserCredentialOid};
pub use super::otp::{OtpAlgorithm, OtpCredentialData};
pub use super::password::{Argon2Options, Argon2Password, Argon2Variant, Argon2Version, Password};
pub use super::recovery_code::{RecoveryCodeCredentialData, WebAuthnPublicKeyCredentialData};

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
pub struct UserOid(pub uuid::Uuid);

#[derive(Debug, Clone)]
pub struct User {
    pub oid: UserOid,
    pub email: String,
    pub email_normalized: String,
    pub name: String,
    pub name_normalized: String,
    pub given_name: Option<String>,
    pub family_name: Option<String>,
    pub middle_name: Option<String>,
    pub nickname: Option<String>,
    pub profile: Option<String>,
    pub picture: Option<String>,
    pub website: Option<String>,
    pub gender: Option<String>,
    pub birthdate: Option<String>,
    pub zoneinfo: Option<String>,
    pub locale: Option<String>,
    pub email_verified: bool,
    pub phone_number: Option<String>,
    pub phone_number_verified: Option<bool>,
    pub address_formatted: Option<String>,
    pub address_street_address: Option<String>,
    pub address_locality: Option<String>,
    pub address_region: Option<String>,
    pub address_postal_code: Option<String>,
    pub address_country: Option<String>,
    pub failed_attempts: i32,
    pub enabled: bool,
    pub locked: bool,
    pub locked_until: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub updated_at: Option<DateTime<Utc>>,
}
