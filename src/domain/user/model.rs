use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

pub use super::credential::{CredentialData, CredentialType, UserCredential, UserCredentialOid};
pub use super::otp::{OtpAlgorithm, OtpCredentialData};
pub use super::password::{Argon2Options, Argon2Password, Argon2Variant, Argon2Version, Password};
pub use super::recovery_code::{RecoveryCodeCredentialData, WebAuthnPublicKeyCredentialData};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct UserOid(pub Uuid);

impl From<Uuid> for UserOid {
    fn from(value: Uuid) -> Self {
        Self(value)
    }
}

impl From<UserOid> for Uuid {
    fn from(value: UserOid) -> Self {
        value.0
    }
}

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

#[cfg(test)]
mod tests {
    use super::UserOid;
    use uuid::Uuid;

    #[test]
    fn user_oid_round_trips_through_uuid() {
        let raw = Uuid::new_v4();
        let oid = UserOid::from(raw);

        assert_eq!(Uuid::from(oid), raw);
    }

    #[test]
    fn user_oid_round_trips_through_json() {
        let oid = UserOid::from(Uuid::new_v4());
        let json = serde_json::to_string(&oid).unwrap();
        let decoded: UserOid = serde_json::from_str(&json).unwrap();

        assert_eq!(decoded, oid);
    }
}
