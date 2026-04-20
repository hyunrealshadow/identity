use serde::{Deserialize, Serialize};
use uuid::Uuid;

pub use super::otp::OtpCredentialData;
pub use super::password::Password;
pub use super::recovery_code::{RecoveryCodeCredentialData, WebAuthnPublicKeyCredentialData};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct UserCredentialOid(pub Uuid);

impl From<Uuid> for UserCredentialOid {
    fn from(value: Uuid) -> Self {
        Self(value)
    }
}

impl From<UserCredentialOid> for Uuid {
    fn from(value: UserCredentialOid) -> Self {
        value.0
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CredentialType {
    Password,
    Otp,
    RecoveryCode,
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
}

#[cfg(test)]
mod tests {
    use super::{CredentialType, UserCredentialOid};
    use uuid::Uuid;

    #[test]
    fn credential_type_round_trips_through_json() {
        let json = serde_json::to_string(&CredentialType::RecoveryCode).unwrap();
        let decoded: CredentialType = serde_json::from_str(&json).unwrap();

        assert_eq!(decoded, CredentialType::RecoveryCode);
    }

    #[test]
    fn user_credential_oid_round_trips_through_uuid() {
        let raw = Uuid::new_v4();
        let oid = UserCredentialOid::from(raw);

        assert_eq!(Uuid::from(oid), raw);
    }
}
