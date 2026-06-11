use serde::{Deserialize, Serialize};
use strum::{AsRefStr, Display};

pub use super::otp::OtpCredentialData;
pub use super::password::Password;
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
pub struct UserCredentialOid(pub uuid::Uuid);

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, Display, AsRefStr)]
#[serde(rename_all = "snake_case")]
#[strum(serialize_all = "snake_case")]
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
    use super::CredentialType;

    #[test]
    fn credential_type_round_trips_through_json() {
        let json = serde_json::to_string(&CredentialType::RecoveryCode).unwrap();
        let decoded: CredentialType = serde_json::from_str(&json).unwrap();

        assert_eq!(decoded, CredentialType::RecoveryCode);
    }

}
