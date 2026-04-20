use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecoveryCodeCredentialData {
    pub code: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebAuthnPublicKeyCredentialData {
    pub public_key: String,
}

#[cfg(test)]
mod tests {
    use super::RecoveryCodeCredentialData;

    #[test]
    fn recovery_code_round_trips_through_json() {
        let data = RecoveryCodeCredentialData {
            code: "code".to_owned(),
        };

        let json = serde_json::to_string(&data).unwrap();
        let decoded: RecoveryCodeCredentialData = serde_json::from_str(&json).unwrap();

        assert_eq!(decoded.code, data.code);
    }
}
