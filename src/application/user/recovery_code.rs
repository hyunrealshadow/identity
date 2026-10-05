use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecoveryCodeCredentialData {
    pub hash: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebAuthnPublicKeyCredentialData {
    pub public_key: String,
}
