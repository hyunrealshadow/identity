use serde::{Deserialize, Serialize};

use super::model::KeyType;

fn default_symmetric_algorithm() -> SymmetricKeyAlgorithm {
    SymmetricKeyAlgorithm::XChaCha20Poly1305
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SymmetricKeyAlgorithm {
    Aes256Gcm,
    XChaCha20Poly1305,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct SymmetricKeyData {
    pub key: String,
    #[serde(default = "default_symmetric_algorithm")]
    pub algorithm: SymmetricKeyAlgorithm,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct AsymmetricKeyData {
    pub public_key: String,
    pub private_key: String,
    pub certificate: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(untagged)]
pub enum KeyData {
    Asymmetric(AsymmetricKeyData),
    Symmetric(SymmetricKeyData),
}

impl KeyData {
    #[must_use]
    pub const fn key_type(&self) -> KeyType {
        match self {
            Self::Asymmetric(_) => KeyType::Asymmetric,
            Self::Symmetric(_) => KeyType::Symmetric,
        }
    }
}
