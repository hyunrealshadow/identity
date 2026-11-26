use std::fmt;

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

#[derive(Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct SymmetricKeyData {
    pub key: String,
    #[serde(default = "default_symmetric_algorithm")]
    pub algorithm: SymmetricKeyAlgorithm,
}

impl fmt::Debug for SymmetricKeyData {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SymmetricKeyData")
            .field("key", &"[REDACTED]")
            .field("algorithm", &self.algorithm)
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct AsymmetricKeyData {
    pub public_key: String,
    pub private_key: String,
    pub certificate: Option<String>,
}

impl fmt::Debug for AsymmetricKeyData {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AsymmetricKeyData")
            .field("public_key", &self.public_key)
            .field("private_key", &"[REDACTED]")
            .field("certificate", &self.certificate)
            .finish()
    }
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

#[cfg(test)]
mod tests {
    use super::{AsymmetricKeyData, SymmetricKeyAlgorithm, SymmetricKeyData};

    #[test]
    fn debug_redacts_key_material_secrets() {
        let sym = SymmetricKeyData {
            key: "super-secret-symmetric-key".to_owned(),
            algorithm: SymmetricKeyAlgorithm::XChaCha20Poly1305,
        };
        let asym = AsymmetricKeyData {
            public_key: "pub-pem".to_owned(),
            private_key: "super-secret-private-key".to_owned(),
            certificate: None,
        };

        assert!(!format!("{sym:?}").contains("super-secret-symmetric-key"));
        assert!(!format!("{asym:?}").contains("super-secret-private-key"));
        assert!(format!("{asym:?}").contains("pub-pem"));
    }
}
