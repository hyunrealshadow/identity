use serde::{Deserialize, Serialize};

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

#[cfg(test)]
mod tests {
    use super::{AsymmetricKeyData, KeyData};

    #[test]
    fn key_data_round_trips_through_json() {
        let data = KeyData::Asymmetric(AsymmetricKeyData {
            public_key: "public".to_owned(),
            private_key: "private".to_owned(),
            certificate: None,
        });

        let json = serde_json::to_string(&data).unwrap();
        let decoded: KeyData = serde_json::from_str(&json).unwrap();

        assert_eq!(decoded, data);
    }
}
