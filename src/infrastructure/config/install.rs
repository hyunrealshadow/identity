use identity_domain::key::AsymmetricKeyAlgorithm;
use serde::{Deserialize, Deserializer, de::Error as DeError};

#[derive(Clone, Debug, Deserialize)]
pub struct InstallConfig {
    pub domain: Option<String>,
    pub username: Option<String>,
    pub email: Option<String>,
    pub password: Option<String>,
    pub application_url: Option<String>,
    #[serde(
        default = "default_key_algorithm",
        deserialize_with = "deserialize_install_key_algorithm"
    )]
    pub key_algorithm: AsymmetricKeyAlgorithm,
}

impl Default for InstallConfig {
    fn default() -> Self {
        Self {
            domain: None,
            username: None,
            email: None,
            password: None,
            application_url: None,
            key_algorithm: default_key_algorithm(),
        }
    }
}

const fn default_key_algorithm() -> AsymmetricKeyAlgorithm {
    AsymmetricKeyAlgorithm::EcdsaP256
}

fn deserialize_install_key_algorithm<'de, D>(
    deserializer: D,
) -> Result<AsymmetricKeyAlgorithm, D::Error>
where
    D: Deserializer<'de>,
{
    let value = String::deserialize(deserializer)?;

    value.parse().map_err(DeError::custom)
}
