use std::fmt;

use identity_domain::key::AsymmetricKeyAlgorithm;
use serde::{Deserialize, Deserializer, de::Error as DeError};

#[derive(Clone, Deserialize)]
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

impl fmt::Debug for InstallConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("InstallConfig")
            .field("domain", &self.domain)
            .field("username", &self.username)
            .field("email", &self.email)
            .field("password", &self.password.as_ref().map(|_| "[REDACTED]"))
            .field("application_url", &self.application_url)
            .field("key_algorithm", &self.key_algorithm)
            .finish()
    }
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

#[cfg(test)]
mod tests {
    use super::InstallConfig;

    #[test]
    fn debug_redacts_install_config_password() {
        let cfg = InstallConfig {
            password: Some("super-secret-install-pass".to_owned()),
            ..Default::default()
        };
        assert!(!format!("{cfg:?}").contains("super-secret-install-pass"));
    }
}
