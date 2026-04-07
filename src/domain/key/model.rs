use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::{fmt, str::FromStr};
use thiserror::Error;
use uuid::Uuid;

#[derive(Debug, Error)]
#[error("unknown key type: {value}")]
pub struct ParseKeyTypeError {
    value: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum KeyType {
    Asymmetric,
    Symmetric,
}

impl fmt::Display for KeyType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let value = match self {
            Self::Asymmetric => "asymmetric",
            Self::Symmetric => "symmetric",
        };
        f.write_str(value)
    }
}

impl FromStr for KeyType {
    type Err = ParseKeyTypeError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "asymmetric" => Ok(Self::Asymmetric),
            "symmetric" => Ok(Self::Symmetric),
            _ => Err(ParseKeyTypeError {
                value: value.to_owned(),
            }),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct AsymmetricKeyData {
    pub public_key: String,
    pub private_key: String,
    pub certificate: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AsymmetricKeyAlgorithm {
    Rsa { bits: usize },
    EcdsaP256,
    EcdsaP384,
    EcdsaP521,
    EcdsaSecp256k1,
    Ed25519,
    Ed448,
}

impl AsymmetricKeyAlgorithm {
    pub fn validate(&self) -> Result<(), String> {
        match self {
            Self::Rsa { bits } if *bits < 2048 => Err("rsa bits must be at least 2048".to_owned()),
            _ => Ok(()),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct SymmetricKeyData {
    pub key: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(untagged)]
pub enum KeyData {
    Asymmetric(AsymmetricKeyData),
    Symmetric(SymmetricKeyData),
}

#[derive(Debug, Clone)]
pub struct Key {
    pub oid: Uuid,
    pub r#type: KeyType,
    pub data: KeyData,
    pub expires_at: Option<DateTime<Utc>>,
    pub revoked_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub updated_at: Option<DateTime<Utc>>,
}
