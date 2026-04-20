use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::{fmt, str::FromStr};
use thiserror::Error;
use uuid::Uuid;

pub use super::algorithm::AsymmetricKeyAlgorithm;
pub use super::material::{AsymmetricKeyData, KeyData, SymmetricKeyData};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct KeyOid(pub Uuid);

impl From<Uuid> for KeyOid {
    fn from(value: Uuid) -> Self {
        Self(value)
    }
}

impl From<KeyOid> for Uuid {
    fn from(value: KeyOid) -> Self {
        value.0
    }
}

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

#[derive(Debug, Clone)]
pub struct Key {
    pub oid: KeyOid,
    pub r#type: KeyType,
    pub data: KeyData,
    pub expires_at: Option<DateTime<Utc>>,
    pub revoked_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub updated_at: Option<DateTime<Utc>>,
}

#[cfg(test)]
mod tests {
    use super::KeyOid;
    use uuid::Uuid;

    #[test]
    fn key_oid_round_trips_through_uuid() {
        let raw = Uuid::new_v4();
        let oid = KeyOid::from(raw);

        assert_eq!(Uuid::from(oid), raw);
    }

    #[test]
    fn key_oid_round_trips_through_json() {
        let oid = KeyOid::from(Uuid::new_v4());
        let json = serde_json::to_string(&oid).unwrap();
        let decoded: KeyOid = serde_json::from_str(&json).unwrap();

        assert_eq!(decoded, oid);
    }
}
