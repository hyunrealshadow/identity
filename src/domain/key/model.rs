use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::str::FromStr;
use strum::{AsRefStr, Display, EnumIter, IntoEnumIterator};
use thiserror::Error;

pub use super::algorithm::AsymmetricKeyAlgorithm;
pub use super::material::{AsymmetricKeyData, KeyData, SymmetricKeyData};

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
pub struct KeyOid(pub uuid::Uuid);

#[derive(Debug, Error)]
#[error("unknown key type: {value}")]
pub struct ParseKeyTypeError {
    value: String,
}

#[derive(
    Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, Display, AsRefStr, EnumIter,
)]
#[serde(rename_all = "snake_case")]
#[strum(serialize_all = "snake_case")]
pub enum KeyType {
    Asymmetric,
    Symmetric,
}

impl FromStr for KeyType {
    type Err = ParseKeyTypeError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::iter()
            .find(|variant| variant.as_ref() == value)
            .ok_or_else(|| ParseKeyTypeError {
                value: value.to_owned(),
            })
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
