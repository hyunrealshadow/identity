use chrono::{DateTime, Utc};

pub use super::definition::{SettingDefinition, SettingValue};
pub use super::error::SettingValidationError;

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
pub struct SettingOid(pub uuid::Uuid);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SettingEntry<T> {
    pub oid: SettingOid,
    pub key: String,
    pub value: T,
    pub created_at: DateTime<Utc>,
    pub updated_at: Option<DateTime<Utc>>,
}
