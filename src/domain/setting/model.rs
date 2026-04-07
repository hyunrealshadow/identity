use chrono::{DateTime, Utc};
use serde::{Serialize, de::DeserializeOwned};
use thiserror::Error;
use uuid::Uuid;

#[derive(Debug, Error)]
#[error("{message}")]
pub struct SettingValidationError {
    message: String,
}

impl SettingValidationError {
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }

    pub fn message(&self) -> &str {
        &self.message
    }
}

pub trait SettingValue:
    Clone + PartialEq + Send + Sync + Serialize + DeserializeOwned + 'static
{
}

impl<T> SettingValue for T where
    T: Clone + PartialEq + Send + Sync + Serialize + DeserializeOwned + 'static
{
}

pub trait SettingDefinition: Send + Sync + 'static {
    type Value: SettingValue;

    const KEY: &'static str;

    fn default_value() -> Self::Value;

    fn validate(_value: &Self::Value) -> Result<(), SettingValidationError> {
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SettingEntry<T> {
    pub oid: Uuid,
    pub key: String,
    pub value: T,
    pub created_at: DateTime<Utc>,
    pub updated_at: Option<DateTime<Utc>>,
}
