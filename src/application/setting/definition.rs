use serde::{Deserialize, Serialize, de::DeserializeOwned};
use thiserror::Error;

use super::error::SettingError;

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

/// A typed view over every setting stored under `PREFIX`, bound the way a
/// configuration section is: the value of `PREFIX.a.b` fills field `a.b`, and a
/// JSON object stored at a key fills the fields beneath it.
pub trait SettingSection: Serialize + DeserializeOwned + Default {
    const PREFIX: &'static str;

    /// Object-valued fields stored at their own key instead of being split
    /// into keys for every child field.
    const OBJECT_FIELDS: &'static [&'static str] = &[];

    fn validate(&self) -> Result<(), SettingValidationError> {
        Ok(())
    }
}

pub trait SettingDefinition: Send + Sync + 'static {
    type Value: SettingValue;

    const KEY: &'static str;

    fn default_value() -> Self::Value;

    fn validate(_value: &Self::Value) -> Result<(), SettingValidationError> {
        Ok(())
    }

    /// Decodes and validates a stored value.
    fn decode(raw: &serde_json::Value) -> Result<Self::Value, SettingError> {
        let value = Self::Value::deserialize(raw).map_err(SettingError::Deserialize)?;
        Self::validate(&value)
            .map_err(|error| SettingError::Validation(error.message().to_owned()))?;
        Ok(value)
    }
}

#[cfg(test)]
mod tests {
    use super::SettingDefinition;

    #[test]
    fn default_setting_definition_uses_declared_default() {
        struct ExampleSetting;

        impl SettingDefinition for ExampleSetting {
            type Value = bool;
            const KEY: &'static str = "example";

            fn default_value() -> Self::Value {
                true
            }
        }

        assert!(ExampleSetting::default_value());
    }
}
