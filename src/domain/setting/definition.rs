use serde::{Serialize, de::DeserializeOwned};

use super::error::SettingValidationError;

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
