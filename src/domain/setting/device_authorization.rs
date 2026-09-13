use serde::{Deserialize, Serialize};

use crate::setting::{SettingDefinition, SettingValidationError};

/// Tunables of the RFC 8628 device authorization flow.
///
/// Defaults to a ten minute request lifetime and a five second polling interval.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceAuthorizationSettings {
    /// Lifetime of a device authorization request, returned as `expires_in`.
    pub request_ttl_seconds: i64,
    /// Polling interval advertised to clients as `interval`.
    pub polling_interval_seconds: i64,
}

impl Default for DeviceAuthorizationSettings {
    fn default() -> Self {
        Self {
            request_ttl_seconds: 600,
            polling_interval_seconds: 5,
        }
    }
}

pub struct DeviceAuthorizationSetting;

impl SettingDefinition for DeviceAuthorizationSetting {
    type Value = DeviceAuthorizationSettings;

    const KEY: &'static str = "openid_connect.device_authorization";

    fn default_value() -> Self::Value {
        DeviceAuthorizationSettings::default()
    }

    fn validate(value: &Self::Value) -> Result<(), SettingValidationError> {
        if value.request_ttl_seconds < 1 {
            return Err(SettingValidationError::new(
                "device authorization request lifetime must be positive",
            ));
        }
        if value.polling_interval_seconds < 1 {
            return Err(SettingValidationError::new(
                "device authorization polling interval must be positive",
            ));
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::{DeviceAuthorizationSetting, DeviceAuthorizationSettings};
    use crate::setting::SettingDefinition;

    #[test]
    fn defaults_define_request_lifetime_and_polling_interval() {
        let defaults = DeviceAuthorizationSetting::default_value();

        assert_eq!(defaults.request_ttl_seconds, 600);
        assert_eq!(defaults.polling_interval_seconds, 5);
        assert!(DeviceAuthorizationSetting::validate(&defaults).is_ok());
    }

    #[test]
    fn rejects_non_positive_lifetime_and_polling_interval() {
        let mut settings = DeviceAuthorizationSettings {
            polling_interval_seconds: 0,
            ..DeviceAuthorizationSettings::default()
        };
        assert!(DeviceAuthorizationSetting::validate(&settings).is_err());

        settings = DeviceAuthorizationSettings {
            request_ttl_seconds: 0,
            ..DeviceAuthorizationSettings::default()
        };
        assert!(DeviceAuthorizationSetting::validate(&settings).is_err());
    }
}
