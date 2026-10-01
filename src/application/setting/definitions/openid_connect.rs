use serde::{Deserialize, Serialize};

use crate::setting::{SettingSection, SettingValidationError};

/// Tunables of the RFC 8628 device authorization flow.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceAuthorizationSettings {
    pub request_ttl_seconds: i64,
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

/// RFC 7591 dynamic client registration.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct DynamicRegistrationSettings {
    pub enabled: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct PushedAuthorizationSettings {
    pub request_ttl_seconds: i64,
    pub require_pushed_authorization_requests: bool,
}
impl Default for PushedAuthorizationSettings {
    fn default() -> Self {
        Self {
            request_ttl_seconds: 90,
            require_pushed_authorization_requests: false,
        }
    }
}

/// Every `openid_connect.*` setting, bound as one section.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct OpenIdConnectSettings {
    pub pushed_authorization: PushedAuthorizationSettings,
    /// Default protocol rules for clients without an explicit override.
    pub oauth_version: identity_domain::openid_connect::OAuthProtocolVersion,
    pub dynamic_registration: DynamicRegistrationSettings,
    pub device_authorization: DeviceAuthorizationSettings,
}

impl SettingSection for OpenIdConnectSettings {
    const PREFIX: &'static str = "openid_connect";
    const OBJECT_FIELDS: &'static [&'static str] =
        &["device_authorization", "pushed_authorization"];

    fn validate(&self) -> Result<(), SettingValidationError> {
        if !(1..=600).contains(&self.pushed_authorization.request_ttl_seconds) {
            return Err(SettingValidationError::new(
                "pushed request lifetime must be between 1 and 600 seconds",
            ));
        }
        if self.device_authorization.request_ttl_seconds < 1 {
            return Err(SettingValidationError::new(
                "device authorization request lifetime must be positive",
            ));
        }
        if self.device_authorization.polling_interval_seconds < 1 {
            return Err(SettingValidationError::new(
                "device authorization polling interval must be positive",
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::{DeviceAuthorizationSettings, DynamicRegistrationSettings, OpenIdConnectSettings};
    use crate::setting::{SettingChanges, SettingRegistry, SettingSection, SettingsSnapshot};

    #[test]
    fn binds_existing_openid_connect_keys() {
        let settings = OpenIdConnectSettings {
            pushed_authorization: super::PushedAuthorizationSettings {
                request_ttl_seconds: 120,
                require_pushed_authorization_requests: true,
            },
            oauth_version: identity_domain::openid_connect::OAuthProtocolVersion::V2_1,
            dynamic_registration: DynamicRegistrationSettings { enabled: true },
            device_authorization: DeviceAuthorizationSettings {
                request_ttl_seconds: 30,
                polling_interval_seconds: 2,
            },
        };

        let snapshot = SettingsSnapshot::default().with_section(&settings);
        assert_eq!(snapshot.section::<OpenIdConnectSettings>(), settings);

        let changes = SettingChanges::default()
            .set_section(&settings)
            .unwrap()
            .into_iter()
            .collect::<Vec<_>>();
        assert_eq!(changes.len(), 4);
        assert!(changes.iter().any(|(key, value)| {
            key == "openid_connect.oauth_version" && value == &serde_json::json!("2.1")
        }));
        assert!(changes.iter().any(|(key, value)| {
            key == "openid_connect.dynamic_registration.enabled"
                && value == &serde_json::json!(true)
        }));
        assert!(changes.iter().any(|(key, value)| {
            key == "openid_connect.device_authorization"
                && value
                    == &serde_json::json!({
                        "request_ttl_seconds": 30,
                        "polling_interval_seconds": 2
                    })
        }));

        assert_eq!(
            SettingChanges::default()
                .set_section_field(&settings, "dynamic_registration.enabled")
                .unwrap()
                .into_iter()
                .collect::<Vec<_>>(),
            vec![(
                "openid_connect.dynamic_registration.enabled".to_owned(),
                serde_json::json!(true)
            )]
        );
    }

    #[test]
    fn defaults_and_validation_belong_to_the_section() {
        let defaults = SettingRegistry::default()
            .register_section::<OpenIdConnectSettings>()
            .defaults()
            .unwrap();
        assert_eq!(defaults.len(), 4);
        assert_eq!(
            SettingsSnapshot::default().section::<OpenIdConnectSettings>(),
            OpenIdConnectSettings::default()
        );

        let mut invalid = OpenIdConnectSettings::default();
        invalid.device_authorization.polling_interval_seconds = 0;
        assert!(invalid.validate().is_err());
        invalid.device_authorization.polling_interval_seconds = 5;
        invalid.device_authorization.request_ttl_seconds = 0;
        assert!(invalid.validate().is_err());
        invalid.device_authorization.request_ttl_seconds = 600;
        for ttl in [0, 601] {
            invalid.pushed_authorization.request_ttl_seconds = ttl;
            assert!(invalid.validate().is_err());
        }
    }
}
