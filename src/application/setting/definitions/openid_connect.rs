use identity_domain::openid_connect::OAuthProtocolVersion;
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

/// Default lifetimes for tokens and authorization codes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct TokenLifetimeSettings {
    pub access_token_lifetime_seconds: i64,
    pub id_token_lifetime_seconds: i64,
    pub refresh_token_lifetime_days: i64,
    pub authorization_code_lifetime_seconds: i64,
}

impl Default for TokenLifetimeSettings {
    fn default() -> Self {
        Self {
            access_token_lifetime_seconds: 3_600,
            id_token_lifetime_seconds: 3_600,
            refresh_token_lifetime_days: 30,
            authorization_code_lifetime_seconds: 600,
        }
    }
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
    pub oauth_version: OAuthProtocolVersion,
    pub dynamic_registration: DynamicRegistrationSettings,
    pub device_authorization: DeviceAuthorizationSettings,
    pub tokens: TokenLifetimeSettings,
}

impl SettingSection for OpenIdConnectSettings {
    const PREFIX: &'static str = "openid_connect";
    const OBJECT_FIELDS: &'static [&'static str] =
        &["device_authorization", "pushed_authorization", "tokens"];

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
        if self.tokens.access_token_lifetime_seconds < 1 {
            return Err(SettingValidationError::new(
                "access token lifetime must be positive",
            ));
        }
        if self.tokens.id_token_lifetime_seconds < 1 {
            return Err(SettingValidationError::new(
                "ID token lifetime must be positive",
            ));
        }
        if self.tokens.refresh_token_lifetime_days < 1 {
            return Err(SettingValidationError::new(
                "refresh token lifetime must be positive",
            ));
        }
        if !(1..=600).contains(&self.tokens.authorization_code_lifetime_seconds) {
            return Err(SettingValidationError::new(
                "authorization code lifetime must be between 1 and 600 seconds",
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use identity_domain::openid_connect::OAuthProtocolVersion;
    use serde_json::json;

    use super::{
        DeviceAuthorizationSettings, DynamicRegistrationSettings, OpenIdConnectSettings,
        PushedAuthorizationSettings, TokenLifetimeSettings,
    };
    use crate::setting::{SettingChanges, SettingSection, SettingsSnapshot};

    #[test]
    fn binds_existing_openid_connect_keys() {
        let settings = OpenIdConnectSettings {
            pushed_authorization: PushedAuthorizationSettings {
                request_ttl_seconds: 120,
                require_pushed_authorization_requests: true,
            },
            oauth_version: OAuthProtocolVersion::V2_1,
            dynamic_registration: DynamicRegistrationSettings { enabled: true },
            device_authorization: DeviceAuthorizationSettings {
                request_ttl_seconds: 30,
                polling_interval_seconds: 2,
            },
            tokens: TokenLifetimeSettings {
                access_token_lifetime_seconds: 1_800,
                id_token_lifetime_seconds: 900,
                refresh_token_lifetime_days: 14,
                authorization_code_lifetime_seconds: 300,
            },
        };

        let snapshot = SettingsSnapshot::default().with_section(&settings);
        assert_eq!(snapshot.section::<OpenIdConnectSettings>(), settings);

        let changes = SettingChanges::default()
            .set_section(&settings)
            .unwrap()
            .into_iter()
            .collect::<Vec<_>>();
        assert_eq!(changes.len(), 5);
        assert!(changes.iter().any(|(key, value)| {
            key == "openid_connect.oauth_version" && value == &json!("2.1")
        }));
        assert!(changes.iter().any(|(key, value)| {
            key == "openid_connect.dynamic_registration.enabled" && value == &json!(true)
        }));
        assert!(changes.iter().any(|(key, value)| {
            key == "openid_connect.device_authorization"
                && value
                    == &json!({
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
                json!(true)
            )]
        );
    }

    #[test]
    fn validates_authorization_time_limits() {
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
        invalid.pushed_authorization.request_ttl_seconds = 90;
        invalid.tokens.access_token_lifetime_seconds = 0;
        assert!(invalid.validate().is_err());
        invalid.tokens.access_token_lifetime_seconds = 3_600;
        invalid.tokens.id_token_lifetime_seconds = 0;
        assert!(invalid.validate().is_err());
        invalid.tokens.id_token_lifetime_seconds = 3_600;
        invalid.tokens.refresh_token_lifetime_days = 0;
        assert!(invalid.validate().is_err());
        invalid.tokens.refresh_token_lifetime_days = 30;
        for ttl in [0, 601] {
            invalid.tokens.authorization_code_lifetime_seconds = ttl;
            assert!(invalid.validate().is_err());
        }
    }
}
