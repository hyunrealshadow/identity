use serde::{Deserialize, Serialize};
use url::Url;
use uuid::Uuid;

use crate::setting::{SettingDefinition, SettingSection, SettingValidationError};

/// Where this installation, its login application and its management console
/// are served, as given during installation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct AppSettings {
    /// Domain this installation is served from. It defines the issuer and
    /// every URL the identity service itself owns, such as the device
    /// verification page (`{domain}/device`).
    pub domain: Option<String>,
    /// Origin of the login application, derived from the application URL
    /// (`https://login.example.com/login` becomes `https://login.example.com`).
    ///
    /// The login application owns the user facing pages — sign-in, consent
    /// and device verification — which may live on a different host than the
    /// identity service itself, so its origin is recorded on its own.
    pub login_domain: Option<String>,
    /// Public base URL of the management console, including its deployment path.
    pub console_domain: Option<String>,
    /// Built-in OAuth client used by the login application.
    pub login_client_id: Option<Uuid>,
    /// Public OAuth client provisioned for this installation's management console.
    pub console_client_id: Option<Uuid>,
}

impl SettingSection for AppSettings {
    const PREFIX: &'static str = "app";
}

pub struct DomainSetting;

impl SettingDefinition for DomainSetting {
    type Value = Option<String>;
    const KEY: &'static str = "app.domain";

    fn default_value() -> Self::Value {
        None
    }
}

pub struct LoginDomainSetting;

impl SettingDefinition for LoginDomainSetting {
    type Value = Option<String>;
    const KEY: &'static str = "app.login_domain";

    fn default_value() -> Self::Value {
        None
    }
}

/// Public base URL of the management console, recorded during installation.
/// The deployment path is retained; credentials, queries and fragments are forbidden.
pub struct ConsoleDomainSetting;

impl SettingDefinition for ConsoleDomainSetting {
    type Value = Option<String>;
    const KEY: &'static str = "app.console_domain";

    fn default_value() -> Self::Value {
        None
    }

    fn validate(value: &Self::Value) -> Result<(), SettingValidationError> {
        let Some(raw) = value else {
            return Ok(());
        };
        let url = Url::parse(raw.as_str())
            .map_err(|_| SettingValidationError::new("console origin is not a valid URL"))?;
        if url.scheme() != "https"
            || url.host_str().is_none()
            || url.host_str().is_some_and(|host| host.contains('*'))
            || !url.username().is_empty()
            || url.password().is_some()
            || url.query().is_some()
            || url.fragment().is_some()
        {
            return Err(SettingValidationError::new(
                "console address must use HTTPS without credentials, query or fragment",
            ));
        }
        Ok(())
    }
}

pub struct LoginClientIdSetting;

impl SettingDefinition for LoginClientIdSetting {
    type Value = Option<Uuid>;
    const KEY: &'static str = "app.login_client_id";

    fn default_value() -> Self::Value {
        None
    }
}

pub struct ConsoleClientIdSetting;

impl SettingDefinition for ConsoleClientIdSetting {
    type Value = Option<Uuid>;
    const KEY: &'static str = "app.console_client_id";

    fn default_value() -> Self::Value {
        None
    }
}

#[cfg(test)]
mod tests {
    use uuid::Uuid;

    use super::{
        AppSettings, ConsoleDomainSetting, DomainSetting, LoginClientIdSetting, LoginDomainSetting,
    };
    use crate::setting::{InstallationSettings, SettingDefinition, SettingsSnapshot};

    #[test]
    fn app_fields_and_installation_rows_are_read_independently() {
        let app = AppSettings {
            console_domain: Some("https://console.example.com".to_owned()),
            domain: Some("identity.example.com".to_owned()),
            login_domain: Some("https://login.example.com".to_owned()),
            login_client_id: Some(Uuid::new_v4()),
            console_client_id: Some(Uuid::new_v4()),
        };
        let installation = InstallationSettings {
            initialized: true,
            ..InstallationSettings::default()
        };

        let snapshot = SettingsSnapshot::default()
            .with_section(&app)
            .with::<ConsoleDomainSetting>(Some("https://console.example.com".to_owned()))
            .with_section(&installation);

        assert_eq!(snapshot.section::<AppSettings>(), app);
        assert_eq!(snapshot.get::<DomainSetting>(), app.domain);
        assert_eq!(snapshot.get::<LoginDomainSetting>(), app.login_domain);
        assert_eq!(snapshot.get::<LoginClientIdSetting>(), app.login_client_id);
        assert_eq!(
            snapshot.get::<ConsoleDomainSetting>().as_deref(),
            Some("https://console.example.com")
        );
        assert_eq!(snapshot.section::<InstallationSettings>(), installation);
    }

    #[test]
    fn console_address_validation_allows_paths_but_rejects_unsafe_urls() {
        assert!(ConsoleDomainSetting::validate(&None).is_ok());
        for origin in [
            "http://console.example.com",
            "https://user:pass@console.example.com",
            "https://console.example.com?query=1",
            "https://console.example.com#fragment",
        ] {
            assert!(
                ConsoleDomainSetting::validate(&Some(origin.to_owned())).is_err(),
                "{origin}"
            );
        }
        assert!(
            ConsoleDomainSetting::validate(&Some("https://login.example.com/console/".to_owned()))
                .is_ok()
        );
    }
}
