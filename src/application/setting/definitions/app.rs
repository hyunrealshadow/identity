use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::setting::{SettingDefinition, SettingSection};

/// Where this installation and its login application are served, as given
/// during installation.
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
    /// Built-in OAuth client used by the login application.
    pub login_client_id: Option<Uuid>,
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

pub struct LoginClientIdSetting;

impl SettingDefinition for LoginClientIdSetting {
    type Value = Option<Uuid>;
    const KEY: &'static str = "app.login_client_id";

    fn default_value() -> Self::Value {
        None
    }
}

#[cfg(test)]
mod tests {
    use uuid::Uuid;

    use super::{AppSettings, DomainSetting, LoginClientIdSetting, LoginDomainSetting};
    use crate::setting::{InstallationSettings, SettingsSnapshot};

    #[test]
    fn app_fields_and_installation_rows_are_read_independently() {
        let app = AppSettings {
            domain: Some("identity.example.com".to_owned()),
            login_domain: Some("https://login.example.com".to_owned()),
            login_client_id: Some(Uuid::new_v4()),
        };
        let installation = InstallationSettings {
            initialized: true,
            ..InstallationSettings::default()
        };

        let snapshot = SettingsSnapshot::default()
            .with_section(&app)
            .with_section(&installation);

        assert_eq!(snapshot.section::<AppSettings>(), app);
        assert_eq!(snapshot.get::<DomainSetting>(), app.domain);
        assert_eq!(snapshot.get::<LoginDomainSetting>(), app.login_domain);
        assert_eq!(snapshot.get::<LoginClientIdSetting>(), app.login_client_id);
        assert_eq!(snapshot.section::<InstallationSettings>(), installation);
    }
}
