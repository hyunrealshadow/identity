use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::setting::{SettingSection, SettingValidationError};

/// Installation state bound from separate `app.installation.*` settings.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct InstallationSettings {
    pub initialized: bool,
    pub initialized_at: Option<DateTime<Utc>>,
}

impl SettingSection for InstallationSettings {
    const PREFIX: &'static str = "app.installation";

    fn validate(&self) -> Result<(), SettingValidationError> {
        if let Some(v) = self.initialized_at
            && v.timestamp() < 0
        {
            return Err(SettingValidationError::new(
                "installation timestamp is invalid",
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use chrono::{TimeZone, Utc};
    use serde_json::json;

    use super::InstallationSettings;
    use crate::setting::{SettingChanges, SettingsSnapshot};

    #[test]
    fn binds_every_installation_key() {
        let installation = InstallationSettings {
            initialized: true,
            initialized_at: Some(Utc.timestamp_opt(1_700_000_000, 0).unwrap()),
        };

        let snapshot = SettingsSnapshot::default().with_section(&installation);

        assert_eq!(snapshot.section::<InstallationSettings>(), installation);
        assert_eq!(
            SettingChanges::default()
                .set_section(&installation)
                .unwrap()
                .into_iter()
                .collect::<Vec<_>>(),
            vec![
                ("app.installation.initialized".to_owned(), json!(true)),
                (
                    "app.installation.initialized_at".to_owned(),
                    json!(installation.initialized_at)
                ),
            ]
        );
    }
}
