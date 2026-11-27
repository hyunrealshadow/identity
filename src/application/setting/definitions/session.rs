use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::setting::{SettingSection, SettingValidationError};

/// Instance-wide session lifetimes, login interaction timeout, and recent
/// authentication freshness windows.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct SessionSettings {
    /// Hours a newly established or reauthenticated session stays valid.
    pub lifetime_hours: u32,
    /// Minutes a multi-factor authentication remains fresh for elevated actions.
    pub elevated_authentication_lifetime_minutes: u32,
    /// Minutes a sign-in remains fresh for ordinary recent-authentication checks.
    pub recent_authentication_lifetime_minutes: u32,
    /// Minutes an interactive login flow stays open before expiring.
    pub login_lifetime_minutes: u32,
}

impl Default for SessionSettings {
    fn default() -> Self {
        Self {
            lifetime_hours: 168,
            elevated_authentication_lifetime_minutes: 60,
            recent_authentication_lifetime_minutes: 5,
            login_lifetime_minutes: 5,
        }
    }
}

impl SessionSettings {
    #[must_use]
    pub const fn session_lifetime(&self) -> Duration {
        Duration::from_secs((self.lifetime_hours as u64) * 3_600)
    }

    #[must_use]
    pub const fn elevated_authentication_lifetime(&self) -> Duration {
        Duration::from_secs((self.elevated_authentication_lifetime_minutes as u64) * 60)
    }

    #[must_use]
    pub const fn recent_authentication_lifetime(&self) -> Duration {
        Duration::from_secs((self.recent_authentication_lifetime_minutes as u64) * 60)
    }

    #[must_use]
    pub const fn login_lifetime(&self) -> Duration {
        Duration::from_secs((self.login_lifetime_minutes as u64) * 60)
    }
}

impl SettingSection for SessionSettings {
    const PREFIX: &'static str = "auth.session";
    const OBJECT_FIELDS: &'static [&'static str] = &[];

    fn validate(&self) -> Result<(), SettingValidationError> {
        if self.lifetime_hours == 0 {
            return Err(SettingValidationError::new(
                "session lifetime must be at least 1 hour",
            ));
        }
        if self.elevated_authentication_lifetime_minutes == 0 {
            return Err(SettingValidationError::new(
                "elevated authentication lifetime must be at least 1 minute",
            ));
        }
        if self.recent_authentication_lifetime_minutes == 0 {
            return Err(SettingValidationError::new(
                "recent authentication lifetime must be at least 1 minute",
            ));
        }
        if self.login_lifetime_minutes == 0 {
            return Err(SettingValidationError::new(
                "login lifetime must be at least 1 minute",
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use serde_json::json;

    use super::SessionSettings;
    use crate::setting::{SettingChanges, SettingSection, SettingsSnapshot};

    #[test]
    fn defaults_convert_to_expected_durations() {
        let defaults = SessionSettings::default();
        assert_eq!(
            defaults.session_lifetime(),
            Duration::from_secs(7 * 24 * 3600)
        );
        assert_eq!(
            defaults.elevated_authentication_lifetime(),
            Duration::from_secs(60 * 60)
        );
        assert_eq!(
            defaults.recent_authentication_lifetime(),
            Duration::from_secs(5 * 60)
        );
        assert_eq!(defaults.login_lifetime(), Duration::from_secs(5 * 60));
    }

    #[test]
    fn binds_session_section_keys_and_validates_positive_values() {
        let settings = SessionSettings {
            lifetime_hours: 24,
            elevated_authentication_lifetime_minutes: 30,
            recent_authentication_lifetime_minutes: 10,
            login_lifetime_minutes: 15,
        };
        let snapshot = SettingsSnapshot::default().with_section(&settings);
        assert_eq!(snapshot.section::<SessionSettings>(), settings);

        let changes: Vec<_> = SettingChanges::default()
            .set_section(&settings)
            .unwrap()
            .into_iter()
            .collect();
        assert!(changes.contains(&("auth.session.lifetime_hours".to_owned(), json!(24))));

        for invalid in [
            SessionSettings {
                lifetime_hours: 0,
                ..settings
            },
            SessionSettings {
                elevated_authentication_lifetime_minutes: 0,
                ..settings
            },
            SessionSettings {
                recent_authentication_lifetime_minutes: 0,
                ..settings
            },
            SessionSettings {
                login_lifetime_minutes: 0,
                ..settings
            },
        ] {
            assert!(invalid.validate().is_err());
        }
    }
}
