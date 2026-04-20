use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::domain::setting::{SettingDefinition, SettingValidationError};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct InstallationState {
    pub initialized: bool,
    pub domain: Option<String>,
    pub first_user_oid: Option<Uuid>,
    pub first_key_oid: Option<Uuid>,
    pub initialized_at: Option<DateTime<Utc>>,
}

pub struct InstallationSetting;

impl SettingDefinition for InstallationSetting {
    type Value = InstallationState;

    const KEY: &'static str = "app.installation";

    fn default_value() -> Self::Value {
        InstallationState::default()
    }

    fn validate(value: &Self::Value) -> Result<(), SettingValidationError> {
        if !value.initialized {
            return Ok(());
        }

        if value
            .domain
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .is_none()
        {
            return Err(SettingValidationError::new(
                "installation domain is required once initialized",
            ));
        }

        if value.first_user_oid.is_none() {
            return Err(SettingValidationError::new(
                "first user oid is required once initialized",
            ));
        }

        if value.first_key_oid.is_none() {
            return Err(SettingValidationError::new(
                "first key oid is required once initialized",
            ));
        }

        if value.initialized_at.is_none() {
            return Err(SettingValidationError::new(
                "initialized_at is required once initialized",
            ));
        }

        Ok(())
    }
}
