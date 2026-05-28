use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::setting::{SettingDefinition, SettingValidationError};

// --- Per-field setting definitions (flat storage) ---

pub struct InstallationInitializedSetting;
impl SettingDefinition for InstallationInitializedSetting {
    type Value = bool;
    const KEY: &'static str = "app.installation.initialized";
    fn default_value() -> bool {
        false
    }
}

pub struct InstallationDomainSetting;
impl SettingDefinition for InstallationDomainSetting {
    type Value = Option<String>;
    const KEY: &'static str = "app.installation.domain";
    fn default_value() -> Option<String> {
        None
    }
}

pub struct InstallationFirstUserOidSetting;
impl SettingDefinition for InstallationFirstUserOidSetting {
    type Value = Option<Uuid>;
    const KEY: &'static str = "app.installation.first_user_oid";
    fn default_value() -> Option<Uuid> {
        None
    }
}

pub struct InstallationFirstKeyOidSetting;
impl SettingDefinition for InstallationFirstKeyOidSetting {
    type Value = Option<Uuid>;
    const KEY: &'static str = "app.installation.first_key_oid";
    fn default_value() -> Option<Uuid> {
        None
    }
}

pub struct InstallationInitializedAtSetting;
impl SettingDefinition for InstallationInitializedAtSetting {
    type Value = Option<DateTime<Utc>>;
    const KEY: &'static str = "app.installation.initialized_at";
    fn default_value() -> Option<DateTime<Utc>> {
        None
    }
    fn validate(value: &Self::Value) -> Result<(), SettingValidationError> {
        if value.is_none_or(|v| v.timestamp() < 0) {
            return Err(SettingValidationError::new(
                "installation timestamp is invalid",
            ));
        }
        Ok(())
    }
}

// --- Grouped read-view struct (for backward-compatible consumers) ---

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct InstallationState {
    pub initialized: bool,
    pub domain: Option<String>,
    pub first_user_oid: Option<Uuid>,
    pub first_key_oid: Option<Uuid>,
    pub initialized_at: Option<DateTime<Utc>>,
}

/// Group-level setting that is assembled from the 5 per-field flat settings.
/// Its KEY is unused for storage (each field has its own KEY). A custom
/// provider implementation reads from the 5 flat `CachedSetting`s and
/// assembles an `InstallationState`.
pub struct InstallationSetting;

impl SettingDefinition for InstallationSetting {
    type Value = InstallationState;

    const KEY: &'static str = "app.installation";

    fn default_value() -> Self::Value {
        InstallationState::default()
    }
}
