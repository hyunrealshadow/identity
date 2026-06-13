use crate::setting::SettingDefinition;

pub struct AuthUiEnabledSetting;

impl SettingDefinition for AuthUiEnabledSetting {
    type Value = bool;
    const KEY: &'static str = "app.auth_ui.enabled";

    fn default_value() -> Self::Value {
        true
    }
}
