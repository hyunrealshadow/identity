use crate::setting::SettingDefinition;

pub struct ConsentUrlSetting;

impl SettingDefinition for ConsentUrlSetting {
    type Value = Option<String>;
    const KEY: &'static str = "app.consent_url";

    fn default_value() -> Self::Value {
        None
    }
}
