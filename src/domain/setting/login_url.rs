use crate::setting::SettingDefinition;

pub struct LoginUrlSetting;

impl SettingDefinition for LoginUrlSetting {
    type Value = Option<String>;
    const KEY: &'static str = "app.login_url";

    fn default_value() -> Self::Value {
        None
    }
}
