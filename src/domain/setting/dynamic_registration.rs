use crate::setting::SettingDefinition;

pub struct DynamicClientRegistrationSetting;

impl SettingDefinition for DynamicClientRegistrationSetting {
    type Value = bool;

    const KEY: &'static str = "openid_connect.dynamic_registration.enabled";

    fn default_value() -> Self::Value {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::DynamicClientRegistrationSetting;
    use crate::setting::SettingDefinition;

    #[test]
    fn dynamic_registration_is_disabled_by_default() {
        assert!(!DynamicClientRegistrationSetting::default_value());
    }
}
