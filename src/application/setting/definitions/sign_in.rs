use crate::setting::SettingDefinition;

/// Whether sign-in may reveal that an entered email or username has no
/// account. When disallowed, every identifier continues to the password step
/// and a failed password does not say which of the two was wrong.
pub struct IdentifierEnumerationAllowedSetting;

impl SettingDefinition for IdentifierEnumerationAllowedSetting {
    type Value = bool;

    const KEY: &'static str = "auth.login.identifier_enumeration_allowed";

    fn default_value() -> Self::Value {
        true
    }
}
