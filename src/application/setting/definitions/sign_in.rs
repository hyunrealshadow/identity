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

/// Whether an account with a verified email address may sign in with a
/// one-time code or link sent to it, instead of its password. Offered only
/// while email delivery is configured.
pub struct EmailSignInEnabledSetting;

impl SettingDefinition for EmailSignInEnabledSetting {
    type Value = bool;

    const KEY: &'static str = "auth.login.email_sign_in_enabled";

    fn default_value() -> Self::Value {
        false
    }
}
