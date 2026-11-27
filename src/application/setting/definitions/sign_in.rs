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

/// Consecutive failed attempts before locking an account or ending an OTP
/// login flow.
pub struct MaxFailedAttemptsSetting;

impl SettingDefinition for MaxFailedAttemptsSetting {
    type Value = u32;

    const KEY: &'static str = "auth.login.max_failed_attempts";

    fn default_value() -> Self::Value {
        5
    }
}

/// Minutes an account stays locked after reaching the failed-attempt limit.
pub struct LockoutDurationMinutesSetting;

impl SettingDefinition for LockoutDurationMinutesSetting {
    type Value = u32;

    const KEY: &'static str = "auth.login.lockout_duration_minutes";

    fn default_value() -> Self::Value {
        15
    }
}

/// Whether someone who forgot their password may replace it from the
/// sign-in flow with a one-time link sent to the account's verified email
/// address. Offered only while email delivery is configured.
pub struct PasswordResetEnabledSetting;

impl SettingDefinition for PasswordResetEnabledSetting {
    type Value = bool;

    const KEY: &'static str = "auth.login.password_reset_enabled";

    fn default_value() -> Self::Value {
        true
    }
}

/// Whether someone without an account may create one from the sign-in flow.
/// The email address is verified with an emailed link before the account
/// exists, so it is offered only while email delivery is configured.
pub struct RegistrationEnabledSetting;

impl SettingDefinition for RegistrationEnabledSetting {
    type Value = bool;

    const KEY: &'static str = "auth.login.registration_enabled";

    fn default_value() -> Self::Value {
        false
    }
}
