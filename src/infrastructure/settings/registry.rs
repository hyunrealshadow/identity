use identity_application::setting::{
    BreachedPasswordCheckEnabledSetting, ConsoleClientIdSetting, ConsoleDomainSetting,
    DomainSetting, EmailDeliverySettings, EmailPolicySettings, EmailSignInEnabledSetting,
    EmailTemplatesSetting, IdentifierEnumerationAllowedSetting, InstallationSettings,
    LockoutDurationMinutesSetting, LoginClientIdSetting, LoginDomainSetting,
    MaxFailedAttemptsSetting, OpenIdConnectSettings, PasswordHashSetting,
    PasswordHistoryCountSetting, PasswordMaxAgeDaysSetting, PasswordMinLengthSetting,
    PasswordResetEnabledSetting, RegistrationEnabledSetting, SessionSettings, SettingRegistry,
};

/// Settings persisted by this application, shared by the runtime loader and
/// the defaults seed.
pub(crate) fn setting_registry() -> SettingRegistry {
    SettingRegistry::default()
        .register::<PasswordHashSetting>()
        .register::<BreachedPasswordCheckEnabledSetting>()
        .register::<IdentifierEnumerationAllowedSetting>()
        .register::<EmailSignInEnabledSetting>()
        .register::<PasswordResetEnabledSetting>()
        .register::<RegistrationEnabledSetting>()
        .register::<PasswordMaxAgeDaysSetting>()
        .register::<PasswordHistoryCountSetting>()
        .register::<PasswordMinLengthSetting>()
        .register::<MaxFailedAttemptsSetting>()
        .register::<LockoutDurationMinutesSetting>()
        .register::<EmailTemplatesSetting>()
        .register::<DomainSetting>()
        .register::<LoginDomainSetting>()
        .register::<ConsoleDomainSetting>()
        .register::<LoginClientIdSetting>()
        .register::<ConsoleClientIdSetting>()
        .register_section::<SessionSettings>()
        .register_section::<InstallationSettings>()
        .register_section::<OpenIdConnectSettings>()
        .register_section::<EmailDeliverySettings>()
        .register_section::<EmailPolicySettings>()
}
