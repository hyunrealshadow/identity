use identity_application::setting::{
    BreachedPasswordCheckEnabledSetting, ConsoleClientIdSetting, ConsoleDomainSetting,
    DomainSetting, EmailDeliverySettings, EmailSignInEnabledSetting, EmailTemplatesSetting,
    IdentifierEnumerationAllowedSetting, InstallationSettings, LoginClientIdSetting,
    LoginDomainSetting, OpenIdConnectSettings, PasswordHashSetting, PasswordResetEnabledSetting,
    SettingRegistry,
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
        .register::<EmailTemplatesSetting>()
        .register::<DomainSetting>()
        .register::<LoginDomainSetting>()
        .register::<ConsoleDomainSetting>()
        .register::<LoginClientIdSetting>()
        .register::<ConsoleClientIdSetting>()
        .register_section::<InstallationSettings>()
        .register_section::<OpenIdConnectSettings>()
        .register_section::<EmailDeliverySettings>()
}
