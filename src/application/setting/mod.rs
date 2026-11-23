pub mod application_origins;
pub mod binding;
pub mod definition;
mod definitions;
pub mod email;
pub mod error;
pub mod management;
pub mod runtime;

pub use binding::{SettingChanges, SettingRegistry, SettingsSnapshot, SettingsSource};
pub use definition::{SettingDefinition, SettingSection, SettingValidationError, SettingValue};
pub use definitions::{
    AppSettings, BreachedPasswordCheckEnabledSetting, ConsoleClientIdSetting, ConsoleDomainSetting,
    DeviceAuthorizationSettings, DomainSetting, DynamicRegistrationSettings, EmailDeliverySettings,
    EmailSignInEnabledSetting, EmailTemplatesSetting, IdentifierEnumerationAllowedSetting,
    InstallationSettings, LoginClientIdSetting, LoginDomainSetting, OpenIdConnectSettings,
    PasswordHashSetting,
};
pub use definitions::{
    ProtectedSecret, PushedAuthorizationSettings, SmtpAuthentication, SmtpSecurity, Xoauth2Grant,
    Xoauth2Settings,
};
pub use error::SettingError;
