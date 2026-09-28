use std::sync::Arc;

use crate::auth::password::HashOptions;

use super::{
    DeviceAuthorizationSetting, DeviceAuthorizationSettings, DynamicClientRegistrationSetting,
    DynamicClientRegistrationSettings, InstallationState, LoginDomainSetting, LoginDomainSettings,
    PasswordHashSetting, SettingDefinition,
};

/// A consistent view of the ordinary settings, refreshed as one unit.
#[derive(PartialEq)]
pub struct OrdinarySettingsSnapshot {
    pub password_hash_options: HashOptions,
    pub installation: InstallationState,
    pub login_domain: Option<String>,
    pub dynamic_client_registration: bool,
    pub device_authorization: DeviceAuthorizationSettings,
}

impl Default for OrdinarySettingsSnapshot {
    fn default() -> Self {
        Self {
            password_hash_options: PasswordHashSetting::default_value(),
            installation: InstallationState::default(),
            login_domain: LoginDomainSetting::default_value(),
            dynamic_client_registration: DynamicClientRegistrationSetting::default_value(),
            device_authorization: DeviceAuthorizationSetting::default_value(),
        }
    }
}

pub trait OrdinarySettingsProvider: Send + Sync {
    fn current_snapshot(&self) -> Arc<OrdinarySettingsSnapshot>;
}

/// A typed view of a currently loaded configuration value.
pub trait Setting<T>: Send + Sync {
    fn current_value(&self) -> T;
}

pub trait OrdinarySettingValue: Clone + Send + Sync + 'static {
    fn from_snapshot(snapshot: &OrdinarySettingsSnapshot) -> Self;
}

impl<V, P> Setting<V> for P
where
    V: OrdinarySettingValue,
    P: OrdinarySettingsProvider + ?Sized,
{
    fn current_value(&self) -> V {
        V::from_snapshot(&self.current_snapshot())
    }
}

impl OrdinarySettingValue for HashOptions {
    fn from_snapshot(snapshot: &OrdinarySettingsSnapshot) -> Self {
        snapshot.password_hash_options.clone()
    }
}

impl OrdinarySettingValue for InstallationState {
    fn from_snapshot(snapshot: &OrdinarySettingsSnapshot) -> Self {
        snapshot.installation.clone()
    }
}

impl OrdinarySettingValue for LoginDomainSettings {
    fn from_snapshot(snapshot: &OrdinarySettingsSnapshot) -> Self {
        Self {
            value: snapshot.login_domain.clone(),
        }
    }
}

impl OrdinarySettingValue for DynamicClientRegistrationSettings {
    fn from_snapshot(snapshot: &OrdinarySettingsSnapshot) -> Self {
        Self {
            enabled: snapshot.dynamic_client_registration,
        }
    }
}

impl OrdinarySettingValue for DeviceAuthorizationSettings {
    fn from_snapshot(snapshot: &OrdinarySettingsSnapshot) -> Self {
        snapshot.device_authorization.clone()
    }
}
