use std::sync::Arc;
use std::time::Duration;

use sea_orm::DatabaseConnection;

use crate::database::repository::setting::SettingRepositoryImpl;
use identity_application::{
    error::AppError,
    setting::runtime::{CachedSetting, SettingsRefresher},
};
use identity_domain::{
    auth::password::PasswordHashSetting,
    setting::{
        dynamic_registration::DynamicClientRegistrationSetting, installation::InstallationSetting,
    },
};

pub type AppPasswordHashSettingService = CachedSetting<PasswordHashSetting, SettingRepositoryImpl>;
pub type AppInstallationSettingService = CachedSetting<InstallationSetting, SettingRepositoryImpl>;
pub type AppDynamicClientRegistrationSettingService =
    CachedSetting<DynamicClientRegistrationSetting, SettingRepositoryImpl>;

#[derive(Clone)]
pub struct AppRuntimeSettings {
    password_hash_setting: Arc<AppPasswordHashSettingService>,
    installation_setting: Arc<AppInstallationSettingService>,
    dynamic_client_registration_setting: Arc<AppDynamicClientRegistrationSettingService>,
}

impl AppRuntimeSettings {
    pub async fn from_db(db: DatabaseConnection) -> Result<Self, AppError> {
        Ok(Self {
            password_hash_setting: Arc::new(
                AppPasswordHashSettingService::new(SettingRepositoryImpl::new(db.clone())).await?,
            ),
            installation_setting: Arc::new(
                AppInstallationSettingService::new(SettingRepositoryImpl::new(db.clone())).await?,
            ),
            dynamic_client_registration_setting: Arc::new(
                AppDynamicClientRegistrationSettingService::new(SettingRepositoryImpl::new(db))
                    .await?,
            ),
        })
    }

    pub fn spawn_refresh_task(&self, refresh_interval: Duration) {
        let mut refresher = SettingsRefresher::new(refresh_interval);
        refresher.register(Arc::clone(&self.password_hash_setting));
        refresher.register(Arc::clone(&self.installation_setting));
        refresher.register(Arc::clone(&self.dynamic_client_registration_setting));
        refresher.spawn_detached();
    }

    #[must_use]
    pub fn password_hash_options(&self) -> Arc<AppPasswordHashSettingService> {
        Arc::clone(&self.password_hash_setting)
    }

    #[must_use]
    pub fn installation(&self) -> Arc<AppInstallationSettingService> {
        Arc::clone(&self.installation_setting)
    }

    #[must_use]
    pub fn dynamic_client_registration(&self) -> Arc<AppDynamicClientRegistrationSettingService> {
        Arc::clone(&self.dynamic_client_registration_setting)
    }
}
