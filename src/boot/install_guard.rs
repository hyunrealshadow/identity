use std::io::Error as IoError;

use identity_application::setting::{InstallationSettings, SettingsSource};
use identity_infrastructure::{
    config::DatabaseConfig,
    database::install_lock::{InstallLockGuard, try_acquire_install_lock},
    settings::AppRuntimeSettings,
};
use tracing::info;

use super::AppResult;

pub async fn ensure_install_startup_guard(
    database: &DatabaseConfig,
    settings: &AppRuntimeSettings,
) -> AppResult<Option<InstallLockGuard>> {
    let initialized = || {
        settings
            .store()
            .snapshot()
            .section::<InstallationSettings>()
            .initialized
    };
    if initialized() {
        return Ok(None);
    }

    if let Some(guard) = try_acquire_install_lock(database).await? {
        info!("installation lock acquired for this instance");
        return Ok(Some(guard));
    }

    settings.store().refresh().await?;
    if initialized() {
        return Ok(None);
    }

    Err(Box::new(IoError::other(
        "installation is in progress on another pod; refusing startup",
    )))
}
