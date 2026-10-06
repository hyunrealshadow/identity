use std::{sync::Arc, time::Duration};

use identity_application::error::AppError;
use sea_orm::DatabaseConnection;

use super::{
    key_ring::CachedRuntimeKeyRingProvider, openid_connect::CachedCorsOrigins,
    refresher::SettingsRefresher, setting_registry, store::SettingsStore,
};

#[derive(Clone)]
pub struct AppRuntimeSettings {
    store: Arc<SettingsStore>,
    cors_origins: Arc<CachedCorsOrigins>,
    key_ring: Arc<CachedRuntimeKeyRingProvider>,
}

impl AppRuntimeSettings {
    pub async fn from_db(db: DatabaseConnection) -> Result<Self, AppError> {
        Ok(Self {
            store: Arc::new(SettingsStore::new(db.clone(), setting_registry()).await?),
            cors_origins: Arc::new(CachedCorsOrigins::new(db.clone()).await?),
            key_ring: Arc::new(CachedRuntimeKeyRingProvider::new(db).await?),
        })
    }

    pub fn spawn_refresh_task(&self, refresh_interval: Duration) {
        let mut refresher = SettingsRefresher::new(refresh_interval);
        refresher.register(Arc::clone(&self.store));
        refresher.register(Arc::clone(&self.cors_origins));
        refresher.register(Arc::clone(&self.key_ring));
        refresher.spawn_detached();
    }

    #[must_use]
    pub fn store(&self) -> Arc<SettingsStore> {
        Arc::clone(&self.store)
    }

    #[must_use]
    pub fn cors_origins(&self) -> Arc<CachedCorsOrigins> {
        Arc::clone(&self.cors_origins)
    }

    #[must_use]
    pub fn key_ring(&self) -> Arc<CachedRuntimeKeyRingProvider> {
        Arc::clone(&self.key_ring)
    }
}
