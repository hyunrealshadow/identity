use std::{sync::Arc, time::Duration};

use sea_orm::DatabaseConnection;

use identity_application::{error::AppError, setting::runtime::SettingsRefresher};

use super::{
    key_ring::CachedRuntimeKeyRingProvider, openid_connect::CachedCorsOrigins,
    ordinary::OrdinarySettings,
};

#[derive(Clone)]
pub struct AppRuntimeSettings {
    ordinary: Arc<OrdinarySettings>,
    cors_origins: Arc<CachedCorsOrigins>,
    key_ring: Arc<CachedRuntimeKeyRingProvider>,
}

impl AppRuntimeSettings {
    pub async fn from_db(db: DatabaseConnection) -> Result<Self, AppError> {
        Ok(Self {
            ordinary: Arc::new(OrdinarySettings::new(db.clone()).await?),
            cors_origins: Arc::new(CachedCorsOrigins::new(db.clone()).await?),
            key_ring: Arc::new(CachedRuntimeKeyRingProvider::new(db).await?),
        })
    }

    pub fn spawn_refresh_task(&self, refresh_interval: Duration) {
        let mut refresher = SettingsRefresher::new(refresh_interval);
        refresher.register(Arc::clone(&self.ordinary));
        refresher.register(Arc::clone(&self.cors_origins));
        refresher.register(Arc::clone(&self.key_ring));
        refresher.spawn_detached();
    }

    #[must_use]
    pub fn ordinary(&self) -> Arc<OrdinarySettings> {
        Arc::clone(&self.ordinary)
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
