use std::collections::HashSet;
use std::sync::{Arc, RwLock};

use crate::database::entity::client_openid_connect_cors_origin;
use async_trait::async_trait;
use identity_application::{
    error::{AppError, codes::common::CommonErrorCode},
    setting::runtime::RefreshableSetting,
};
use sea_orm::{DatabaseConnection, EntityTrait, QuerySelect};

/// A global, read-only setting derived from per-client CORS origin rows.
pub struct CachedCorsOrigins {
    db: DatabaseConnection,
    origins: RwLock<Arc<HashSet<String>>>,
}

impl CachedCorsOrigins {
    pub async fn new(db: DatabaseConnection) -> Result<Self, AppError> {
        let origins = Self::load(&db).await?;
        Ok(Self {
            db,
            origins: RwLock::new(Arc::new(origins)),
        })
    }

    async fn load(db: &DatabaseConnection) -> Result<HashSet<String>, AppError> {
        client_openid_connect_cors_origin::Entity::find()
            .select_only()
            .column(client_openid_connect_cors_origin::Column::Origin)
            .distinct()
            .into_tuple::<String>()
            .all(db)
            .await
            .map(|origins| origins.into_iter().collect())
            .map_err(|error| AppError::from_code(CommonErrorCode::InternalError).with_source(error))
    }

    #[must_use]
    pub fn allows(&self, origin: &str) -> bool {
        self.origins
            .read()
            .unwrap_or_else(|error| error.into_inner())
            .contains(origin)
    }
}

#[async_trait]
impl RefreshableSetting for CachedCorsOrigins {
    fn key(&self) -> &'static str {
        "openid_connect.cors_origins"
    }

    async fn refresh_value(&self) -> Result<(), AppError> {
        let latest = Self::load(&self.db).await?;
        let mut origins = self
            .origins
            .write()
            .unwrap_or_else(|error| error.into_inner());
        if origins.as_ref() != &latest {
            *origins = Arc::new(latest);
        }
        Ok(())
    }
}

#[cfg(test)]
mod cors_origin_tests {
    use std::collections::BTreeMap;

    use identity_application::setting::runtime::RefreshableSetting;
    use sea_orm::{DatabaseBackend, MockDatabase, Value};

    use super::CachedCorsOrigins;

    #[tokio::test]
    async fn reloads_origins_from_derived_table() {
        let row = |origin: &str| {
            BTreeMap::from([("origin".to_owned(), Value::String(Some(origin.to_owned())))])
        };
        let db = MockDatabase::new(DatabaseBackend::Postgres)
            .append_query_results([[row("https://first.example")]])
            .append_query_results([[row("http://localhost:3000")]])
            .into_connection();
        let cache = CachedCorsOrigins::new(db).await.unwrap();
        assert!(cache.allows("https://first.example"));
        assert!(!cache.allows("http://localhost:3000"));

        cache.refresh_value().await.unwrap();
        assert!(!cache.allows("https://first.example"));
        assert!(cache.allows("http://localhost:3000"));
    }
}
