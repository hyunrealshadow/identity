use std::collections::HashSet;
use std::sync::{Arc, RwLock};
use std::time::Duration;

use async_trait::async_trait;
use sea_orm::{ConnectionTrait, DatabaseBackend, DatabaseConnection, Statement};

use crate::{
    crypto::signing_algorithm::SigningAlgorithmDetectorImpl,
    database::repository::{
        key::KeyRepositoryImpl, key_jwk::KeyJwkRepositoryImpl, setting::SettingRepositoryImpl,
    },
};
use identity_application::{
    error::{AppError, codes::common::CommonErrorCode},
    key::runtime::{RuntimeKeyRing, RuntimeKeyRingProvider, RuntimeSigningKey},
    openid_connect::provider::SigningAlgorithmDetector,
    setting::runtime::{CachedSetting, RefreshableSetting, SettingProvider, SettingsRefresher},
};
use identity_domain::{
    auth::password::PasswordHashSetting,
    data_protection::KeyRing,
    key::{KeyData, KeyJwkRepository, repository::KeyRepository},
    setting::model::SettingDefinition,
    setting::{
        device_authorization::DeviceAuthorizationSetting,
        domain::DomainSetting,
        dynamic_registration::DynamicClientRegistrationSetting,
        installation::{
            InstallationFirstKeyOidSetting, InstallationFirstUserOidSetting,
            InstallationInitializedAtSetting, InstallationInitializedSetting, InstallationSetting,
            InstallationState,
        },
        login_domain::LoginDomainSetting,
    },
};

pub type AppPasswordHashSettingService = CachedSetting<PasswordHashSetting, SettingRepositoryImpl>;
pub type AppInstallationInitializedSettingService =
    CachedSetting<InstallationInitializedSetting, SettingRepositoryImpl>;
pub type AppDomainSettingService = CachedSetting<DomainSetting, SettingRepositoryImpl>;
pub type AppInstallationFirstUserOidSettingService =
    CachedSetting<InstallationFirstUserOidSetting, SettingRepositoryImpl>;
pub type AppInstallationFirstKeyOidSettingService =
    CachedSetting<InstallationFirstKeyOidSetting, SettingRepositoryImpl>;
pub type AppInstallationInitializedAtSettingService =
    CachedSetting<InstallationInitializedAtSetting, SettingRepositoryImpl>;
pub type AppInstallationSettingService = GroupedInstallationSettingProvider<SettingRepositoryImpl>;
pub type AppLoginDomainSettingService = CachedSetting<LoginDomainSetting, SettingRepositoryImpl>;
pub type AppDynamicClientRegistrationSettingService =
    CachedSetting<DynamicClientRegistrationSetting, SettingRepositoryImpl>;
pub type AppDeviceAuthorizationSettingService =
    CachedSetting<DeviceAuthorizationSetting, SettingRepositoryImpl>;

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
        let rows = db
            .query_all_raw(Statement::from_string(
                DatabaseBackend::Postgres,
                "SELECT DISTINCT origin FROM client_openid_connect_cors_origin".to_owned(),
            ))
            .await
            .map_err(|error| {
                AppError::from_code(CommonErrorCode::InternalError).with_source(error)
            })?;
        rows.into_iter()
            .map(|row| {
                row.try_get("", "origin").map_err(|error| {
                    AppError::from_code(CommonErrorCode::InternalError).with_source(error)
                })
            })
            .collect()
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
        "client_cors_origins"
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

pub struct CachedRuntimeKeyRingProvider {
    key_repo: Arc<dyn KeyRepository>,
    key_jwk_repo: Arc<dyn KeyJwkRepository>,
    signing_algorithm_detector: Arc<dyn SigningAlgorithmDetector>,
    value: RwLock<Arc<RuntimeKeyRing>>,
}

impl CachedRuntimeKeyRingProvider {
    pub async fn new(db: DatabaseConnection) -> Result<Self, AppError> {
        let provider = Self {
            key_repo: Arc::new(KeyRepositoryImpl::new(db.clone())),
            key_jwk_repo: Arc::new(KeyJwkRepositoryImpl::new(db)),
            signing_algorithm_detector: Arc::new(SigningAlgorithmDetectorImpl),
            value: RwLock::new(Arc::new(RuntimeKeyRing::new(KeyRing::new(vec![]), None))),
        };
        provider.refresh().await?;
        Ok(provider)
    }

    async fn refresh(&self) -> Result<(), AppError> {
        let span = tracing::info_span!("key.ring.refresh");
        let _entered = span.enter();
        let symmetric_keys = self.key_repo.list_decryptable_symmetric().await?;
        let asymmetric_keys = self.key_repo.list_active_asymmetric().await?;
        let mut signing_key = None;

        for key in asymmetric_keys {
            let KeyData::Asymmetric(data) = &key.data else {
                continue;
            };
            let Some(algorithm) = self
                .signing_algorithm_detector
                .detect(&key)
                .into_iter()
                .next()
            else {
                continue;
            };
            let Some(binding) = self
                .key_jwk_repo
                .find_active_by_key_oid_and_algorithm(key.oid, algorithm)
                .await?
            else {
                continue;
            };

            signing_key = Some(RuntimeSigningKey {
                key_id: uuid::Uuid::from(binding.oid).to_string(),
                private_key_pem: data.private_key.clone(),
                algorithm,
            });
            break;
        }

        let previous_signing_key = self
            .current_value()
            .signing_key()
            .map(|key| key.key_id.clone());
        let next_signing_key = signing_key.as_ref().map(|key| key.key_id.clone());
        let value = Arc::new(RuntimeKeyRing::new(
            KeyRing::new(symmetric_keys),
            signing_key,
        ));
        *self
            .value
            .write()
            .unwrap_or_else(|error| error.into_inner()) = value;
        if previous_signing_key != next_signing_key {
            use identity_application::observability::{BusinessEvent, EventValue};
            let mut event = BusinessEvent::business("key.ring.changed").outcome("applied");
            if let Some(key_id) = next_signing_key {
                event = event.attribute("key_id", EventValue::Text(key_id));
            }
            identity_application::observability::event_sink().emit(event);
        }
        Ok(())
    }
}

#[async_trait]
impl RuntimeKeyRingProvider for CachedRuntimeKeyRingProvider {
    fn current_value(&self) -> Arc<RuntimeKeyRing> {
        self.value
            .read()
            .unwrap_or_else(|error| error.into_inner())
            .clone()
    }

    async fn refresh_value(&self) -> Result<(), AppError> {
        self.refresh().await
    }
}

#[async_trait]
impl RefreshableSetting for CachedRuntimeKeyRingProvider {
    fn key(&self) -> &'static str {
        "runtime.key_ring"
    }

    async fn refresh_value(&self) -> Result<(), AppError> {
        self.refresh().await
    }
}

#[derive(Clone)]
pub struct GroupedInstallationSettingProvider<R> {
    initialized: Arc<CachedSetting<InstallationInitializedSetting, R>>,
    domain: Arc<CachedSetting<DomainSetting, R>>,
    first_user_oid: Arc<CachedSetting<InstallationFirstUserOidSetting, R>>,
    first_key_oid: Arc<CachedSetting<InstallationFirstKeyOidSetting, R>>,
    initialized_at: Arc<CachedSetting<InstallationInitializedAtSetting, R>>,
}

impl<R> GroupedInstallationSettingProvider<R>
where
    R: identity_domain::setting::repository::SettingRepository,
{
    fn new(
        initialized: Arc<CachedSetting<InstallationInitializedSetting, R>>,
        domain: Arc<CachedSetting<DomainSetting, R>>,
        first_user_oid: Arc<CachedSetting<InstallationFirstUserOidSetting, R>>,
        first_key_oid: Arc<CachedSetting<InstallationFirstKeyOidSetting, R>>,
        initialized_at: Arc<CachedSetting<InstallationInitializedAtSetting, R>>,
    ) -> Self {
        Self {
            initialized,
            domain,
            first_user_oid,
            first_key_oid,
            initialized_at,
        }
    }

    pub async fn refresh(&self) -> Result<(), AppError> {
        self.initialized.refresh_value().await?;
        self.domain.refresh_value().await?;
        self.first_user_oid.refresh_value().await?;
        self.first_key_oid.refresh_value().await?;
        self.initialized_at.refresh_value().await?;
        Ok(())
    }
}

impl<R> SettingProvider<InstallationSetting> for GroupedInstallationSettingProvider<R>
where
    R: identity_domain::setting::repository::SettingRepository,
{
    fn current_value(&self) -> Arc<InstallationState> {
        Arc::new(InstallationState {
            initialized: *self.initialized.current_value(),
            domain: self.domain.current_value().as_ref().clone(),
            first_user_oid: *self.first_user_oid.current_value().as_ref(),
            first_key_oid: *self.first_key_oid.current_value().as_ref(),
            initialized_at: *self.initialized_at.current_value().as_ref(),
        })
    }
}

#[async_trait]
impl<R> RefreshableSetting for GroupedInstallationSettingProvider<R>
where
    R: identity_domain::setting::repository::SettingRepository,
{
    fn key(&self) -> &'static str {
        InstallationSetting::KEY
    }

    async fn refresh_value(&self) -> Result<(), AppError> {
        self.initialized.refresh_value().await?;
        self.domain.refresh_value().await?;
        self.first_user_oid.refresh_value().await?;
        self.first_key_oid.refresh_value().await?;
        self.initialized_at.refresh_value().await?;
        Ok(())
    }
}

#[derive(Clone)]
pub struct AppRuntimeSettings {
    password_hash_setting: Arc<AppPasswordHashSettingService>,
    installation_setting: Arc<AppInstallationSettingService>,
    installation_initialized_setting: Arc<AppInstallationInitializedSettingService>,
    domain_setting: Arc<AppDomainSettingService>,
    installation_first_user_oid_setting: Arc<AppInstallationFirstUserOidSettingService>,
    installation_first_key_oid_setting: Arc<AppInstallationFirstKeyOidSettingService>,
    installation_initialized_at_setting: Arc<AppInstallationInitializedAtSettingService>,
    dynamic_client_registration_setting: Arc<AppDynamicClientRegistrationSettingService>,
    login_domain_setting: Arc<AppLoginDomainSettingService>,
    device_authorization_setting: Arc<AppDeviceAuthorizationSettingService>,
    cors_origins: Arc<CachedCorsOrigins>,
    key_ring: Arc<CachedRuntimeKeyRingProvider>,
}

impl AppRuntimeSettings {
    pub async fn from_db(db: DatabaseConnection) -> Result<Self, AppError> {
        let initialized = Arc::new(
            AppInstallationInitializedSettingService::new(SettingRepositoryImpl::new(db.clone()))
                .await?,
        );
        let domain =
            Arc::new(AppDomainSettingService::new(SettingRepositoryImpl::new(db.clone())).await?);
        let first_user_oid = Arc::new(
            AppInstallationFirstUserOidSettingService::new(SettingRepositoryImpl::new(db.clone()))
                .await?,
        );
        let first_key_oid = Arc::new(
            AppInstallationFirstKeyOidSettingService::new(SettingRepositoryImpl::new(db.clone()))
                .await?,
        );
        let initialized_at = Arc::new(
            AppInstallationInitializedAtSettingService::new(SettingRepositoryImpl::new(db.clone()))
                .await?,
        );

        Ok(Self {
            password_hash_setting: Arc::new(
                AppPasswordHashSettingService::new(SettingRepositoryImpl::new(db.clone())).await?,
            ),
            installation_setting: Arc::new(GroupedInstallationSettingProvider::new(
                Arc::clone(&initialized),
                Arc::clone(&domain),
                Arc::clone(&first_user_oid),
                Arc::clone(&first_key_oid),
                Arc::clone(&initialized_at),
            )),
            installation_initialized_setting: initialized,
            domain_setting: domain,
            installation_first_user_oid_setting: first_user_oid,
            installation_first_key_oid_setting: first_key_oid,
            installation_initialized_at_setting: initialized_at,
            dynamic_client_registration_setting: Arc::new(
                AppDynamicClientRegistrationSettingService::new(SettingRepositoryImpl::new(
                    db.clone(),
                ))
                .await?,
            ),
            login_domain_setting: Arc::new(
                AppLoginDomainSettingService::new(SettingRepositoryImpl::new(db.clone())).await?,
            ),
            device_authorization_setting: Arc::new(
                AppDeviceAuthorizationSettingService::new(SettingRepositoryImpl::new(db.clone()))
                    .await?,
            ),
            cors_origins: Arc::new(CachedCorsOrigins::new(db.clone()).await?),
            key_ring: Arc::new(CachedRuntimeKeyRingProvider::new(db.clone()).await?),
        })
    }

    pub fn spawn_refresh_task(&self, refresh_interval: Duration) {
        let mut refresher = SettingsRefresher::new(refresh_interval);
        refresher.register(Arc::clone(&self.password_hash_setting));
        refresher.register(Arc::clone(&self.installation_initialized_setting));
        refresher.register(Arc::clone(&self.domain_setting));
        refresher.register(Arc::clone(&self.login_domain_setting));
        refresher.register(Arc::clone(&self.installation_first_user_oid_setting));
        refresher.register(Arc::clone(&self.installation_first_key_oid_setting));
        refresher.register(Arc::clone(&self.installation_initialized_at_setting));
        refresher.register(Arc::clone(&self.dynamic_client_registration_setting));
        refresher.register(Arc::clone(&self.device_authorization_setting));
        refresher.register(Arc::clone(&self.cors_origins));
        refresher.register(Arc::clone(&self.key_ring));
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
    pub fn installation_initialized(&self) -> Arc<AppInstallationInitializedSettingService> {
        Arc::clone(&self.installation_initialized_setting)
    }

    #[must_use]
    pub fn domain(&self) -> Arc<AppDomainSettingService> {
        Arc::clone(&self.domain_setting)
    }

    /// Origin of the login application, recorded during installation.
    #[must_use]
    pub fn login_domain(&self) -> Arc<AppLoginDomainSettingService> {
        Arc::clone(&self.login_domain_setting)
    }

    #[must_use]
    pub fn installation_first_user_oid(&self) -> Arc<AppInstallationFirstUserOidSettingService> {
        Arc::clone(&self.installation_first_user_oid_setting)
    }

    #[must_use]
    pub fn installation_first_key_oid(&self) -> Arc<AppInstallationFirstKeyOidSettingService> {
        Arc::clone(&self.installation_first_key_oid_setting)
    }

    #[must_use]
    pub fn installation_initialized_at(&self) -> Arc<AppInstallationInitializedAtSettingService> {
        Arc::clone(&self.installation_initialized_at_setting)
    }

    #[must_use]
    pub fn dynamic_client_registration(&self) -> Arc<AppDynamicClientRegistrationSettingService> {
        Arc::clone(&self.dynamic_client_registration_setting)
    }

    #[must_use]
    pub fn device_authorization(&self) -> Arc<AppDeviceAuthorizationSettingService> {
        Arc::clone(&self.device_authorization_setting)
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
