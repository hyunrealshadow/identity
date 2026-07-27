use std::sync::{Arc, RwLock};
use std::time::Duration;

use async_trait::async_trait;
use sea_orm::DatabaseConnection;

use crate::{
    crypto::signing_algorithm::SigningAlgorithmDetectorImpl,
    database::repository::{
        key::KeyRepositoryImpl, key_jwk::KeyJwkRepositoryImpl, setting::SettingRepositoryImpl,
    },
};
use identity_application::{
    error::AppError,
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
        consent_url::ConsentUrlSetting,
        dynamic_registration::DynamicClientRegistrationSetting,
        installation::{
            InstallationDomainSetting, InstallationFirstKeyOidSetting,
            InstallationFirstUserOidSetting, InstallationInitializedAtSetting,
            InstallationInitializedSetting, InstallationSetting, InstallationState,
        },
        login_url::LoginUrlSetting,
    },
};

pub type AppPasswordHashSettingService = CachedSetting<PasswordHashSetting, SettingRepositoryImpl>;
pub type AppInstallationInitializedSettingService =
    CachedSetting<InstallationInitializedSetting, SettingRepositoryImpl>;
pub type AppInstallationDomainSettingService =
    CachedSetting<InstallationDomainSetting, SettingRepositoryImpl>;
pub type AppInstallationFirstUserOidSettingService =
    CachedSetting<InstallationFirstUserOidSetting, SettingRepositoryImpl>;
pub type AppInstallationFirstKeyOidSettingService =
    CachedSetting<InstallationFirstKeyOidSetting, SettingRepositoryImpl>;
pub type AppInstallationInitializedAtSettingService =
    CachedSetting<InstallationInitializedAtSetting, SettingRepositoryImpl>;
pub type AppInstallationSettingService = GroupedInstallationSettingProvider<SettingRepositoryImpl>;
pub type AppDynamicClientRegistrationSettingService =
    CachedSetting<DynamicClientRegistrationSetting, SettingRepositoryImpl>;
pub type AppLoginUrlSettingService = CachedSetting<LoginUrlSetting, SettingRepositoryImpl>;
pub type AppConsentUrlSettingService = CachedSetting<ConsentUrlSetting, SettingRepositoryImpl>;

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
        let symmetric_keys = self.key_repo.list_available_symmetric().await?;
        let asymmetric_keys = self.key_repo.list_available_asymmetric().await?;
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
                .find_active_by_key_oid_and_algorithm(key.oid, algorithm.as_str())
                .await?
            else {
                continue;
            };

            signing_key = Some(RuntimeSigningKey {
                key_id: uuid::Uuid::from(binding.oid).to_string(),
                private_key_pem: data.private_key.clone(),
                algorithm: algorithm.as_str().to_owned(),
            });
            break;
        }

        let value = Arc::new(RuntimeKeyRing::new(
            KeyRing::new(symmetric_keys),
            signing_key,
        ));
        *self
            .value
            .write()
            .unwrap_or_else(|error| error.into_inner()) = value;
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
    domain: Arc<CachedSetting<InstallationDomainSetting, R>>,
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
        domain: Arc<CachedSetting<InstallationDomainSetting, R>>,
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
    installation_domain_setting: Arc<AppInstallationDomainSettingService>,
    installation_first_user_oid_setting: Arc<AppInstallationFirstUserOidSettingService>,
    installation_first_key_oid_setting: Arc<AppInstallationFirstKeyOidSettingService>,
    installation_initialized_at_setting: Arc<AppInstallationInitializedAtSettingService>,
    dynamic_client_registration_setting: Arc<AppDynamicClientRegistrationSettingService>,
    login_url_setting: Arc<AppLoginUrlSettingService>,
    consent_url_setting: Arc<AppConsentUrlSettingService>,
    key_ring: Arc<CachedRuntimeKeyRingProvider>,
}

impl AppRuntimeSettings {
    pub async fn from_db(db: DatabaseConnection) -> Result<Self, AppError> {
        let initialized = Arc::new(
            AppInstallationInitializedSettingService::new(SettingRepositoryImpl::new(db.clone()))
                .await?,
        );
        let domain = Arc::new(
            AppInstallationDomainSettingService::new(SettingRepositoryImpl::new(db.clone()))
                .await?,
        );
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
            installation_domain_setting: domain,
            installation_first_user_oid_setting: first_user_oid,
            installation_first_key_oid_setting: first_key_oid,
            installation_initialized_at_setting: initialized_at,
            dynamic_client_registration_setting: Arc::new(
                AppDynamicClientRegistrationSettingService::new(SettingRepositoryImpl::new(
                    db.clone(),
                ))
                .await?,
            ),
            login_url_setting: Arc::new(
                AppLoginUrlSettingService::new(SettingRepositoryImpl::new(db.clone())).await?,
            ),
            consent_url_setting: Arc::new(
                AppConsentUrlSettingService::new(SettingRepositoryImpl::new(db.clone())).await?,
            ),
            key_ring: Arc::new(CachedRuntimeKeyRingProvider::new(db.clone()).await?),
        })
    }

    pub fn spawn_refresh_task(&self, refresh_interval: Duration) {
        let mut refresher = SettingsRefresher::new(refresh_interval);
        refresher.register(Arc::clone(&self.password_hash_setting));
        refresher.register(Arc::clone(&self.installation_initialized_setting));
        refresher.register(Arc::clone(&self.installation_domain_setting));
        refresher.register(Arc::clone(&self.installation_first_user_oid_setting));
        refresher.register(Arc::clone(&self.installation_first_key_oid_setting));
        refresher.register(Arc::clone(&self.installation_initialized_at_setting));
        refresher.register(Arc::clone(&self.dynamic_client_registration_setting));
        refresher.register(Arc::clone(&self.login_url_setting));
        refresher.register(Arc::clone(&self.consent_url_setting));
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
    pub fn installation_domain(&self) -> Arc<AppInstallationDomainSettingService> {
        Arc::clone(&self.installation_domain_setting)
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
    pub fn login_url(&self) -> Arc<AppLoginUrlSettingService> {
        Arc::clone(&self.login_url_setting)
    }

    #[must_use]
    pub fn consent_url(&self) -> Arc<AppConsentUrlSettingService> {
        Arc::clone(&self.consent_url_setting)
    }

    #[must_use]
    pub fn key_ring(&self) -> Arc<CachedRuntimeKeyRingProvider> {
        Arc::clone(&self.key_ring)
    }
}
