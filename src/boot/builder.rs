use std::sync::Arc;
use std::time::Duration;

use sea_orm::DatabaseConnection;
use tera::Tera;

use super::services::AppServices;
use super::settings::AppRuntimeSettings;
#[cfg(feature = "oidc-conformance")]
use crate::application::install::{InstallInput, InstallService};
#[cfg(feature = "oidc-conformance")]
use crate::domain::key::AsymmetricKeyAlgorithm;
#[cfg(feature = "oidc-conformance")]
use crate::infrastructure::auth::password::PasswordHasherImpl;
#[cfg(feature = "oidc-conformance")]
use crate::infrastructure::crypto::key::AsymmetricKeyGeneratorImpl;
use crate::infrastructure::{
    config::{AppConfig, AppEnvironment},
    database,
    database::seed,
    i18n::{I18n, init_error_i18n},
    observability, web,
};

use super::AppResult;
use super::context::AppContext;
use super::install_guard::ensure_install_startup_guard;
use super::lifecycle::AppLifecycle;
use super::resources::AppResources;
use super::state::AppState;

/// Application builder that orchestrates the startup pipeline.
///
/// Each method consumes `self` and returns the next stage, ensuring a clear
/// sequential flow: config -> tracing -> database -> i18n/templates ->
/// runtime settings -> services -> state.
pub struct AppBuilder {
    config: AppConfig,
    environment: AppEnvironment,
    db: Option<DatabaseConnection>,
    i18n: Option<I18n>,
    tera: Option<Arc<Tera>>,
    runtime_settings: Option<Arc<AppRuntimeSettings>>,
    services: Option<Arc<AppServices>>,
}

impl AppBuilder {
    /// Load configuration from `config/{env}.yaml` and determine the environment.
    pub fn from_config() -> AppResult<Self> {
        let (config, environment) = AppConfig::load()?;
        Ok(Self {
            config,
            environment,
            db: None,
            i18n: None,
            tera: None,
            runtime_settings: None,
            services: None,
        })
    }

    /// Initialize the tracing/logging subscriber.
    #[must_use]
    pub fn init_tracing(self) -> Self {
        observability::init_tracing(&self.config.logger);
        self
    }

    /// Connect to the database and optionally run migrations and seeds.
    pub async fn connect_database(mut self) -> AppResult<Self> {
        let db = database::connect(&self.config.database).await?;

        if self.config.database.auto_migrate {
            database::migrate(&db).await?;
        }

        seed::run_all(&db).await?;
        self.db = Some(db);
        Ok(self)
    }

    /// Build I18n translations and the Tera template engine.
    ///
    /// Side-effect: stores the I18n instance in a global `OnceLock` for
    /// `AppError` -> HTTP response conversion.
    pub fn init_i18n_and_templates(mut self) -> AppResult<Self> {
        let i18n = web::tera::build_i18n()?;
        init_error_i18n(i18n.clone());
        let tera = web::tera::build_tera(i18n.loader())?;
        self.i18n = Some(i18n);
        self.tera = Some(tera);
        Ok(self)
    }

    /// Load runtime settings from the database, enforce the installation
    /// startup guard, and spawn the background refresh task.
    pub async fn load_runtime_settings(mut self) -> AppResult<Self> {
        let db = self.db.as_ref().expect("database must be connected first");

        let settings = Arc::new(AppRuntimeSettings::from_db(db.clone()).await?);
        ensure_install_startup_guard(db, settings.as_ref()).await?;

        let refresh_interval =
            Duration::from_secs(self.config.settings.refresh_interval_secs.max(1));
        settings.spawn_refresh_task(refresh_interval);

        self.runtime_settings = Some(settings);
        Ok(self)
    }

    /// When `APP_ENV=conformance`: ensure the system is installed and seed the
    /// conformance test user and OIDC client.
    ///
    /// This is a no-op for every other environment.
    ///
    /// Must be called after `connect_database` and before `load_runtime_settings`.
    #[cfg(feature = "oidc-conformance")]
    pub async fn conformance_autosetup(self) -> AppResult<Self> {
        if !matches!(self.environment, AppEnvironment::Conformance) {
            return Ok(self);
        }

        let db = self.db.as_ref().expect("database must be connected first");

        // ── Step 1: auto-install if the system has not been initialized yet ──
        //
        // We query the DB directly because runtime settings have not been
        // loaded yet at this point in the startup pipeline.

        if !conformance_installation_initialized(db).await? {
            tracing::info!("conformance autosetup: system not initialized – running install");

            // Construct a minimal InstallService without pre-loaded settings.
            // We load settings in-line here just for the install call.
            let bootstrap_settings =
                Arc::new(crate::boot::settings::AppRuntimeSettings::from_db(db.clone()).await?);

            let install_service = InstallService {
                db: db.clone(),
                password_hasher: Arc::new(PasswordHasherImpl::new()),
                password_hash_options: bootstrap_settings.password_hash_options(),
                installation_setting: bootstrap_settings.installation(),
                key_generator: Arc::new(AsymmetricKeyGeneratorImpl),
            };

            install_service
                .install(InstallInput {
                    username: "admin".to_owned(),
                    email: "admin@conformance.local".to_owned(),
                    password: "ConformanceAdmin1!".to_owned(),
                    domain: "http://identity:5150".to_owned(),
                    key_algorithm: AsymmetricKeyAlgorithm::EcdsaP256,
                })
                .await?;

            tracing::info!("conformance auto setup: install complete");
        }

        Ok(self)
    }

    /// Construct application services (login, session, key, install).
    #[must_use]
    pub fn build_services(mut self) -> Self {
        let db = self.db.clone().expect("database must be connected first");
        let settings = self
            .runtime_settings
            .as_ref()
            .expect("runtime settings must be loaded first");

        self.services = Some(Arc::new(AppServices::from_db(db, settings.as_ref())));
        self
    }

    /// Assemble the final `AppState` and return it together with the config.
    pub fn build(self) -> (AppState, AppConfig) {
        let context = Arc::new(AppContext::new(
            self.environment,
            self.config.health.checks.clone(),
        ));
        let resources = Arc::new(AppResources::new(
            self.db.expect("database must be connected first"),
            self.tera.expect("templates must be initialized first"),
            self.i18n.expect("i18n must be initialized first"),
        ));
        let lifecycle = Arc::new(AppLifecycle::new());
        let settings = self
            .runtime_settings
            .expect("runtime settings must be loaded first");
        let services = self.services.expect("services must be built first");

        let state = AppState::new(context, resources, lifecycle, settings, services);
        (state, self.config)
    }
}

/// Query the database directly to determine whether installation has been
/// completed.  Used during conformance autosetup, before runtime settings are
/// loaded.
#[cfg(feature = "oidc-conformance")]
async fn conformance_installation_initialized(
    db: &sea_orm::DatabaseConnection,
) -> AppResult<bool> {
    use sea_orm::{ColumnTrait, EntityTrait, QueryFilter};

    use crate::{
        domain::setting::{installation::InstallationSetting, model::SettingDefinition},
        infrastructure::database::entity::setting,
    };

    let row = setting::Entity::find()
        .filter(setting::Column::Key.eq(InstallationSetting::KEY))
        .one(db)
        .await?;

    let Some(row) = row else {
        return Ok(false);
    };

    let state: crate::domain::setting::installation::InstallationState =
        serde_json::from_value(row.value)?;

    Ok(state.initialized)
}
