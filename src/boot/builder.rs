use std::sync::Arc;
use std::time::Duration;

use sea_orm::DatabaseConnection;
use tera::Tera;

use super::services::AppServices;
use super::settings::AppRuntimeSettings;
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
        let i18n = web::build_i18n()?;
        init_error_i18n(i18n.clone());
        let tera = web::build_tera(i18n.loader())?;
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
