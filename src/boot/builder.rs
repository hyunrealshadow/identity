use std::sync::Arc;
use std::time::Duration;

use sea_orm::DatabaseConnection;
use tera::Tera;

use identity_application::install::{InstallInput, InstallService};
use identity_domain::key::AsymmetricKeyAlgorithm;
use identity_infrastructure::auth::password::PasswordHasherImpl;
use identity_infrastructure::crypto::certificate_generator::CertificateGeneratorImpl;
use identity_infrastructure::crypto::key::AsymmetricKeyGeneratorImpl;
use identity_infrastructure::database::repository::install::InstallPersistenceImpl;
use identity_infrastructure::{
    AppContext, AppLifecycle, AppResources, AppState,
    config::{AppConfig, AppEnvironment, InstallConfig},
    database,
    database::seed,
    i18n::{I18n, init_error_i18n},
    observability,
    services::AppServices,
    settings::AppRuntimeSettings,
    web,
};

use super::AppResult;
use super::install_guard::ensure_install_startup_guard;

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
    /// Attempt system installation from config.
    ///
    /// If the system is not yet installed AND the `install` config section
    /// provides `domain` + `username` + `password`, performs installation
    /// automatically.  Otherwise this is a no-op (web installation remains
    /// available).
    ///
    /// Must be called after `connect_database` and before
    /// `load_runtime_settings`.
    pub async fn maybe_auto_install(self) -> AppResult<Self> {
        if self.config.install.domain.is_none()
            || self.config.install.username.is_none()
            || self.config.install.password.is_none()
        {
            return Ok(self);
        }

        let db = self.db.as_ref().expect("database must be connected first");

        if is_installed(db).await? {
            return Ok(self);
        }

        tracing::info!("auto install: running from config");

        let cfg = &self.config.install;
        tracing::info!(
            domain = %cfg.domain.as_deref().unwrap_or("<none>"),
            username = %cfg.username.as_deref().unwrap_or("<none>"),
            "auto install: config values"
        );
        let settings = Arc::new(AppRuntimeSettings::from_db(db.clone()).await?);
        let key_algorithm = parse_install_algorithm(cfg.key_algorithm.as_str())
            .unwrap_or(AsymmetricKeyAlgorithm::EcdsaP256);
        let svc = build_install_service(&settings, db.clone());

        let domain = install_domain(cfg, &self.config);

        svc.install(InstallInput {
            username: cfg.username.clone().unwrap_or_default(),
            email: cfg.email.clone().unwrap_or_else(|| {
                format!(
                    "{}@install.local",
                    cfg.username.as_deref().unwrap_or("admin")
                )
            }),
            password: cfg.password.clone().unwrap_or_default(),
            domain,
            key_algorithm,
        })
        .await?;

        tracing::info!("auto install: complete");
        Ok(self)
    }

    /// Construct application services (login, session, key, install).
    pub fn build_services(mut self) -> AppResult<Self> {
        let db = self.db.clone().expect("database must be connected first");
        let settings = self
            .runtime_settings
            .as_ref()
            .expect("runtime settings must be loaded first");

        self.services = Some(Arc::new(AppServices::from_db(db, settings.as_ref())?));
        Ok(self)
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

async fn is_installed(db: &sea_orm::DatabaseConnection) -> AppResult<bool> {
    use sea_orm::{ColumnTrait, EntityTrait, QueryFilter};

    use identity_domain::setting::{
        installation::InstallationInitializedSetting, model::SettingDefinition,
    };
    use identity_infrastructure::database::entity::setting;

    let row = setting::Entity::find()
        .filter(setting::Column::Key.eq(InstallationInitializedSetting::KEY))
        .one(db)
        .await?;

    let Some(row) = row else {
        return Ok(false);
    };

    serde_json::from_value(row.value).map_err(Into::into)
}

fn build_install_service(
    settings: &AppRuntimeSettings,
    db: DatabaseConnection,
) -> InstallService<identity_infrastructure::database::repository::setting::SettingRepositoryImpl> {
    InstallService {
        password_hasher: Arc::new(PasswordHasherImpl::new()),
        password_hash_options: settings.password_hash_options(),
        installation_initialized: settings.installation_initialized(),
        installation_domain: settings.installation_domain(),
        installation_first_user_oid: settings.installation_first_user_oid(),
        installation_first_key_oid: settings.installation_first_key_oid(),
        installation_initialized_at: settings.installation_initialized_at(),
        key_generator: Arc::new(AsymmetricKeyGeneratorImpl),
        certificate_generator: Arc::new(CertificateGeneratorImpl),
        persistence: Arc::new(InstallPersistenceImpl::new(db)),
    }
}

fn parse_install_algorithm(raw: &str) -> Option<AsymmetricKeyAlgorithm> {
    match raw {
        "ecdsa-p256" => Some(AsymmetricKeyAlgorithm::EcdsaP256),
        "ecdsa-p384" => Some(AsymmetricKeyAlgorithm::EcdsaP384),
        "ecdsa-p521" => Some(AsymmetricKeyAlgorithm::EcdsaP521),
        "ecdsa-secp256k1" => Some(AsymmetricKeyAlgorithm::EcdsaSecp256k1),
        "ed25519" => Some(AsymmetricKeyAlgorithm::Ed25519),
        "ed448" => Some(AsymmetricKeyAlgorithm::Ed448),
        "rsa-2048" => Some(AsymmetricKeyAlgorithm::Rsa { bits: 2048 }),
        "rsa-3072" => Some(AsymmetricKeyAlgorithm::Rsa { bits: 3072 }),
        "rsa-4096" => Some(AsymmetricKeyAlgorithm::Rsa { bits: 4096 }),
        _ => None,
    }
}

fn install_domain(cfg: &InstallConfig, config: &AppConfig) -> String {
    let from_cfg = cfg.domain.as_deref().filter(|v| !v.trim().is_empty());
    if let Some(domain) = from_cfg {
        let is_url = domain.contains("://");
        let has_dot = domain.contains('.');
        if is_url || has_dot {
            return domain.to_owned();
        }
    }
    // Fall back to server host (same behaviour as old conformance_autosetup)
    config
        .server
        .host
        .as_deref()
        .filter(|v| !v.trim().is_empty())
        .unwrap_or("https://localhost:5150")
        .to_owned()
}

#[cfg(test)]
mod tests {}
