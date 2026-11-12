use std::{
    io::{Error, ErrorKind},
    sync::Arc,
    time::Duration,
};

use identity_application::{
    error::{AppError, codes::install::InstallErrorCode},
    install::{InstallInput, InstallService},
    setting::{
        ConsoleClientIdSetting, ConsoleDomainSetting, DomainSetting, InstallationSettings,
        SettingsSource,
    },
};
use identity_domain::{key::JwaSigningAlgorithm, openid_connect::BUILTIN_CLIENT_SECRET_LIFETIME};
use identity_infrastructure::{
    AppContext, AppLifecycle, AppResources, AppState,
    auth::{
        breached_password::PwnedPasswordChecker, password::PasswordHasherImpl,
        workload::build_workload_authenticator,
    },
    config::{AppConfig, AppEnvironment, InstallConfig},
    crypto::{certificate_generator::CertificateGeneratorImpl, key::AsymmetricKeyGeneratorImpl},
    database,
    database::{
        repository::{install::InstallRepositoryImpl, setting::read_section},
        seed,
        seed::{console, console::ConsoleClientSeedConfig, login},
    },
    i18n::{I18n, init_error_i18n},
    observability,
    services::AppServices,
    settings::AppRuntimeSettings,
    web::tera as web_tera,
};
use sea_orm::DatabaseConnection;
use tera::Tera;
use tracing::info;
use url::Url;

use super::{AppResult, install_guard::ensure_install_startup_guard};

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

    /// Initialize observability (console output, OTLP pipelines, PII policy,
    /// W3C trace context and the non-blocking event/audit sink).
    pub fn init_tracing(self) -> AppResult<Self> {
        observability::init(&self.config, &self.environment)?;
        Ok(self)
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
        let i18n = web_tera::build_i18n()?;
        if self.config.console.enabled && i18n.loader().is_none() {
            return Err(
                Error::other("console management requires both backend error locales").into(),
            );
        }
        init_error_i18n(i18n.clone());
        let tera = web_tera::build_tera(i18n.loader())?;
        self.i18n = Some(i18n);
        self.tera = Some(tera);
        Ok(self)
    }

    /// Load runtime settings from the database, enforce the installation
    /// startup guard, and spawn the background refresh task.
    pub async fn load_runtime_settings(mut self) -> AppResult<Self> {
        let db = self.db.as_ref().expect("database must be connected first");

        let settings = Arc::new(AppRuntimeSettings::from_db(db.clone()).await?);
        let installed = settings
            .store()
            .snapshot()
            .section::<InstallationSettings>()
            .initialized;
        // Both first-party clients are system-managed and reconciled on start.
        if installed {
            login::ensure_login_client(db).await?;
        }
        if installed && let Some(config) = installed_console_seed_config(settings.as_ref())? {
            console::ensure_console_client(db, &config).await?;
        }
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
    /// automatically. Otherwise this is a no-op (the installation API remains
    /// available for the external application).
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

        info!("auto install: running from config");

        let cfg = &self.config.install;
        info!(
            domain = %cfg.domain.as_deref().unwrap_or("<none>"),
            username = %cfg.username.as_deref().unwrap_or("<none>"),
            "auto install: config values"
        );
        let settings = Arc::new(AppRuntimeSettings::from_db(db.clone()).await?);
        // The configured key decides both the key type and the algorithm it
        // signs with by default; keys that cannot sign are rejected here.
        let unsupported = || {
            AppError::from_code(InstallErrorCode::UnsupportedAlgorithm)
                .with_param("algorithm", cfg.key_algorithm.to_string())
        };
        let signing_algorithm = JwaSigningAlgorithm::primary_for_key_type(&cfg.key_algorithm)
            .ok_or_else(unsupported)?;

        let mut svc = build_install_service(&settings, db.clone())?;
        svc.repository = Arc::new(
            InstallRepositoryImpl::new(db.clone())
                .with_console_client_config(console_seed_config(&self.config)?),
        );

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
            application_url: cfg
                .application_url
                .clone()
                .unwrap_or_else(|| "https://localhost:3000".to_owned()),
            console_url: self
                .config
                .console
                .validated_origin()
                .ok()
                .flatten()
                .unwrap_or_else(|| "https://localhost:3100".to_owned()),
            signing_algorithm,
            key_algorithm: Some(cfg.key_algorithm),
        })
        .await?;

        info!("auto install: complete");
        Ok(self)
    }

    /// Construct application services (login, session, key, install).
    pub fn build_services(mut self) -> AppResult<Self> {
        let db = self.db.clone().expect("database must be connected first");
        let settings = self
            .runtime_settings
            .as_ref()
            .expect("runtime settings must be loaded first");

        let workload_authenticator = build_workload_authenticator(&self.config.internal.workloads)
            .map_err(|error| Error::new(ErrorKind::InvalidInput, error))?;

        self.services = Some(Arc::new(
            AppServices::from_db_with_workload_auth(
                db.clone(),
                settings.as_ref(),
                workload_authenticator,
            )?
            .with_console_installation(db, console_seed_config(&self.config)?),
        ));
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

async fn is_installed(db: &DatabaseConnection) -> AppResult<bool> {
    Ok(read_section::<InstallationSettings, _>(db)
        .await?
        .initialized)
}

/// Installed Console client addresses come only from database settings.
fn installed_console_seed_config(
    settings: &AppRuntimeSettings,
) -> AppResult<Option<ConsoleClientSeedConfig>> {
    let snapshot = settings.store().snapshot();
    if snapshot.get::<ConsoleClientIdSetting>().is_none() {
        return Ok(None);
    }
    let Some(base) = snapshot.get::<ConsoleDomainSetting>() else {
        return Ok(None);
    };
    let base = Url::parse(&format!("{}/", base.trim_end_matches('/')))
        .map_err(|error| Error::other(error.to_string()))?;
    let origin = base.origin().ascii_serialization();
    let domain = snapshot
        .get::<DomainSetting>()
        .ok_or_else(|| Error::other("console requires the installed issuer domain"))?;
    let issuer = issuer_from_domain(&domain)?;
    Ok(Some(ConsoleClientSeedConfig::new(
        &origin,
        issuer.as_str(),
        base.join("callback")?.as_str(),
    )?))
}

fn issuer_from_domain(domain: &str) -> AppResult<Url> {
    let candidate = if domain.contains("://") {
        domain.to_owned()
    } else {
        format!("https://{domain}")
    };
    let url = Url::parse(&candidate).map_err(|error| Error::other(error.to_string()))?;
    Ok(url)
}

fn console_seed_config(config: &AppConfig) -> AppResult<Option<ConsoleClientSeedConfig>> {
    let Some(origin) = config.console.validated_origin().map_err(Error::other)? else {
        return Ok(None);
    };
    let issuer = config
        .server
        .host
        .as_deref()
        .ok_or_else(|| Error::other("console requires the configured issuer"))?;
    Ok(Some(ConsoleClientSeedConfig::new(
        &origin,
        issuer,
        &format!("{origin}/callback"),
    )?))
}

fn build_install_service(
    settings: &AppRuntimeSettings,
    db: DatabaseConnection,
) -> AppResult<InstallService> {
    Ok(InstallService {
        breach_checker: Arc::new(PwnedPasswordChecker::new()?),
        password_hasher: Arc::new(PasswordHasherImpl::new()),
        settings: settings.store(),
        key_generator: Arc::new(AsymmetricKeyGeneratorImpl),
        certificate_generator: Arc::new(CertificateGeneratorImpl),
        repository: Arc::new(InstallRepositoryImpl::new(db)),
        runtime_key_ring: settings.key_ring(),
        client_secret_lifetime: BUILTIN_CLIENT_SECRET_LIFETIME,
    })
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
