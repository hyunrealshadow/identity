use std::{env, fs};

use serde::Deserialize;
use tera::Tera;
use url::Url;

pub type ConfigResult<T> = Result<T, Box<dyn std::error::Error + Send + Sync + 'static>>;

#[derive(Clone, Debug, Deserialize)]
pub struct AppConfig {
    #[serde(default)]
    pub logger: LoggerConfig,
    #[serde(default)]
    pub server: ServerConfig,
    #[serde(default)]
    pub database: DatabaseConfig,
    #[serde(default)]
    pub health: HealthConfig,
    #[serde(default)]
    pub settings: SettingsConfig,
}

impl AppConfig {
    pub fn load() -> ConfigResult<(Self, AppEnvironment)> {
        let environment = AppEnvironment::detect();
        let path = format!("config/{}.yaml", environment.as_str());
        let raw = fs::read_to_string(&path)?;
        let rendered = render_config_template(&raw)?;
        let config: Self = serde_yml::from_str(&rendered)?;

        Ok((config.normalized(), environment))
    }

    #[must_use]
    pub fn normalized(mut self) -> Self {
        if self
            .server
            .tls
            .domain
            .as_deref()
            .is_none_or(|value| value.trim().is_empty())
        {
            self.server.tls.domain =
                Some(default_tls_domain_from_host(self.server.host.as_deref()));
        }

        self
    }
}

fn render_config_template(raw: &str) -> ConfigResult<String> {
    let mut tera = Tera::default();
    tera.add_raw_template("config", raw)?;
    Ok(tera.render("config", &tera::Context::new())?)
}

#[derive(Clone, Debug, Deserialize)]
pub struct LoggerConfig {
    #[serde(default = "default_true")]
    pub enable: bool,
    #[serde(default)]
    pub pretty_backtrace: bool,
    #[serde(default = "default_log_level")]
    pub level: String,
    #[serde(default = "default_log_format")]
    pub format: String,
}

impl Default for LoggerConfig {
    fn default() -> Self {
        Self {
            enable: true,
            pretty_backtrace: false,
            level: default_log_level(),
            format: default_log_format(),
        }
    }
}

#[derive(Clone, Debug, Deserialize)]
pub struct ServerConfig {
    #[serde(default = "default_port")]
    pub port: u16,
    #[serde(default = "default_binding")]
    pub binding: String,
    #[serde(default)]
    pub host: Option<String>,
    #[serde(default)]
    pub tls: TlsConfig,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            port: default_port(),
            binding: default_binding(),
            host: None,
            tls: TlsConfig::default(),
        }
    }
}

#[derive(Clone, Debug, Deserialize)]
pub struct TlsConfig {
    #[serde(default)]
    pub enable: bool,
    #[serde(default = "default_true")]
    pub auto_generate: bool,
    #[serde(default = "default_tls_cert_path")]
    pub cert_path: String,
    #[serde(default = "default_tls_key_path")]
    pub key_path: String,
    #[serde(default)]
    pub domain: Option<String>,
}

impl Default for TlsConfig {
    fn default() -> Self {
        Self {
            enable: false,
            auto_generate: true,
            cert_path: default_tls_cert_path(),
            key_path: default_tls_key_path(),
            domain: None,
        }
    }
}

#[derive(Clone, Debug, Deserialize)]
pub struct DatabaseConfig {
    pub uri: String,
    #[serde(default)]
    pub enable_logging: bool,
    #[serde(default = "default_connect_timeout")]
    pub connect_timeout: u64,
    #[serde(default = "default_idle_timeout")]
    pub idle_timeout: u64,
    #[serde(default = "default_min_connections")]
    pub min_connections: u32,
    #[serde(default = "default_max_connections")]
    pub max_connections: u32,
    #[serde(default = "default_true")]
    pub auto_migrate: bool,
}

#[derive(Clone, Debug, Deserialize)]
pub struct SettingsConfig {
    #[serde(default = "default_settings_refresh_interval_secs")]
    pub refresh_interval_secs: u64,
}

impl Default for SettingsConfig {
    fn default() -> Self {
        Self {
            refresh_interval_secs: default_settings_refresh_interval_secs(),
        }
    }
}

#[derive(Clone, Debug, Deserialize)]
pub struct HealthConfig {
    #[serde(default = "default_true")]
    pub enable: bool,
    #[serde(default = "default_health_route")]
    pub route: String,
    #[serde(default)]
    pub server: HealthServerConfig,
    #[serde(default)]
    pub checks: HealthChecksConfig,
}

impl Default for HealthConfig {
    fn default() -> Self {
        Self {
            enable: true,
            route: default_health_route(),
            server: HealthServerConfig::default(),
            checks: HealthChecksConfig::default(),
        }
    }
}

#[derive(Clone, Debug, Deserialize)]
pub struct HealthServerConfig {
    #[serde(default)]
    pub binding: Option<String>,
    #[serde(default = "default_health_port")]
    pub port: u16,
}

impl Default for HealthServerConfig {
    fn default() -> Self {
        Self {
            binding: None,
            port: default_health_port(),
        }
    }
}

#[derive(Clone, Debug, Deserialize)]
pub struct HealthChecksConfig {
    #[serde(default = "default_true")]
    pub database: bool,
}

impl Default for HealthChecksConfig {
    fn default() -> Self {
        Self { database: true }
    }
}

impl Default for DatabaseConfig {
    fn default() -> Self {
        Self {
            uri: String::new(),
            enable_logging: false,
            connect_timeout: default_connect_timeout(),
            idle_timeout: default_idle_timeout(),
            min_connections: default_min_connections(),
            max_connections: default_max_connections(),
            auto_migrate: true,
        }
    }
}

#[derive(Clone, Debug)]
pub enum AppEnvironment {
    Development,
    Test,
    #[cfg(feature = "oidc-conformance")]
    Conformance,
    Production,
    Custom(String),
}

impl AppEnvironment {
    #[must_use]
    pub fn detect() -> Self {
        let raw = env::var("APP_ENV")
            .or_else(|_| env::var("RUST_ENV"))
            .unwrap_or_else(|_| "development".to_owned());

        match raw.to_lowercase().as_str() {
            "development" | "dev" => Self::Development,
            "test" => Self::Test,
            #[cfg(feature = "oidc-conformance")]
            "conformance" => Self::Conformance,
            "production" | "prod" => Self::Production,
            other => Self::Custom(other.to_owned()),
        }
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        match self {
            Self::Development => "development",
            Self::Test => "test",
            #[cfg(feature = "oidc-conformance")]
            Self::Conformance => "conformance",
            Self::Production => "production",
            Self::Custom(value) => value.as_str(),
        }
    }

    #[must_use]
    pub fn is_production(&self) -> bool {
        matches!(self, Self::Production)
    }

    #[must_use]
    #[cfg(feature = "oidc-conformance")]
    pub fn is_conformance(&self) -> bool {
        matches!(self, Self::Conformance)
    }
}

fn default_true() -> bool {
    true
}

fn default_log_level() -> String {
    "debug".to_owned()
}

fn default_health_route() -> String {
    "/health".to_owned()
}

fn default_log_format() -> String {
    "compact".to_owned()
}

fn default_port() -> u16 {
    5150
}

fn default_binding() -> String {
    "127.0.0.1".to_owned()
}

fn default_tls_cert_path() -> String {
    "config/tls/server.crt".to_owned()
}

fn default_tls_key_path() -> String {
    "config/tls/server.key".to_owned()
}

fn default_tls_domain() -> String {
    "localhost".to_owned()
}

fn default_tls_domain_from_host(host: Option<&str>) -> String {
    let Some(host) = host.map(str::trim).filter(|value| !value.is_empty()) else {
        return default_tls_domain();
    };

    if let Ok(url) = Url::parse(host)
        && let Some(parsed_host) = url.host_str()
    {
        return parsed_host.to_owned();
    }

    default_tls_domain()
}

fn default_connect_timeout() -> u64 {
    500
}

fn default_health_port() -> u16 {
    8081
}

fn default_idle_timeout() -> u64 {
    500
}

fn default_min_connections() -> u32 {
    1
}

fn default_max_connections() -> u32 {
    10
}

fn default_settings_refresh_interval_secs() -> u64 {
    5
}

#[cfg(test)]
mod tests {
    use super::{AppConfig, AppEnvironment, render_config_template};
    use serial_test::serial;

    fn set_env(key: &str, value: &str) {
        unsafe { std::env::set_var(key, value) };
    }

    fn remove_env(key: &str) {
        unsafe { std::env::remove_var(key) };
    }

    #[test]
    #[serial]
    #[cfg(feature = "oidc-conformance")]
    fn detect_conformance_environment() {
        set_env("APP_ENV", "conformance");

        let environment = AppEnvironment::detect();

        remove_env("APP_ENV");

        assert!(matches!(environment, AppEnvironment::Conformance));
        assert!(environment.is_conformance());
        assert!(!environment.is_production());
        assert_eq!(environment.as_str(), "conformance");
    }

    #[test]
    #[serial]
    fn detect_prefers_app_env_over_rust_env() {
        set_env("APP_ENV", "production");
        set_env("RUST_ENV", "test");

        let environment = AppEnvironment::detect();

        remove_env("APP_ENV");
        remove_env("RUST_ENV");

        assert!(matches!(environment, AppEnvironment::Production));
    }

    #[test]
    #[serial]
    fn detect_uses_rust_env_and_normalizes_custom_values() {
        remove_env("APP_ENV");
        set_env("RUST_ENV", "Staging");

        let environment = AppEnvironment::detect();

        remove_env("RUST_ENV");

        assert!(matches!(environment, AppEnvironment::Custom(value) if value == "staging"));
    }

    #[test]
    #[serial]
    fn render_template_uses_default_when_env_is_missing() {
        remove_env("TEST_RENDER_ENV");

        let rendered = render_config_template(
            r#"value: {{ get_env(name="TEST_RENDER_ENV", default="fallback") }}"#,
        )
        .unwrap();

        assert_eq!(rendered, "value: fallback");
    }

    #[test]
    #[serial]
    fn render_template_errors_when_required_env_is_missing() {
        remove_env("TEST_RENDER_ENV");

        let result = render_config_template(r#"value: {{ get_env(name="TEST_RENDER_ENV") }}"#);

        assert!(result.is_err());
    }

    #[test]
    fn deserialization_applies_config_defaults() {
        let config: AppConfig = serde_yml::from_str(
            r#"
database:
  uri: postgres://localhost/identity
"#,
        )
        .unwrap();

        assert_eq!(config.logger.level, "debug");
        assert_eq!(config.logger.format, "compact");
        assert_eq!(config.server.port, 5150);
        assert_eq!(config.server.binding, "127.0.0.1");
        assert!(!config.server.tls.enable);
        assert_eq!(config.health.route, "/health");
        assert_eq!(config.settings.refresh_interval_secs, 5);
        assert!(config.health.enable);
        assert!(config.health.checks.database);
        assert!(config.database.auto_migrate);
    }

    #[test]
    fn deserialization_applies_tls_defaults() {
        let config: AppConfig = serde_yml::from_str(
            r#"
database:
  uri: postgres://localhost/identity
"#,
        )
        .unwrap();

        assert!(!config.server.tls.enable);
        assert!(config.server.tls.auto_generate);
        assert_eq!(config.server.tls.cert_path, "config/tls/server.crt");
        assert_eq!(config.server.tls.key_path, "config/tls/server.key");
        assert_eq!(config.server.tls.domain, None);
    }

    #[test]
    fn tls_domain_prefers_explicit_value() {
        let config: AppConfig = serde_yml::from_str(
            r#"
server:
  host: http://example.com
  tls:
    domain: identity.example.com
database:
  uri: postgres://localhost/identity
"#,
        )
        .unwrap();

        let config = config.normalized();

        assert_eq!(
            config.server.tls.domain.as_deref(),
            Some("identity.example.com")
        );
    }

    #[test]
    fn tls_domain_falls_back_to_server_host() {
        let config: AppConfig = serde_yml::from_str(
            r#"
server:
  host: https://identity.example.com:8443/base
  tls:
    domain: null
database:
  uri: postgres://localhost/identity
"#,
        )
        .unwrap();

        let config = config.normalized();

        assert_eq!(
            config.server.tls.domain.as_deref(),
            Some("identity.example.com")
        );
    }

    #[test]
    fn tls_domain_falls_back_to_localhost_when_host_is_missing() {
        let config: AppConfig = serde_yml::from_str(
            r#"
server:
  tls:
    domain: null
database:
  uri: postgres://localhost/identity
"#,
        )
        .unwrap();

        let config = config.normalized();

        assert_eq!(config.server.tls.domain.as_deref(), Some("localhost"));
    }
}
