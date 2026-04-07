use std::{env, fs};

use serde::Deserialize;
use tera::{Function, Tera, Value, from_value, to_value};

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
        let config: Self = serde_yaml::from_str(&rendered)?;

        Ok((config, environment))
    }
}

struct GetEnvFn;

impl Function for GetEnvFn {
    fn call(&self, args: &std::collections::HashMap<String, Value>) -> tera::Result<Value> {
        let name = args
            .get("name")
            .ok_or_else(|| tera::Error::msg("get_env(): missing required argument `name`"))
            .and_then(|value| {
                from_value::<String>(value.clone())
                    .map_err(|_| tera::Error::msg("get_env(): `name` must be a string"))
            })?;

        let default = args
            .get("default")
            .map(|value| {
                from_value::<String>(value.clone())
                    .map_err(|_| tera::Error::msg("get_env(): `default` must be a string"))
            })
            .transpose()?;

        let value = match env::var(&name) {
            Ok(value) => value,
            Err(_) => default.ok_or_else(|| {
                tera::Error::msg(format!(
                    "get_env(): environment variable `{name}` is not set"
                ))
            })?,
        };

        to_value(value).map_err(|e| tera::Error::msg(e.to_string()))
    }
}

fn render_config_template(raw: &str) -> ConfigResult<String> {
    let mut tera = Tera::default();
    tera.register_function("get_env", GetEnvFn);
    Ok(Tera::one_off(raw, &tera::Context::new(), false)?)
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
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            port: default_port(),
            binding: default_binding(),
            host: None,
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
            "production" | "prod" => Self::Production,
            other => Self::Custom(other.to_owned()),
        }
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        match self {
            Self::Development => "development",
            Self::Test => "test",
            Self::Production => "production",
            Self::Custom(value) => value.as_str(),
        }
    }

    #[must_use]
    pub fn is_production(&self) -> bool {
        matches!(self, Self::Production)
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
    1
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
        let config: AppConfig = serde_yaml::from_str(
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
        assert_eq!(config.health.route, "/health");
        assert_eq!(config.settings.refresh_interval_secs, 5);
        assert!(config.health.enable);
        assert!(config.health.checks.database);
        assert!(config.database.auto_migrate);
    }
}
