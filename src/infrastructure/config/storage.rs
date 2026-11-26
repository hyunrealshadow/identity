use std::fmt;

use super::default_true;
use serde::Deserialize;

#[derive(Clone, Deserialize)]
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

impl fmt::Debug for DatabaseConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DatabaseConfig")
            .field("uri", &"[REDACTED]")
            .field("enable_logging", &self.enable_logging)
            .field("connect_timeout", &self.connect_timeout)
            .field("idle_timeout", &self.idle_timeout)
            .field("min_connections", &self.min_connections)
            .field("max_connections", &self.max_connections)
            .field("auto_migrate", &self.auto_migrate)
            .finish()
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

fn default_connect_timeout() -> u64 {
    500
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
    use super::DatabaseConfig;

    #[test]
    fn debug_redacts_database_uri() {
        let cfg = DatabaseConfig {
            uri: "postgres://user:super-secret-db-pass@localhost/identity".to_owned(),
            ..Default::default()
        };
        assert!(!format!("{cfg:?}").contains("super-secret-db-pass"));
    }
}
