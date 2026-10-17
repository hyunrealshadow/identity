use super::default_true;
use serde::Deserialize;

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
