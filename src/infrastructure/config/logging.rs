use super::default_true;
use serde::Deserialize;

#[derive(Clone, Debug, Deserialize)]
pub struct LoggerConfig {
    #[serde(default = "default_true")]
    pub enable: bool,
    #[serde(default)]
    pub pretty_backtrace: bool,
    #[serde(default = "default_log_level")]
    pub level: String,
    #[serde(default = "default_log_format")]
    pub format: LogFormat,
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

#[derive(Clone, Copy, Debug, Default, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum LogFormat {
    #[default]
    Compact,
    Json,
    Pretty,
}

fn default_log_level() -> String {
    "debug".to_owned()
}

const fn default_log_format() -> LogFormat {
    LogFormat::Compact
}
