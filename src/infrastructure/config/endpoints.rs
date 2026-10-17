use super::default_true;
use serde::Deserialize;

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

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GraphqlConfig {
    #[serde(default)]
    pub server: GraphqlServerConfig,
    #[serde(default)]
    pub allowed_origins: Vec<String>,
    #[serde(default = "default_graphql_max_depth")]
    pub max_depth: usize,
    #[serde(default = "default_graphql_max_complexity")]
    pub max_complexity: usize,
    #[serde(default = "default_graphql_max_page_size")]
    pub max_page_size: usize,
    #[serde(default = "default_graphql_timeout_secs")]
    pub timeout_secs: u64,
}

impl Default for GraphqlConfig {
    fn default() -> Self {
        Self {
            server: GraphqlServerConfig::default(),
            allowed_origins: Vec::new(),
            max_depth: default_graphql_max_depth(),
            max_complexity: default_graphql_max_complexity(),
            max_page_size: default_graphql_max_page_size(),
            timeout_secs: default_graphql_timeout_secs(),
        }
    }
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GraphqlServerConfig {
    #[serde(default)]
    pub binding: Option<String>,
    #[serde(default)]
    pub port: Option<u16>,
}

fn default_health_route() -> String {
    "/health".to_owned()
}

fn default_health_port() -> u16 {
    8081
}

fn default_graphql_max_depth() -> usize {
    12
}

fn default_graphql_max_complexity() -> usize {
    300
}

fn default_graphql_max_page_size() -> usize {
    100
}

fn default_graphql_timeout_secs() -> u64 {
    10
}
