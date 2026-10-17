use serde::Deserialize;
use std::fmt;

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InternalConfig {
    #[serde(default)]
    pub server: InternalServerConfig,
    #[serde(default)]
    pub workloads: WorkloadsConfig,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InternalServerConfig {
    #[serde(default = "default_internal_binding")]
    pub binding: String,
    #[serde(default = "default_internal_port")]
    pub port: u16,
}

impl Default for InternalServerConfig {
    fn default() -> Self {
        Self {
            binding: default_internal_binding(),
            port: default_internal_port(),
        }
    }
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkloadsConfig {
    #[serde(default)]
    pub login: LoginWorkloadConfig,
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LoginWorkloadConfig {
    #[serde(default)]
    pub static_tokens: Vec<StaticTokenConfig>,
    #[serde(default)]
    pub kubernetes_service_account: KubernetesServiceAccountConfig,
}

impl LoginWorkloadConfig {
    #[must_use]
    pub fn has_any_authentication(&self) -> bool {
        !self.static_tokens.is_empty() || self.kubernetes_service_account.enabled
    }
}

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StaticTokenConfig {
    #[serde(default)]
    pub file: Option<String>,
    #[serde(default)]
    pub environment: Option<String>,
    #[serde(default)]
    pub token: Option<String>,
}

impl fmt::Debug for StaticTokenConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("StaticTokenConfig")
            .field("file", &self.file)
            .field("environment", &self.environment)
            .field("token", &self.token.as_ref().map(|_| "[REDACTED]"))
            .finish()
    }
}

impl StaticTokenConfig {
    pub(super) fn has_exactly_one_source(&self) -> bool {
        [
            self.file.as_deref(),
            self.environment.as_deref(),
            self.token.as_deref(),
        ]
        .into_iter()
        .filter(|value| value.is_some_and(|value| !value.trim().is_empty()))
        .count()
            == 1
    }
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KubernetesServiceAccountConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_internal_token_audience")]
    pub audience: String,
    #[serde(default = "default_internal_token_service_account")]
    pub service_account: String,
    #[serde(default = "default_internal_token_namespace")]
    pub namespace: String,
    #[serde(default = "default_internal_token_issuer")]
    pub issuer: String,
    #[serde(default)]
    pub ca_file: Option<String>,
    #[serde(default)]
    pub token_file: Option<String>,
}

impl Default for KubernetesServiceAccountConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            audience: default_internal_token_audience(),
            service_account: default_internal_token_service_account(),
            namespace: default_internal_token_namespace(),
            issuer: default_internal_token_issuer(),
            ca_file: None,
            token_file: None,
        }
    }
}

fn default_internal_binding() -> String {
    "127.0.0.1".to_owned()
}

const fn default_internal_port() -> u16 {
    5151
}

fn default_internal_token_audience() -> String {
    "identity-internal".to_owned()
}

fn default_internal_token_service_account() -> String {
    "identity-login".to_owned()
}

fn default_internal_token_namespace() -> String {
    "default".to_owned()
}

fn default_internal_token_issuer() -> String {
    "https://kubernetes.default.svc.cluster.local".to_owned()
}
