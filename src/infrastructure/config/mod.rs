use std::{env, fs};

use identity_domain::key::AsymmetricKeyAlgorithm;
use ipnet::IpNet;
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
    pub internal: InternalConfig,
    #[serde(default)]
    pub client_credential_rotation: ClientCredentialRotationConfig,
    #[serde(default)]
    pub database: DatabaseConfig,
    #[serde(default)]
    pub health: HealthConfig,
    #[serde(default)]
    pub graphql: GraphqlConfig,
    #[serde(default)]
    pub settings: SettingsConfig,
    #[serde(default)]
    pub install: InstallConfig,
    #[serde(default)]
    pub openid_connect: OpenIdConnectConfig,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClientCredentialRotationConfig {
    #[serde(default = "default_true")]
    pub enable: bool,
    #[serde(default = "default_rotation_check_interval_secs")]
    pub check_interval_secs: u64,
    #[serde(default = "default_credential_lifetime_days")]
    pub credential_lifetime_days: i64,
    #[serde(default = "default_rotate_before_expiry_days")]
    pub rotate_before_expiry_days: i64,
    #[serde(default = "default_retire_after_secs")]
    pub retire_after_secs: i64,
}

impl Default for ClientCredentialRotationConfig {
    fn default() -> Self {
        Self {
            enable: true,
            check_interval_secs: default_rotation_check_interval_secs(),
            credential_lifetime_days: default_credential_lifetime_days(),
            rotate_before_expiry_days: default_rotate_before_expiry_days(),
            retire_after_secs: default_retire_after_secs(),
        }
    }
}

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

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StaticTokenConfig {
    #[serde(default)]
    pub file: Option<String>,
    #[serde(default)]
    pub environment: Option<String>,
}

impl StaticTokenConfig {
    fn has_exactly_one_source(&self) -> bool {
        self.file
            .as_deref()
            .is_some_and(|value| !value.trim().is_empty())
            ^ self
                .environment
                .as_deref()
                .is_some_and(|value| !value.trim().is_empty())
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

impl LoginWorkloadConfig {
    #[must_use]
    pub fn has_any_authentication(&self) -> bool {
        !self.static_tokens.is_empty() || self.kubernetes_service_account.enabled
    }
}

impl AppConfig {
    pub fn load() -> ConfigResult<(Self, AppEnvironment)> {
        let environment = AppEnvironment::detect();
        let path = format!("config/{}.yaml", environment.as_str());
        let raw = fs::read_to_string(&path)?;
        let rendered = render_config_template(&raw)?;
        let config: Self = serde_yml::from_str(&rendered)?;
        let config = config.normalized();
        config.validate_https_contract()?;

        Ok((config, environment))
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
        if let Some(host) = self.server.host.as_deref()
            && let Ok(url) = Url::parse(host)
        {
            let origin = url.origin().ascii_serialization();
            if !self
                .graphql
                .allowed_origins
                .iter()
                .any(|allowed| allowed == &origin)
            {
                self.graphql.allowed_origins.push(origin);
            }
        }

        self
    }

    pub fn validate_https_contract(&self) -> ConfigResult<()> {
        let host = self
            .server
            .host
            .as_deref()
            .filter(|value| !value.trim().is_empty())
            .ok_or_else(|| invalid_config("server.host must be an https URL"))?;
        let host = Url::parse(host)
            .map_err(|error| invalid_config(format!("server.host must be a valid URL: {error}")))?;

        if host.scheme() != "https" {
            return Err(invalid_config("server.host must use https").into());
        }

        if self.server.tls.termination == TlsTermination::Upstream
            && self.server.tls.trusted_proxies.is_empty()
            && self.server.tls.direct_http_clients.is_empty()
        {
            return Err(invalid_config(
                "server.tls must configure at least one trusted_proxies or direct_http_clients network when TLS termination is upstream",
            )
            .into());
        }

        if self.internal.server.binding == self.server.binding
            && self.internal.server.port == self.server.port
        {
            return Err(invalid_config(
                "internal.server must use a listener distinct from the public server",
            )
            .into());
        }
        if !self.internal.workloads.login.has_any_authentication() {
            return Err(invalid_config(
                "internal.workloads.login must configure at least one authentication method (static_tokens or kubernetes_service_account)",
            )
            .into());
        }
        if self
            .internal
            .workloads
            .login
            .static_tokens
            .iter()
            .any(|source| !source.has_exactly_one_source())
        {
            return Err(invalid_config(
                "each login static token must configure exactly one of file or environment",
            )
            .into());
        }
        let kubernetes = &self.internal.workloads.login.kubernetes_service_account;
        if kubernetes.enabled
            && (kubernetes.namespace.trim().is_empty()
                || kubernetes.service_account.trim().is_empty()
                || kubernetes.audience.trim().is_empty()
                || kubernetes.issuer.trim().is_empty()
                || kubernetes
                    .ca_file
                    .as_deref()
                    .is_some_and(|path| path.trim().is_empty())
                || kubernetes
                    .token_file
                    .as_deref()
                    .is_some_and(|path| path.trim().is_empty()))
        {
            return Err(invalid_config(
                "kubernetes_service_account namespace, service_account, audience, issuer, and configured credential files must not be empty",
            )
            .into());
        }
        let rotation = &self.client_credential_rotation;
        if rotation.enable
            && (rotation.check_interval_secs == 0
                || rotation.credential_lifetime_days <= 0
                || rotation.rotate_before_expiry_days <= 0
                || rotation.credential_lifetime_days <= rotation.rotate_before_expiry_days
                || rotation.retire_after_secs <= 0)
        {
            return Err(invalid_config(
                "client credential rotation intervals must be positive and credential_lifetime_days must exceed rotate_before_expiry_days",
            )
            .into());
        }

        Ok(())
    }
}

fn invalid_config(message: impl Into<String>) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::InvalidInput, message.into())
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
    pub format: LogFormat,
}

#[derive(Clone, Copy, Debug, Default, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum LogFormat {
    #[default]
    Compact,
    Json,
    Pretty,
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

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OpenIdConnectConfig {
    #[serde(default)]
    pub dynamic_registration: DynamicClientRegistrationConfig,
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DynamicClientRegistrationConfig {
    /// Optional fixed RFC 7591 initial access token used only by the OIDC
    /// conformance harness. Ordinary deployments must not use a long-lived
    /// shared token for dynamic client registration.
    #[cfg(feature = "oidc-conformance")]
    #[serde(default)]
    pub conformance_initial_access_token: Option<String>,
}

impl DynamicClientRegistrationConfig {
    #[must_use]
    pub fn required_conformance_initial_access_token(&self) -> Option<&str> {
        #[cfg(feature = "oidc-conformance")]
        {
            self.conformance_initial_access_token
                .as_deref()
                .map(str::trim)
                .filter(|value| !value.is_empty())
        }
        #[cfg(not(feature = "oidc-conformance"))]
        {
            None
        }
    }
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TlsConfig {
    #[serde(default)]
    pub termination: TlsTermination,
    #[serde(default = "default_true")]
    pub auto_generate: bool,
    #[serde(default = "default_tls_cert_path")]
    pub cert_path: String,
    #[serde(default = "default_tls_key_path")]
    pub key_path: String,
    #[serde(default)]
    pub domain: Option<String>,
    #[serde(default)]
    pub trusted_proxies: Vec<IpNet>,
    #[serde(default)]
    pub direct_http_clients: Vec<IpNet>,
}

impl Default for TlsConfig {
    fn default() -> Self {
        Self {
            termination: TlsTermination::Direct,
            auto_generate: true,
            cert_path: default_tls_cert_path(),
            key_path: default_tls_key_path(),
            domain: None,
            trusted_proxies: Vec::new(),
            direct_http_clients: Vec::new(),
        }
    }
}

#[derive(Clone, Copy, Debug, Default, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum TlsTermination {
    #[default]
    Direct,
    Upstream,
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
pub struct InstallConfig {
    pub domain: Option<String>,
    pub username: Option<String>,
    pub email: Option<String>,
    pub password: Option<String>,
    pub application_url: Option<String>,
    #[serde(
        default = "default_key_algorithm",
        deserialize_with = "deserialize_install_key_algorithm"
    )]
    pub key_algorithm: AsymmetricKeyAlgorithm,
}

impl Default for InstallConfig {
    fn default() -> Self {
        Self {
            domain: None,
            username: None,
            email: None,
            password: None,
            application_url: None,
            key_algorithm: default_key_algorithm(),
        }
    }
}

const fn default_key_algorithm() -> AsymmetricKeyAlgorithm {
    AsymmetricKeyAlgorithm::EcdsaP256
}

fn deserialize_install_key_algorithm<'de, D>(
    deserializer: D,
) -> Result<AsymmetricKeyAlgorithm, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let value = String::deserialize(deserializer)?;
    match value.as_str() {
        "ecdsa-p256" => Ok(AsymmetricKeyAlgorithm::EcdsaP256),
        "ecdsa-p384" => Ok(AsymmetricKeyAlgorithm::EcdsaP384),
        "ecdsa-p521" => Ok(AsymmetricKeyAlgorithm::EcdsaP521),
        "ecdsa-secp256k1" => Ok(AsymmetricKeyAlgorithm::EcdsaSecp256k1),
        "ed25519" => Ok(AsymmetricKeyAlgorithm::Ed25519),
        "ed448" => Ok(AsymmetricKeyAlgorithm::Ed448),
        "rsa-2048" => Ok(AsymmetricKeyAlgorithm::Rsa { bits: 2048 }),
        "rsa-3072" => Ok(AsymmetricKeyAlgorithm::Rsa { bits: 3072 }),
        "rsa-4096" => Ok(AsymmetricKeyAlgorithm::Rsa { bits: 4096 }),
        _ => Err(serde::de::Error::unknown_variant(
            &value,
            &[
                "ecdsa-p256",
                "ecdsa-p384",
                "ecdsa-p521",
                "ecdsa-secp256k1",
                "ed25519",
                "ed448",
                "rsa-2048",
                "rsa-3072",
                "rsa-4096",
            ],
        )),
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
    pub fn is_conformance(&self) -> bool {
        #[cfg(feature = "oidc-conformance")]
        {
            matches!(self, Self::Conformance)
        }
        #[cfg(not(feature = "oidc-conformance"))]
        {
            false
        }
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

const fn default_log_format() -> LogFormat {
    LogFormat::Compact
}

fn default_port() -> u16 {
    5150
}

fn default_binding() -> String {
    "127.0.0.1".to_owned()
}

fn default_internal_binding() -> String {
    "127.0.0.1".to_owned()
}

const fn default_internal_port() -> u16 {
    5151
}

const fn default_rotation_check_interval_secs() -> u64 {
    60
}

const fn default_credential_lifetime_days() -> i64 {
    180
}

const fn default_rotate_before_expiry_days() -> i64 {
    30
}

const fn default_retire_after_secs() -> i64 {
    24 * 60 * 60
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

#[cfg(test)]
mod tests {
    use super::{AppConfig, AppEnvironment, LogFormat, TlsTermination, render_config_template};
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
        let config = serde_yml::from_str::<AppConfig>(
            r#"
database:
  uri: postgres://localhost/identity
"#,
        )
        .unwrap();

        assert_eq!(config.logger.level, "debug");
        assert_eq!(config.logger.format, LogFormat::Compact);
        assert_eq!(config.server.port, 5150);
        assert_eq!(config.server.binding, "127.0.0.1");
        assert_eq!(config.server.tls.termination, TlsTermination::Direct);
        assert_eq!(config.health.route, "/health");
        assert_eq!(config.graphql.server.port, None);
        assert_eq!(config.graphql.max_depth, 12);
        assert_eq!(config.graphql.max_complexity, 300);
        assert_eq!(config.graphql.max_page_size, 100);
        assert_eq!(config.graphql.timeout_secs, 10);
        assert_eq!(config.settings.refresh_interval_secs, 5);
        assert!(config.health.enable);
        assert!(config.health.checks.database);
        assert!(config.database.auto_migrate);
    }

    #[test]
    fn legacy_fixed_registration_token_config_is_rejected() {
        let result = serde_yml::from_str::<AppConfig>(
            r#"
openid_connect:
  dynamic_registration:
    initial_access_token: long-lived-secret
"#,
        );

        assert!(result.is_err());
    }

    #[test]
    #[cfg(feature = "oidc-conformance")]
    fn conformance_registration_token_config_is_explicit() {
        let config = serde_yml::from_str::<AppConfig>(
            r#"
openid_connect:
  dynamic_registration:
    conformance_initial_access_token: " test-secret "
"#,
        )
        .unwrap();

        assert_eq!(
            config
                .openid_connect
                .dynamic_registration
                .required_conformance_initial_access_token(),
            Some("test-secret")
        );
    }

    #[test]
    #[cfg(not(feature = "oidc-conformance"))]
    fn conformance_registration_token_config_requires_feature() {
        let result = serde_yml::from_str::<AppConfig>(
            r#"
openid_connect:
  dynamic_registration:
    conformance_initial_access_token: test-secret
"#,
        );

        assert!(result.is_err());
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

        assert_eq!(config.server.tls.termination, TlsTermination::Direct);
        assert!(config.server.tls.auto_generate);
        assert_eq!(config.server.tls.cert_path, "config/tls/server.crt");
        assert_eq!(config.server.tls.key_path, "config/tls/server.key");
        assert_eq!(config.server.tls.domain, None);
        assert!(config.server.tls.trusted_proxies.is_empty());
    }

    #[test]
    fn tls_domain_prefers_explicit_value() {
        let config: AppConfig = serde_yml::from_str(
            r#"
server:
  host: https://example.com
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
    fn graphql_cors_always_allows_the_configured_public_origin() {
        let config = serde_yml::from_str::<AppConfig>(
            r#"
server:
  host: https://identity.example.com:8443/base
database:
  uri: postgres://localhost/identity
"#,
        )
        .unwrap()
        .normalized();

        assert!(
            config
                .graphql
                .allowed_origins
                .contains(&"https://identity.example.com:8443".to_string())
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

    #[test]
    fn https_contract_rejects_plain_http_host() {
        let config: AppConfig = serde_yml::from_str(
            r#"
server:
  host: http://identity.example.com
  tls:
    termination: upstream
database:
  uri: postgres://localhost/identity
"#,
        )
        .unwrap();

        let error = config.validate_https_contract().unwrap_err();

        assert!(error.to_string().contains("must use https"));
    }

    #[test]
    fn https_contract_accepts_upstream_tls_termination() {
        let config: AppConfig = serde_yml::from_str(
            r#"
server:
  host: https://identity.example.com
  tls:
    termination: upstream
    trusted_proxies:
      - 10.0.0.0/8
internal:
  workloads:
    login:
      static_tokens:
        - file: config/secrets/login-workload-token
database:
  uri: postgres://localhost/identity
"#,
        )
        .unwrap();

        assert!(config.validate_https_contract().is_ok());
    }

    #[test]
    fn https_contract_accepts_an_explicit_direct_http_client() {
        let config: AppConfig = serde_yml::from_str(
            r#"
server:
  host: https://identity.example.com
  tls:
    termination: upstream
    direct_http_clients:
      - 10.42.1.7/32
internal:
  workloads:
    login:
      static_tokens:
        - file: config/secrets/login-workload-token
database:
  uri: postgres://localhost/identity
"#,
        )
        .unwrap();

        assert!(config.validate_https_contract().is_ok());
    }

    #[test]
    fn internal_login_workload_requires_an_authentication_method() {
        let config: AppConfig = serde_yml::from_str(
            r#"
server:
  host: https://identity.example.com
internal:
  server:
    binding: 127.0.0.1
    port: 5151
database:
  uri: postgres://localhost/identity
"#,
        )
        .unwrap();

        let error = config.validate_https_contract().unwrap_err();

        assert!(error.to_string().contains("workloads.login"));
    }

    #[test]
    fn kubernetes_service_account_authentication_is_accepted() {
        let config: AppConfig = serde_yml::from_str(
            r#"
server:
  host: https://identity.example.com
internal:
  workloads:
    login:
      kubernetes_service_account:
        enabled: true
database:
  uri: postgres://localhost/identity
"#,
        )
        .unwrap();

        assert!(config.validate_https_contract().is_ok());
        let kubernetes = &config.internal.workloads.login.kubernetes_service_account;
        assert!(kubernetes.enabled);
        assert_eq!(kubernetes.audience, "identity-internal");
        assert_eq!(kubernetes.service_account, "identity-login");
        assert_eq!(kubernetes.namespace, "default");
        assert!(kubernetes.ca_file.is_none());
        assert!(kubernetes.token_file.is_none());
    }

    #[test]
    fn kubernetes_service_account_identity_must_be_fully_scoped() {
        let mut config: AppConfig = serde_yml::from_str(
            r#"
server:
  host: https://identity.example.com
internal:
  workloads:
    login:
      kubernetes_service_account:
        enabled: true
database:
  uri: postgres://localhost/identity
"#,
        )
        .unwrap();
        config
            .internal
            .workloads
            .login
            .kubernetes_service_account
            .namespace = " ".to_owned();

        let error = config.validate_https_contract().unwrap_err();

        assert!(error.to_string().contains("namespace"));
    }

    #[test]
    fn rotation_can_run_without_an_additional_token() {
        let config: AppConfig = serde_yml::from_str(
            r#"
server:
  host: https://identity.example.com
internal:
  workloads:
    login:
      static_tokens:
        - file: config/secrets/login-workload-token
client_credential_rotation:
  enable: true
database:
  uri: postgres://localhost/identity
"#,
        )
        .unwrap();

        assert!(config.validate_https_contract().is_ok());
    }

    #[test]
    fn https_contract_rejects_upstream_tls_without_an_allowed_source() {
        let config: AppConfig = serde_yml::from_str(
            r#"
server:
  host: https://identity.example.com
  tls:
    termination: upstream
database:
  uri: postgres://localhost/identity
"#,
        )
        .unwrap();

        let error = config.validate_https_contract().unwrap_err();

        assert!(error.to_string().contains("trusted_proxies"));
    }
}
