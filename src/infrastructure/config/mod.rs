//! Application configuration loading, normalization, and validation.

use std::{
    env,
    error::Error,
    fs,
    io::{Error as IoError, ErrorKind},
};

use serde::Deserialize;
use serde_yml::from_str;
use tera::{Context, Error as TeraError, Kwargs, State, Tera, TeraResult, Value};
use url::Url;

pub type ConfigResult<T> = Result<T, Box<dyn Error + Send + Sync + 'static>>;

mod endpoints;
mod install;
mod logging;
mod observability;
mod openid_connect;
mod server;
mod storage;
mod workloads;

pub use endpoints::{
    GraphqlConfig, GraphqlServerConfig, HealthChecksConfig, HealthConfig, HealthServerConfig,
};
pub use install::InstallConfig;
pub use logging::{LogFormat, LoggerConfig};
pub use openid_connect::{DynamicClientRegistrationConfig, OpenIdConnectConfig};
pub use server::{ServerConfig, TlsConfig, TlsTermination};
pub use storage::{DatabaseConfig, SettingsConfig};
pub use workloads::{
    InternalConfig, InternalServerConfig, KubernetesServiceAccountConfig, LoginWorkloadConfig,
    StaticTokenConfig, WorkloadsConfig,
};

use server::default_tls_domain_from_host;

#[cfg(test)]
mod tests;

pub use observability::{
    DiagnosticsPipelineConfig, EventsPipelineConfig, ObservabilityConfig, OtlpCompression,
    OtlpConfig, PiiConfig, SamplingConfig, SecretSourceConfig, SelfMetricsConfig,
    TraceContextConfig,
};

#[derive(Clone, Debug, Deserialize)]
pub struct AppConfig {
    #[serde(default)]
    pub logger: LoggerConfig,
    #[serde(default)]
    pub observability: ObservabilityConfig,
    #[serde(default)]
    pub server: ServerConfig,
    #[serde(default)]
    pub internal: InternalConfig,
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

impl AppConfig {
    pub fn load() -> ConfigResult<(Self, AppEnvironment)> {
        let environment = AppEnvironment::detect();
        let path = format!("config/{}.yaml", environment.as_str());
        let raw = fs::read_to_string(&path)?;
        let rendered = render_config_template(&raw)?;
        let config: Self = from_str(&rendered)?;
        let config = config.normalized();
        config.validate_https_contract()?;
        config.observability.validate()?;

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
                "each login static token must configure exactly one of file, environment, or token",
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
        Ok(())
    }
}

fn invalid_config(message: impl Into<String>) -> IoError {
    IoError::new(ErrorKind::InvalidInput, message.into())
}

fn render_config_template(raw: &str) -> ConfigResult<String> {
    let mut tera = Tera::default();
    tera.register_function("get_env", |args: Kwargs, _: &State| -> TeraResult<Value> {
        let name = args.must_get::<String>("name")?;
        match env::var(&name) {
            Ok(value) => Ok(Value::from(value)),
            Err(error) => args
                .get::<Value>("default")?
                .ok_or_else(|| TeraError::message(format!("get_env({name}): {error}"))),
        }
    });
    tera.add_raw_template("config", raw)?;
    Ok(tera.render("config", &Context::new())?)
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
