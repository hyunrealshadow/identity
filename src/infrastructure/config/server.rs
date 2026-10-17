use super::default_true;
use ipnet::IpNet;
use serde::Deserialize;
use url::Url;

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

pub(super) fn default_tls_domain_from_host(host: Option<&str>) -> String {
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
