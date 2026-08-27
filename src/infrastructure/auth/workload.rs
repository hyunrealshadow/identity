use std::{
    fs,
    path::PathBuf,
    sync::Arc,
    time::{Duration, Instant},
};

use async_trait::async_trait;
use josekit::jwt::{self, JwtPayload};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

use identity_domain::{
    key::PublicJwk,
    openid_connect::{AuthenticatedWorkload, BuiltInWorkload, WorkloadAuthenticator},
};

use crate::config::{KubernetesServiceAccountConfig, LoginWorkloadConfig};

const JWKS_CACHE_TTL: Duration = Duration::from_secs(5 * 60);

fn token_digest(token: &str) -> Vec<u8> {
    Sha256::digest(token.trim().as_bytes()).to_vec()
}

/// Builds the authenticator chain for the Login workload from configuration.
/// Static tokens come from the configured files (plus the
/// `IDENTITY_WORKLOAD_TOKEN` environment variable for local development);
/// the Kubernetes ServiceAccount adapter is appended when enabled.
pub fn build_login_workload_authenticator(
    config: &LoginWorkloadConfig,
) -> Result<Arc<dyn WorkloadAuthenticator>, String> {
    let mut adapters: Vec<Arc<dyn WorkloadAuthenticator>> = Vec::new();
    if !config.static_tokens.is_empty() {
        let files = config
            .static_tokens
            .iter()
            .filter_map(|source| source.file.as_deref())
            .map(PathBuf::from)
            .collect::<Vec<_>>();
        let inline_tokens = config
            .static_tokens
            .iter()
            .filter_map(|source| source.environment.as_deref())
            .map(|name| {
                std::env::var(name)
                    .map_err(|error| format!("failed to read static token from {name}: {error}"))
            })
            .collect::<Result<Vec<_>, _>>()?;
        adapters.push(Arc::new(StaticTokenWorkloadAuthenticator::new(
            files,
            inline_tokens,
        )?));
    }
    if config.kubernetes_service_account.enabled {
        let http = kubernetes_http_client(&config.kubernetes_service_account)?;
        adapters.push(Arc::new(
            KubernetesServiceAccountWorkloadAuthenticator::new(
                &config.kubernetes_service_account,
                http,
            ),
        ));
    }
    Ok(Arc::new(AnyWorkloadAuthenticator::new(adapters)))
}

fn kubernetes_http_client(
    config: &KubernetesServiceAccountConfig,
) -> Result<reqwest::Client, String> {
    let mut builder = reqwest::Client::builder();
    if let Some(path) = config.ca_file.as_deref() {
        let pem = fs::read(path).map_err(|error| {
            format!("failed to read Kubernetes issuer CA bundle {path}: {error}")
        })?;
        let certificates = reqwest::Certificate::from_pem_bundle(&pem).map_err(|error| {
            format!("failed to parse Kubernetes issuer CA bundle {path}: {error}")
        })?;
        if certificates.is_empty() {
            return Err(format!(
                "Kubernetes issuer CA bundle {path} contains no certificates"
            ));
        }
        builder = builder.tls_certs_merge(certificates);
    }
    builder
        .build()
        .map_err(|error| format!("failed to build Kubernetes issuer HTTP client: {error}"))
}

/// Authenticates the Login workload with a deployer-managed 256-bit static
/// token read from files (or an inline fallback for local development).
///
/// Token files are re-read on every authentication attempt so the accepted
/// set can change without restarting Identity.
pub struct StaticTokenWorkloadAuthenticator {
    files: Vec<PathBuf>,
    inline_digests: Vec<Vec<u8>>,
}

impl StaticTokenWorkloadAuthenticator {
    /// Creates the authenticator from token files plus resolved environment
    /// tokens. Fails when no source is configured.
    pub fn new(files: Vec<PathBuf>, inline_tokens: Vec<String>) -> Result<Self, String> {
        if files.is_empty() && inline_tokens.is_empty() {
            return Err(
                "login workload static token requires at least one token file or an inline token"
                    .to_owned(),
            );
        }
        let mut sources: Vec<String> = Vec::new();
        for file in &files {
            sources.push(fs::read_to_string(file).map_err(|error| {
                format!(
                    "failed to read login workload token file {}: {error}",
                    file.display()
                )
            })?);
        }
        sources.extend(inline_tokens.iter().cloned());
        if !sources
            .iter()
            .all(|token| token.trim().chars().count() >= 32)
        {
            return Err(
                "login workload static tokens must contain at least 32 characters".to_owned(),
            );
        }
        Ok(Self {
            files,
            inline_digests: inline_tokens
                .iter()
                .map(|token| token_digest(token))
                .collect(),
        })
    }

    fn read_digests(&self) -> Vec<Vec<u8>> {
        let mut digests: Vec<Vec<u8>> = self
            .files
            .iter()
            .filter_map(|file| fs::read_to_string(file).ok())
            .map(|token| token_digest(token.trim()))
            .collect();
        digests.extend(self.inline_digests.iter().cloned());
        digests
    }
}

#[async_trait]
impl WorkloadAuthenticator for StaticTokenWorkloadAuthenticator {
    async fn authenticate(&self, token: &str) -> Option<AuthenticatedWorkload> {
        let presented = token_digest(token);
        let valid = self
            .read_digests()
            .iter()
            .any(|expected| bool::from(presented.ct_eq(expected)));
        valid.then_some(AuthenticatedWorkload(BuiltInWorkload::Login))
    }
}

/// Authenticates the Login workload with a Kubernetes projected ServiceAccount
/// token. The token is verified against the cluster issuer's JWKS and must
/// carry the configured audience and the exact configured ServiceAccount
/// subject.
pub struct KubernetesServiceAccountWorkloadAuthenticator {
    config: KubernetesServiceAccountConfig,
    http: reqwest::Client,
    keys: tokio::sync::Mutex<Option<(Instant, Vec<PublicJwk>)>>,
}

impl KubernetesServiceAccountWorkloadAuthenticator {
    #[must_use]
    pub fn new(config: &KubernetesServiceAccountConfig, http: reqwest::Client) -> Self {
        Self {
            config: config.clone(),
            http,
            keys: tokio::sync::Mutex::new(None),
        }
    }

    fn request(&self, url: &str) -> Result<reqwest::RequestBuilder, String> {
        let request = self.http.get(url);
        let Some(path) = self.config.token_file.as_deref() else {
            return Ok(request);
        };
        let issuer = reqwest::Url::parse(&self.config.issuer)
            .map_err(|error| format!("invalid Kubernetes issuer URL: {error}"))?;
        let target = reqwest::Url::parse(url)
            .map_err(|error| format!("invalid Kubernetes discovery URL: {error}"))?;
        if issuer.origin() != target.origin() {
            return Ok(request);
        }
        let token = fs::read_to_string(path).map_err(|error| {
            format!("failed to read Kubernetes issuer bearer token {path}: {error}")
        })?;
        let token = token.trim();
        if token.is_empty() {
            return Err(format!(
                "Kubernetes issuer bearer token {path} must not be empty"
            ));
        }
        Ok(request.bearer_auth(token))
    }

    async fn jwks(&self) -> Result<Vec<PublicJwk>, String> {
        if let Some((fetched_at, keys)) = self.keys.lock().await.as_ref()
            && fetched_at.elapsed() < JWKS_CACHE_TTL
        {
            return Ok(keys.clone());
        }
        let discovery_url = format!(
            "{}/.well-known/openid-configuration",
            self.config.issuer.trim_end_matches('/')
        );
        let discovery: OidcDiscovery = self
            .request(&discovery_url)?
            .send()
            .await
            .map_err(|error| format!("failed to fetch cluster OIDC discovery: {error}"))?
            .error_for_status()
            .map_err(|error| format!("cluster OIDC discovery failed: {error}"))?
            .json()
            .await
            .map_err(|error| format!("invalid cluster OIDC discovery: {error}"))?;
        let jwks: Jwks = self
            .request(&discovery.jwks_uri)?
            .send()
            .await
            .map_err(|error| format!("failed to fetch cluster JWKS: {error}"))?
            .error_for_status()
            .map_err(|error| format!("cluster JWKS fetch failed: {error}"))?
            .json()
            .await
            .map_err(|error| format!("invalid cluster JWKS: {error}"))?;
        let keys = jwks
            .keys
            .into_iter()
            .filter_map(|key| {
                serde_json::from_value::<PublicJwk>(serde_json::to_value(key).ok()?).ok()
            })
            .collect::<Vec<_>>();
        if keys.is_empty() {
            return Err("cluster JWKS contained no usable keys".to_owned());
        }
        *self.keys.lock().await = Some((Instant::now(), keys.clone()));
        Ok(keys)
    }

    fn valid_claims(&self, payload: &JwtPayload) -> bool {
        let Some(subject) = payload.subject() else {
            return false;
        };
        let expected_subject = format!(
            "system:serviceaccount:{}:{}",
            self.config.namespace, self.config.service_account
        );
        if subject != expected_subject {
            return false;
        }
        if payload.issuer() != Some(self.config.issuer.as_str()) {
            return false;
        }
        let audience_matches = payload.audience().is_some_and(|audiences| {
            audiences
                .iter()
                .any(|audience| *audience == self.config.audience)
        });
        if !audience_matches {
            return false;
        }
        payload
            .expires_at()
            .is_some_and(|expires| expires > std::time::SystemTime::now())
    }
}

#[async_trait]
impl WorkloadAuthenticator for KubernetesServiceAccountWorkloadAuthenticator {
    async fn authenticate(&self, token: &str) -> Option<AuthenticatedWorkload> {
        if token.split('.').count() != 3 {
            return None;
        }
        let keys = self.jwks().await.ok()?;
        for key in keys {
            let alg = key.algorithm().unwrap_or("RS256");
            let Ok(verifier) =
                identity_application::openid_connect::jose::asymmetric_verifier_from_public_jwk(
                    alg, &key,
                )
            else {
                continue;
            };
            let Ok((payload, _)) = jwt::decode_with_verifier(token, &*verifier) else {
                continue;
            };
            if self.valid_claims(&payload) {
                return Some(AuthenticatedWorkload(BuiltInWorkload::Login));
            }
        }
        None
    }
}

/// Tries every configured adapter in order until one authenticates the
/// credential.
pub struct AnyWorkloadAuthenticator {
    adapters: Vec<Arc<dyn WorkloadAuthenticator>>,
}

impl AnyWorkloadAuthenticator {
    #[must_use]
    pub fn new(adapters: Vec<Arc<dyn WorkloadAuthenticator>>) -> Self {
        Self { adapters }
    }
}

#[async_trait]
impl WorkloadAuthenticator for AnyWorkloadAuthenticator {
    async fn authenticate(&self, token: &str) -> Option<AuthenticatedWorkload> {
        for adapter in &self.adapters {
            if let Some(workload) = adapter.authenticate(token).await {
                return Some(workload);
            }
        }
        None
    }
}

#[derive(Debug, Deserialize)]
struct OidcDiscovery {
    jwks_uri: String,
}

#[derive(Debug, Deserialize)]
struct Jwks {
    keys: Vec<serde_json::Value>,
}

#[cfg(test)]
mod tests {
    use std::{fs, path::PathBuf, time::Duration};

    use identity_domain::openid_connect::{
        AuthenticatedWorkload, BuiltInWorkload, WorkloadAuthenticator as _,
    };

    use josekit::jwt::JwtPayload;

    use crate::config::KubernetesServiceAccountConfig;

    use super::{KubernetesServiceAccountWorkloadAuthenticator, StaticTokenWorkloadAuthenticator};

    #[tokio::test]
    async fn static_token_accepts_configured_tokens() {
        let dir = std::env::temp_dir().join(format!("identity-wl-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        let current = dir.join("current");
        let previous = dir.join("previous");
        fs::write(&current, "current-workload-token-0123456789abcdef").unwrap();
        fs::write(&previous, "previous-workload-token-0123456789abcdef").unwrap();

        let authenticator = StaticTokenWorkloadAuthenticator::new(
            vec![PathBuf::from(&current), PathBuf::from(&previous)],
            Vec::new(),
        )
        .unwrap();

        assert_eq!(
            authenticator
                .authenticate("current-workload-token-0123456789abcdef")
                .await,
            Some(AuthenticatedWorkload(BuiltInWorkload::Login))
        );
        assert_eq!(
            authenticator
                .authenticate("previous-workload-token-0123456789abcdef")
                .await,
            Some(AuthenticatedWorkload(BuiltInWorkload::Login))
        );
        assert_eq!(
            authenticator.authenticate("wrong-workload-token").await,
            None
        );

        fs::remove_file(&current).ok();
        fs::remove_file(&previous).ok();
        fs::remove_dir(&dir).ok();
    }

    #[tokio::test]
    async fn static_token_normalizes_file_whitespace() {
        let dir = std::env::temp_dir().join(format!("identity-wl-trim-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        let token_file = dir.join("token");
        fs::write(&token_file, "workload-token-with-32-characters-minimum\r\n").unwrap();

        let authenticator =
            StaticTokenWorkloadAuthenticator::new(vec![token_file.clone()], Vec::new()).unwrap();

        assert_eq!(
            authenticator
                .authenticate("workload-token-with-32-characters-minimum")
                .await,
            Some(AuthenticatedWorkload(BuiltInWorkload::Login))
        );

        fs::remove_file(&token_file).ok();
        fs::remove_dir(&dir).ok();
    }

    #[tokio::test]
    async fn static_token_accepts_resolved_environment_tokens() {
        let token = "environment-workload-token-0123456789abcdef".to_owned();
        let authenticator =
            StaticTokenWorkloadAuthenticator::new(Vec::new(), vec![token.clone()]).unwrap();

        assert_eq!(
            authenticator.authenticate(&token).await,
            Some(AuthenticatedWorkload(BuiltInWorkload::Login))
        );
    }

    #[test]
    fn kubernetes_claims_require_exact_service_account_subject_and_expiry() {
        let config = KubernetesServiceAccountConfig {
            enabled: true,
            audience: "identity-internal".to_owned(),
            service_account: "identity-login".to_owned(),
            namespace: "identity".to_owned(),
            issuer: "https://kubernetes.default.svc.cluster.local".to_owned(),
            ca_file: None,
            token_file: None,
        };
        let authenticator =
            KubernetesServiceAccountWorkloadAuthenticator::new(&config, reqwest::Client::new());
        let mut payload = JwtPayload::new();
        payload.set_issuer(&config.issuer);
        payload.set_subject("system:serviceaccount:identity:identity-login");
        payload.set_audience(vec![config.audience.clone()]);
        payload.set_expires_at(&(std::time::SystemTime::now() + Duration::from_secs(60)));

        assert!(authenticator.valid_claims(&payload));

        payload.set_subject("system:serviceaccount:other:identity-login");
        assert!(!authenticator.valid_claims(&payload));

        payload.set_subject("system:serviceaccount:identity:identity-login");
        payload.set_claim("exp", None).unwrap();
        assert!(!authenticator.valid_claims(&payload));
    }

    #[test]
    fn kubernetes_http_client_rejects_a_missing_ca_bundle() {
        let config = KubernetesServiceAccountConfig {
            enabled: true,
            audience: "identity-internal".to_owned(),
            service_account: "identity-login".to_owned(),
            namespace: "identity".to_owned(),
            issuer: "https://kubernetes.default.svc.cluster.local".to_owned(),
            ca_file: Some("this-kubernetes-ca-does-not-exist.crt".to_owned()),
            token_file: None,
        };

        let error = super::kubernetes_http_client(&config).unwrap_err();

        assert!(error.contains("failed to read Kubernetes issuer CA bundle"));
    }

    #[test]
    fn kubernetes_request_rejects_a_missing_same_origin_bearer_token() {
        let config = KubernetesServiceAccountConfig {
            enabled: true,
            audience: "identity-internal".to_owned(),
            service_account: "identity-login".to_owned(),
            namespace: "identity".to_owned(),
            issuer: "https://kubernetes.default.svc.cluster.local".to_owned(),
            ca_file: None,
            token_file: Some("this-kubernetes-token-does-not-exist".to_owned()),
        };
        let authenticator =
            KubernetesServiceAccountWorkloadAuthenticator::new(&config, reqwest::Client::new());

        let error = authenticator
            .request("https://kubernetes.default.svc.cluster.local/openid/v1/jwks")
            .unwrap_err();

        assert!(error.contains("failed to read Kubernetes issuer bearer token"));
        assert!(
            authenticator
                .request("https://external.example.com/openid/v1/jwks")
                .is_ok()
        );
    }

    #[test]
    fn static_token_rejects_short_or_missing_sources() {
        let dir = std::env::temp_dir().join(format!("identity-wl-short-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        let short = dir.join("short");
        fs::write(&short, "too-short").unwrap();

        let error = StaticTokenWorkloadAuthenticator::new(vec![PathBuf::from(&short)], Vec::new())
            .err()
            .expect("short token must be rejected");
        assert!(error.contains("32 characters"));

        let error = StaticTokenWorkloadAuthenticator::new(Vec::new(), Vec::new())
            .err()
            .expect("missing sources must be rejected");
        assert!(error.contains("at least one token file"));

        fs::remove_file(&short).ok();
        fs::remove_dir(&dir).ok();
    }
}
