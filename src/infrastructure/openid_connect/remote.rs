use std::{env, net::SocketAddr, time::Duration};

use async_trait::async_trait;
use http::HeaderMap;
use identity_application::{
    observability::outbound_trace,
    openid_connect::remote::{
        DEFAULT_REMOTE_DOCUMENT_MAX_BYTES, RemoteDocumentFetcher, RemoteFetchError,
        RemoteTransportError, RemoteUrlError, fetchable_url, resolved_address_is_allowed,
        validate_https_public_url,
    },
};
use reqwest::{Client, Error, StatusCode, redirect::Policy};
use tokio::net::lookup_host;
use tracing::Instrument as _;
use url::{Host, Url};

#[must_use]
pub fn conformance_mode_active() -> bool {
    conformance_mode_active_for(
        cfg!(feature = "oidc-conformance"),
        env::var("APP_ENV").ok().as_deref(),
    )
}

fn conformance_mode_active_for(feature_enabled: bool, app_env: Option<&str>) -> bool {
    feature_enabled && app_env.is_some_and(|value| value.trim().eq_ignore_ascii_case("conformance"))
}

#[must_use]
pub fn conformance_allows_invalid_certs() -> bool {
    conformance_mode_active()
}

/// Validates a target URL and resolves any domain name up front so the HTTP
/// client can pin connections to the validated `SocketAddr`s and avoid
/// DNS-rebinding TOCTOU.
pub(crate) async fn resolve_and_validate_target(
    url: &Url,
    allow_private_targets: bool,
    allow_insecure_scheme: bool,
) -> Result<Option<(String, Vec<SocketAddr>)>, RemoteFetchError> {
    if !allow_insecure_scheme && url.scheme() != "https" {
        return Err(RemoteFetchError::NotHttps);
    }

    if !allow_private_targets {
        if allow_insecure_scheme {
            // Even in insecure test mode, check IP literals and localhost via HTTPS check shape
            if let Err(RemoteUrlError::UnsafeHost) = validate_https_public_url(&https_equiv(url)) {
                return Err(RemoteFetchError::UnsafeHost);
            }
        } else {
            validate_https_public_url(url)?;
        }
    }

    let Some(Host::Domain(host)) = url.host() else {
        return Ok(None);
    };

    let port = url
        .port_or_known_default()
        .ok_or(RemoteFetchError::UnsafeHost)?;
    let addresses = lookup_host((host, port))
        .await
        .map_err(RemoteFetchError::ResolveFailed)?
        .collect::<Vec<_>>();

    if addresses.is_empty() {
        return Err(RemoteFetchError::UnsafeHost);
    }

    for address in &addresses {
        if !resolved_address_is_allowed(address.ip(), allow_private_targets) {
            return Err(RemoteFetchError::UnsafeHost);
        }
    }

    Ok(Some((host.to_owned(), addresses)))
}

fn https_equiv(url: &Url) -> Url {
    let mut candidate = url.clone();
    let _ = candidate.set_scheme("https");
    candidate
}

pub(crate) fn build_pinned_client(
    timeout: Duration,
    allow_invalid_certs: bool,
    pinned: Option<(&str, &[SocketAddr])>,
) -> Result<Client, Error> {
    let mut builder = Client::builder()
        .redirect(Policy::none())
        .connect_timeout(timeout)
        .timeout(timeout)
        .danger_accept_invalid_certs(allow_invalid_certs);
    if let Some((host, addrs)) = pinned {
        builder = builder.resolve_to_addrs(host, addrs);
    }
    builder.build()
}

pub struct HttpRemoteDocumentFetcher {
    timeout: Duration,
    allow_private_targets: bool,
    allow_invalid_certs: bool,
    allow_insecure_scheme: bool,
    direct_client: Client,
}

impl HttpRemoteDocumentFetcher {
    pub fn new(
        timeout: Duration,
        allow_private_targets: bool,
        allow_invalid_certs: bool,
    ) -> Result<Self, Error> {
        let direct_client = build_pinned_client(timeout, allow_invalid_certs, None)?;
        Ok(Self {
            timeout,
            allow_private_targets,
            allow_invalid_certs,
            allow_insecure_scheme: false,
            direct_client,
        })
    }

    pub fn request_uri_default() -> Result<Self, Error> {
        Self::new(
            Duration::from_secs(5),
            conformance_mode_active(),
            conformance_allows_invalid_certs(),
        )
    }

    #[cfg(any(test, feature = "test-support"))]
    pub fn for_test_local_http(timeout: Duration) -> Result<Self, Error> {
        let direct_client = build_pinned_client(timeout, false, None)?;
        Ok(Self {
            timeout,
            allow_private_targets: true,
            allow_invalid_certs: false,
            allow_insecure_scheme: true,
            direct_client,
        })
    }
}

#[async_trait]
impl RemoteDocumentFetcher for HttpRemoteDocumentFetcher {
    async fn fetch_https_public_document(
        &self,
        url: &Url,
        max_bytes: usize,
    ) -> Result<Vec<u8>, RemoteFetchError> {
        let pinned = resolve_and_validate_target(
            url,
            self.allow_private_targets,
            self.allow_insecure_scheme,
        )
        .await?;
        let client_owner;
        let client = match pinned.as_ref() {
            Some((host, addrs)) => {
                client_owner = build_pinned_client(
                    self.timeout,
                    self.allow_invalid_certs,
                    Some((host, addrs)),
                )
                .map_err(|error| {
                    RemoteFetchError::FetchFailed(RemoteTransportError::from_error(&error))
                })?;
                &client_owner
            }
            None => &self.direct_client,
        };
        fetch_document_with_client(client, url, max_bytes).await
    }
}

pub async fn fetch_document_with_client(
    client: &Client,
    url: &Url,
    max_bytes: usize,
) -> Result<Vec<u8>, RemoteFetchError> {
    let fetch_url = fetchable_url(url);
    let trace = outbound_trace();
    // JWKS and request_uri targets never receive internal trace context unless
    // the deployment explicitly allow-lists their origin.
    let mut headers = HeaderMap::new();
    trace.inject(&fetch_url, &mut headers);
    let span = trace.client_span("GET", &fetch_url);
    let mut response = client
        .get(fetch_url)
        .headers(headers)
        .send()
        .instrument(span.clone())
        .await
        .map_err(|error| RemoteFetchError::FetchFailed(RemoteTransportError::from_error(&error)))?;
    span.record("http.response.status_code", response.status().as_u16());

    if response.status() != StatusCode::OK {
        return Err(RemoteFetchError::NotOk);
    }

    if response
        .content_length()
        .is_some_and(|length| length > max_bytes as u64)
    {
        return Err(RemoteFetchError::TooLarge);
    }

    let mut body = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|error| RemoteFetchError::ReadFailed(RemoteTransportError::from_error(&error)))?
    {
        if body.len() + chunk.len() > max_bytes {
            return Err(RemoteFetchError::TooLarge);
        }

        body.extend_from_slice(&chunk);
    }

    Ok(body)
}

pub fn default_max_remote_document_bytes() -> usize {
    DEFAULT_REMOTE_DOCUMENT_MAX_BYTES
}

#[cfg(test)]
mod tests {
    use super::conformance_mode_active_for;

    #[test]
    fn conformance_mode_requires_feature_and_environment() {
        assert!(!conformance_mode_active_for(false, None));
        assert!(!conformance_mode_active_for(false, Some("conformance")));
        assert!(!conformance_mode_active_for(true, None));
        assert!(!conformance_mode_active_for(true, Some("production")));
        assert!(conformance_mode_active_for(true, Some(" conformance ")));
    }
}
