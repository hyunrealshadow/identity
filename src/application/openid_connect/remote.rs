use std::time::Duration;

use url::Url;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RemoteUrlError {
    NotHttps,
    UnsafeHost,
}

#[derive(Debug, thiserror::Error)]
pub enum RemoteFetchError {
    #[error("remote URL must use https")]
    NotHttps,
    #[error("remote URL points to an unsafe host")]
    UnsafeHost,
    #[error("failed to fetch remote document")]
    FetchFailed(#[source] reqwest::Error),
    #[error("remote document did not return 200 OK")]
    NotOk,
    #[error("remote document is too large")]
    TooLarge,
    #[error("failed to read remote document")]
    ReadFailed(#[source] reqwest::Error),
}

#[derive(Clone, Copy)]
pub struct RemoteFetchPolicy {
    pub max_bytes: usize,
    pub timeout: Duration,
    pub allow_invalid_certs: bool,
}

impl RemoteFetchPolicy {
    #[must_use]
    pub const fn new(max_bytes: usize, timeout: Duration, allow_invalid_certs: bool) -> Self {
        Self {
            max_bytes,
            timeout,
            allow_invalid_certs,
        }
    }
}

pub const DEFAULT_REMOTE_DOCUMENT_MAX_BYTES: usize = 1024 * 1024;

#[must_use]
pub fn conformance_allows_invalid_certs() -> bool {
    cfg!(feature = "oidc-conformance")
        || std::env::var("APP_ENV")
            .map(|value| value.eq_ignore_ascii_case("conformance"))
            .unwrap_or(false)
}

pub fn validate_https_public_url(url: &Url) -> Result<(), RemoteUrlError> {
    if url.scheme() != "https" {
        return Err(RemoteUrlError::NotHttps);
    }

    if is_unsafe_host(url) {
        return Err(RemoteUrlError::UnsafeHost);
    }

    Ok(())
}

fn is_unsafe_host(url: &Url) -> bool {
    match url.host() {
        Some(url::Host::Ipv4(address)) => {
            let octets = address.octets();
            address.is_loopback()
                || address.is_unspecified()
                || octets[0] == 10
                || (octets[0] == 172 && (16..=31).contains(&octets[1]))
                || (octets[0] == 192 && octets[1] == 168)
                || (octets[0] == 169 && octets[1] == 254)
        }
        Some(url::Host::Ipv6(address)) => {
            let segments = address.segments();
            address.is_loopback()
                || address.is_unspecified()
                || (segments[0] & 0xfe00) == 0xfc00
                || (segments[0] & 0xffc0) == 0xfe80
        }
        Some(url::Host::Domain(domain)) => domain.eq_ignore_ascii_case("localhost"),
        None => true,
    }
}

pub async fn fetch_https_public_document(
    client: &reqwest::Client,
    url: &Url,
    max_bytes: usize,
) -> Result<Vec<u8>, RemoteFetchError> {
    validate_https_public_url(url).map_err(|error| match error {
        RemoteUrlError::NotHttps => RemoteFetchError::NotHttps,
        RemoteUrlError::UnsafeHost => RemoteFetchError::UnsafeHost,
    })?;

    fetch_document_after_url_validation(client, url, max_bytes).await
}

pub async fn fetch_document_after_url_validation(
    client: &reqwest::Client,
    url: &Url,
    max_bytes: usize,
) -> Result<Vec<u8>, RemoteFetchError> {
    let mut response = client
        .get(fetchable_url(url))
        .send()
        .await
        .map_err(RemoteFetchError::FetchFailed)?;

    if response.status() != reqwest::StatusCode::OK {
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
        .map_err(RemoteFetchError::ReadFailed)?
    {
        if body.len() + chunk.len() > max_bytes {
            return Err(RemoteFetchError::TooLarge);
        }

        body.extend_from_slice(&chunk);
    }

    Ok(body)
}

pub fn remote_http_client(policy: RemoteFetchPolicy) -> Result<reqwest::Client, reqwest::Error> {
    reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(policy.timeout)
        .danger_accept_invalid_certs(policy.allow_invalid_certs)
        .build()
}

#[must_use]
pub fn fetchable_url(url: &Url) -> Url {
    let mut fetch_url = url.clone();
    fetch_url.set_fragment(None);
    fetch_url
}

#[cfg(test)]
mod tests {
    use super::{RemoteUrlError, fetchable_url, validate_https_public_url};
    use url::Url;

    #[test]
    fn validate_https_public_url_rejects_non_https() {
        let url = Url::parse("http://example.com/jwks.json").unwrap();

        assert_eq!(
            validate_https_public_url(&url),
            Err(RemoteUrlError::NotHttps)
        );
    }

    #[test]
    fn validate_https_public_url_rejects_loopback_and_private_hosts() {
        for raw in [
            "https://127.0.0.1/jwks.json",
            "https://10.0.0.5/jwks.json",
            "https://172.16.0.5/jwks.json",
            "https://192.168.1.5/jwks.json",
            "https://169.254.1.5/jwks.json",
            "https://[::1]/jwks.json",
            "https://[fc00::1]/jwks.json",
            "https://[fe80::1]/jwks.json",
            "https://localhost/jwks.json",
        ] {
            let url = Url::parse(raw).unwrap();

            assert_eq!(
                validate_https_public_url(&url),
                Err(RemoteUrlError::UnsafeHost),
                "{raw} should be rejected"
            );
        }
    }

    #[test]
    fn validate_https_public_url_accepts_public_https_domain() {
        let url = Url::parse("https://rp.example.com/jwks.json").unwrap();

        assert_eq!(validate_https_public_url(&url), Ok(()));
    }

    #[test]
    fn fetchable_url_strips_fragment() {
        let url = Url::parse("https://rp.example.com/request.jwt#fragment").unwrap();

        assert_eq!(
            fetchable_url(&url).as_str(),
            "https://rp.example.com/request.jwt"
        );
    }
}
