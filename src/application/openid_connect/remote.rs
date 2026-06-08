use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    time::Duration,
};

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
    #[error("failed to resolve remote host")]
    ResolveFailed(#[source] std::io::Error),
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
        Some(url::Host::Ipv4(address)) => is_unsafe_ipv4(address),
        Some(url::Host::Ipv6(address)) => is_unsafe_ipv6(address),
        Some(url::Host::Domain(domain)) => {
            let domain = domain.trim_end_matches('.');
            domain.eq_ignore_ascii_case("localhost")
                || domain
                    .rsplit_once('.')
                    .is_some_and(|(_, suffix)| suffix.eq_ignore_ascii_case("localhost"))
        }
        None => true,
    }
}

fn is_unsafe_ip(address: IpAddr) -> bool {
    match address {
        IpAddr::V4(address) => is_unsafe_ipv4(address),
        IpAddr::V6(address) => is_unsafe_ipv6(address),
    }
}

fn is_unsafe_ipv4(address: Ipv4Addr) -> bool {
    let octets = address.octets();
    address.is_loopback()
        || address.is_unspecified()
        || address.is_private()
        || address.is_link_local()
        || address.is_broadcast()
        || address.is_documentation()
        || address.is_multicast()
        || (octets[0] == 100 && (64..=127).contains(&octets[1]))
        || (octets[0] == 198 && (18..=19).contains(&octets[1]))
}

fn is_unsafe_ipv6(address: Ipv6Addr) -> bool {
    let segments = address.segments();
    address.is_loopback()
        || address.is_unspecified()
        || address.is_unique_local()
        || address.is_unicast_link_local()
        || address.is_multicast()
        || (segments[0] == 0x2001 && segments[1] == 0x0db8)
}

pub async fn fetch_https_public_document(
    client: &reqwest::Client,
    url: &Url,
    max_bytes: usize,
) -> Result<Vec<u8>, RemoteFetchError> {
    validate_resolved_https_public_url(url).await?;

    fetch_document_after_url_validation(client, url, max_bytes).await
}

pub async fn validate_resolved_https_public_url(url: &Url) -> Result<(), RemoteFetchError> {
    validate_https_public_url(url).map_err(|error| match error {
        RemoteUrlError::NotHttps => RemoteFetchError::NotHttps,
        RemoteUrlError::UnsafeHost => RemoteFetchError::UnsafeHost,
    })?;

    let Some(url::Host::Domain(host)) = url.host() else {
        return Ok(());
    };

    let port = url
        .port_or_known_default()
        .ok_or(RemoteFetchError::UnsafeHost)?;
    let mut addresses = tokio::net::lookup_host((host, port))
        .await
        .map_err(RemoteFetchError::ResolveFailed)?;
    let mut has_address = false;

    for address in addresses.by_ref() {
        has_address = true;
        if is_unsafe_ip(address.ip()) {
            return Err(RemoteFetchError::UnsafeHost);
        }
    }

    if !has_address {
        return Err(RemoteFetchError::UnsafeHost);
    }

    Ok(())
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
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    use super::{RemoteUrlError, fetchable_url, is_unsafe_ip, validate_https_public_url};
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
            "https://100.64.0.1/jwks.json",
            "https://198.18.0.1/jwks.json",
            "https://224.0.0.1/jwks.json",
            "https://192.0.2.1/jwks.json",
            "https://[::1]/jwks.json",
            "https://[fc00::1]/jwks.json",
            "https://[fe80::1]/jwks.json",
            "https://[2001:db8::1]/jwks.json",
            "https://localhost/jwks.json",
            "https://app.localhost/jwks.json",
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
    fn resolved_address_policy_rejects_non_public_addresses() {
        for address in [
            IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            IpAddr::V4(Ipv4Addr::new(100, 64, 0, 1)),
            IpAddr::V4(Ipv4Addr::new(198, 18, 0, 1)),
            IpAddr::V6(Ipv6Addr::LOCALHOST),
            IpAddr::V6("fc00::1".parse().unwrap()),
            IpAddr::V6("fe80::1".parse().unwrap()),
            IpAddr::V6("2001:db8::1".parse().unwrap()),
        ] {
            assert!(is_unsafe_ip(address), "{address} should be rejected");
        }
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
