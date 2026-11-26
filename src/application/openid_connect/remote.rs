use std::{
    error::Error as StdError,
    io::Error as IoError,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
};

use async_trait::async_trait;
use url::{Host, Url};

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{0}")]
pub struct RemoteTransportError(pub String);

impl RemoteTransportError {
    #[must_use]
    pub fn from_error(error: &dyn StdError) -> Self {
        Self(error.to_string())
    }
}

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
    FetchFailed(#[source] RemoteTransportError),
    #[error("failed to resolve remote host")]
    ResolveFailed(#[source] IoError),
    #[error("remote document did not return 200 OK")]
    NotOk,
    #[error("remote document is too large")]
    TooLarge,
    #[error("failed to read remote document")]
    ReadFailed(#[source] RemoteTransportError),
}

impl From<RemoteUrlError> for RemoteFetchError {
    fn from(error: RemoteUrlError) -> Self {
        match error {
            RemoteUrlError::NotHttps => Self::NotHttps,
            RemoteUrlError::UnsafeHost => Self::UnsafeHost,
        }
    }
}

pub const DEFAULT_REMOTE_DOCUMENT_MAX_BYTES: usize = 1024 * 1024;

/// Application port for fetching bounded HTTPS documents from public remote
/// endpoints (request_uri, client JWKS URI, sector_identifier_uri).
#[async_trait]
pub trait RemoteDocumentFetcher: Send + Sync {
    async fn fetch_https_public_document(
        &self,
        url: &Url,
        max_bytes: usize,
    ) -> Result<Vec<u8>, RemoteFetchError>;
}

/// Fail-closed default fetcher when no HTTP transport adapter is attached.
pub struct UnconfiguredRemoteDocumentFetcher;

#[async_trait]
impl RemoteDocumentFetcher for UnconfiguredRemoteDocumentFetcher {
    async fn fetch_https_public_document(
        &self,
        url: &Url,
        _max_bytes: usize,
    ) -> Result<Vec<u8>, RemoteFetchError> {
        validate_https_public_url(url)?;
        Err(RemoteFetchError::FetchFailed(RemoteTransportError(
            "remote document fetcher is not configured".to_owned(),
        )))
    }
}

#[cfg(test)]
#[must_use]
pub fn test_remote_fetcher() -> std::sync::Arc<dyn RemoteDocumentFetcher> {
    std::sync::Arc::new(UnconfiguredRemoteDocumentFetcher)
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
        Some(Host::Ipv4(address)) => is_unsafe_ipv4(address),
        Some(Host::Ipv6(address)) => is_unsafe_ipv6(address),
        Some(Host::Domain(domain)) => {
            let domain = domain.trim_end_matches('.');
            domain.eq_ignore_ascii_case("localhost")
                || domain
                    .rsplit_once('.')
                    .is_some_and(|(_, suffix)| suffix.eq_ignore_ascii_case("localhost"))
        }
        None => true,
    }
}

#[must_use]
pub fn is_unsafe_ip(address: IpAddr) -> bool {
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
        || octets[0] == 0
        || (octets[0] == 100 && (64..=127).contains(&octets[1]))
        || (octets[0] == 198 && (18..=19).contains(&octets[1]))
}

fn is_unsafe_ipv6(address: Ipv6Addr) -> bool {
    if let Some(v4) = address.to_ipv4_mapped() {
        return is_unsafe_ipv4(v4);
    }
    let segments = address.segments();
    address.is_loopback()
        || address.is_unspecified()
        || address.is_unique_local()
        || address.is_unicast_link_local()
        || address.is_multicast()
        || (segments[0] == 0x2001 && segments[1] == 0x0db8)
}

#[must_use]
pub fn resolved_address_is_allowed(address: IpAddr, allow_unsafe: bool) -> bool {
    allow_unsafe || !is_unsafe_ip(address)
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

    use url::Url;

    use super::{
        RemoteUrlError, fetchable_url, is_unsafe_ip, resolved_address_is_allowed,
        validate_https_public_url,
    };

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
            "https://172.31.255.255/jwks.json",
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
            "https://[::ffff:127.0.0.1]/jwks.json",
            "https://[::ffff:169.254.169.254]/jwks.json",
            "https://[::ffff:10.0.0.1]/jwks.json",
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
            IpAddr::V6("::ffff:127.0.0.1".parse().unwrap()),
            IpAddr::V6("::ffff:169.254.169.254".parse().unwrap()),
            IpAddr::V6("::ffff:10.0.0.1".parse().unwrap()),
        ] {
            assert!(is_unsafe_ip(address), "{address} should be rejected");
        }
    }

    #[test]
    fn conformance_mode_can_fetch_documents_from_the_suite_network() {
        let address = IpAddr::V4(Ipv4Addr::new(172, 18, 0, 5));

        assert!(!resolved_address_is_allowed(address, false));
        assert!(resolved_address_is_allowed(address, true));
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
