//! Tokens of emailed links. A link carries 32 random bytes; only their
//! SHA-256 digest is stored, so a leaked database cannot be turned into
//! working links. Comparisons run in constant time.

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use rand::RngExt;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

use crate::setting::AppSettings;

/// A freshly generated link token and the digest to store for it.
pub struct LinkToken {
    /// The value placed in the link. Never store or log it.
    pub token: String,
    pub digest: String,
}

impl LinkToken {
    #[must_use]
    pub fn generate() -> Self {
        let mut bytes = [0u8; 32];
        rand::rng().fill(&mut bytes);
        let token = URL_SAFE_NO_PAD.encode(bytes);
        let digest = link_digest(&token);
        Self { token, digest }
    }
}

impl std::fmt::Debug for LinkToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LinkToken").finish_non_exhaustive()
    }
}

/// SHA-256 of a presented link token, base64url. Surrounding whitespace that
/// a mail client may add is ignored.
#[must_use]
pub fn link_digest(token: &str) -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest(token.trim().as_bytes()))
}

/// Whether `token` has the shape of a link token, checked before any lookup.
#[must_use]
pub fn plausible_link_token(token: &str) -> bool {
    let token = token.trim();
    (32..=128).contains(&token.len())
        && token
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

/// Whether `token` is the link whose digest is `expected`.
#[must_use]
pub fn link_matches(token: &str, expected: &str) -> bool {
    plausible_link_token(token)
        && bool::from(link_digest(token).as_bytes().ct_eq(expected.as_bytes()))
}

/// The address of the Login page `route` up to where a link token is
/// appended, or `None` while the Login address is not configured.
#[must_use]
pub fn login_link_prefix(app: &AppSettings, route: &str) -> Option<String> {
    let login_domain = app
        .login_domain
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())?;
    let base = if login_domain.ends_with('/') {
        login_domain.to_owned()
    } else {
        format!("{login_domain}/")
    };
    let url = url::Url::parse(&base)
        .and_then(|base| base.join(route))
        .ok()?;
    // The token is base64url, so it needs no further encoding.
    Some(format!("{url}?token="))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_generated_link_matches_only_its_own_digest() {
        let link = LinkToken::generate();
        let other = LinkToken::generate();
        assert!(link_matches(&link.token, &link.digest));
        assert!(link_matches(&format!(" {}\n", link.token), &link.digest));
        assert!(!link_matches(&other.token, &link.digest));
        assert!(!link_matches("", &link.digest));
        assert!(!link_matches("not a token!", &link_digest("not a token!")));
    }
}
