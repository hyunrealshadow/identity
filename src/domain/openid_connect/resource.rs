use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use url::Url;

use crate::{
    authorization::ids::PolicyVersion, client::model::ClientOid,
    client_authorization::AccessTokenPrincipal,
};

/// A resource server accepted by this authorization server.
///
/// `scopes` is a read-only projection of the live, enabled canonical scope rows
/// owned by the resource. It is never a second authorization definition.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OAuthResource {
    pub uri: String,
    pub scopes: Vec<String>,
    pub enabled: bool,
}

#[derive(Debug, thiserror::Error)]
#[error("resource repository error: {0}")]
pub struct OAuthResourceRepositoryError(pub String);

#[async_trait]
pub trait OAuthResourceRepository: Send + Sync {
    async fn find_by_uri(
        &self,
        uri: &str,
    ) -> Result<Option<OAuthResource>, OAuthResourceRepositoryError>;

    /// Exact client ceiling for one resource. Returning `None` means the
    /// adapter cannot express the relation (in-memory test adapters only);
    /// production adapters must return the exact live `client_scope` rows.
    ///
    /// A user principal may use every assigned row. A client principal acts
    /// for itself and may use only rows granted to the client.
    async fn client_scope_codes(
        &self,
        _client: ClientOid,
        _resource_uri: &str,
        _principal: AccessTokenPrincipal,
    ) -> Result<Option<Vec<String>>, OAuthResourceRepositoryError> {
        Ok(None)
    }

    /// Protocol scopes are not owned by an API resource. This ceiling also
    /// applies to identity-only requests that have no access-token audience.
    async fn client_protocol_scope_codes(
        &self,
        _client: ClientOid,
    ) -> Result<Option<Vec<String>>, OAuthResourceRepositoryError> {
        Ok(None)
    }

    /// Opaque semantic fingerprint of the live client ceiling: client identity,
    /// exact `client_scope` scope OIDs/codes, resources, OIDC issuance settings,
    /// platforms and stable credential identifiers. Display text and record
    /// optimistic-lock versions never participate.
    async fn client_authority_fingerprint(
        &self,
        _client: ClientOid,
    ) -> Result<Option<PolicyVersion>, OAuthResourceRepositoryError> {
        Ok(None)
    }
}

/// RFC 3986 absolute URI, with exact identifier spelling preserved.
pub fn valid_resource_uri(uri: &str) -> bool {
    let bytes = uri.as_bytes();
    if bytes.is_empty()
        || bytes
            .iter()
            .any(|b| !b.is_ascii_alphanumeric() && !b"-._~:/?[]@!$&'()*+,;=%".contains(b))
    {
        return false;
    }
    for (i, b) in bytes.iter().enumerate() {
        if *b == b'%'
            && (bytes.get(i + 1).is_none_or(|b| !b.is_ascii_hexdigit())
                || bytes.get(i + 2).is_none_or(|b| !b.is_ascii_hexdigit()))
        {
            return false;
        }
    }
    // RFC 3986 reserves square brackets for IP literals in the authority.
    let Some((_, remainder)) = uri.split_once(':') else {
        return false;
    };
    let outside_authority = remainder.strip_prefix("//").map_or(remainder, |authority| {
        authority
            .find(['/', '?'])
            .map_or("", |index| &authority[index..])
    });
    if outside_authority.contains(['[', ']']) {
        return false;
    }
    Url::parse(uri).is_ok_and(|url| url.fragment().is_none())
}

#[cfg(test)]
mod tests {
    use super::valid_resource_uri;

    #[test]
    fn resource_identifiers_require_absolute_fragment_free_rfc3986_uris() {
        for uri in [
            "urn:identity:graphql",
            "https://api.example.com/",
            "https://api.example.com?tenant=1",
            "https://api.example.com/%23part",
        ] {
            assert!(valid_resource_uri(uri), "{uri}");
        }
        for uri in [
            "",
            "/relative",
            "https://api.example.com/#",
            "https://api.example.com/#part",
            "https://api.example.com/%",
            "https://api.example.com/%ZZ",
            "https://api.example.com/a b",
            "https://api.example.com/中文",
            " https://api.example.com",
            "urn:x\n",
            "urn:x[part]",
            "https://api.example.com/path[part]",
            "https://api.example.com/?q=[part]",
        ] {
            assert!(!valid_resource_uri(uri), "{uri}");
        }
    }
}
