use std::{fmt, str::FromStr};

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use sha2::{Digest, Sha256};
use strum::{AsRefStr, Display, EnumIter, IntoEnumIterator};
use url::Url;

use crate::client::model::Client;
use crate::key::{JwaEncryptionAlgorithm, JweContentEncryption, JwsAlgorithm};
use crate::openid_connect::ResponseType;
use crate::openid_connect::model::provider::{SubjectType, TokenEndpointAuthMethod};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum GrantType {
    AuthorizationCode,
    Implicit,
    RefreshToken,
    ClientCredentials,
    DeviceCode,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("invalid grant type")]
pub struct ParseGrantTypeError;

impl GrantType {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::AuthorizationCode => "authorization_code",
            Self::Implicit => "implicit",
            Self::RefreshToken => "refresh_token",
            Self::ClientCredentials => "client_credentials",
            Self::DeviceCode => "urn:ietf:params:oauth:grant-type:device_code",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ClientAssertionType {
    JwtBearer,
}

impl ClientAssertionType {
    pub const JWT_BEARER_VALUE: &'static str =
        "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";

    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::JwtBearer => Self::JWT_BEARER_VALUE,
        }
    }
}

impl fmt::Display for ClientAssertionType {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("invalid OAuth client assertion type")]
pub struct ParseClientAssertionTypeError;

impl FromStr for ClientAssertionType {
    type Err = ParseClientAssertionTypeError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            Self::JWT_BEARER_VALUE => Ok(Self::JwtBearer),
            _ => Err(ParseClientAssertionTypeError),
        }
    }
}

impl fmt::Display for GrantType {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl FromStr for GrantType {
    type Err = ParseGrantTypeError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "authorization_code" => Ok(Self::AuthorizationCode),
            "implicit" => Ok(Self::Implicit),
            "refresh_token" => Ok(Self::RefreshToken),
            "client_credentials" => Ok(Self::ClientCredentials),
            "urn:ietf:params:oauth:grant-type:device_code" => Ok(Self::DeviceCode),
            _ => Err(ParseGrantTypeError),
        }
    }
}

/// OAuth rules used for this client's authorization code exchanges.
/// OpenID Connect is an additional protocol layer, not a version of OAuth.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, serde::Deserialize, serde::Serialize)]
pub enum OAuthProtocolVersion {
    #[default]
    #[serde(rename = "2.0")]
    V2_0,
    #[serde(rename = "2.1")]
    V2_1,
}

#[derive(Debug, Clone, PartialEq, Eq, Default, serde::Deserialize, serde::Serialize)]
pub struct OpenIdConnectClientSettings {
    #[serde(default)]
    pub skip_consent: bool,
    /// Explicitly trusted confidential OIDC clients may use a transaction-bound
    /// nonce instead of PKCE for authorization code injection protection.
    #[serde(default)]
    pub allow_nonce_without_pkce: bool,
    /// Defaults to OAuth 2.0 for clients whose stored settings predate this field.
    #[serde(default)]
    pub oauth_version: OAuthProtocolVersion,
    /// Allows browser requests from the origins of this client's registered
    /// HTTP(S) redirect URIs at CORS-enabled OAuth endpoints.
    #[serde(default)]
    pub cors_enabled: bool,
    /// When enabled, the token endpoint includes the standard claims the granted
    /// scopes cover (`profile`/`email`/`phone`/`address`) in issued ID Tokens,
    /// matching the implicit-flow behaviour. Defaults to off (current behaviour).
    #[serde(default)]
    pub include_scoped_claims_in_id_token: bool,
    /// Includes standard user claims covered by the granted scopes in access
    /// tokens issued for a user. Machine tokens have no user claims.
    #[serde(default)]
    pub include_scoped_claims_in_access_token: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Display, AsRefStr, EnumIter)]
#[strum(serialize_all = "snake_case")]
pub enum OpenIdConnectClientPlatformType {
    Web,
    Native,
}

impl OpenIdConnectClientPlatformType {
    #[must_use]
    pub fn allows_redirect_uri_scheme(&self, uri: &Url) -> bool {
        match uri.scheme() {
            "https" => true,
            "http" => {
                uri.host_str() == Some("localhost")
                    || (*self == Self::Native
                        && matches!(
                            uri.host(),
                            Some(url::Host::Ipv4(std::net::Ipv4Addr::LOCALHOST))
                                | Some(url::Host::Ipv6(std::net::Ipv6Addr::LOCALHOST))
                        ))
            }
            _ => *self == Self::Native,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParseOpenIdConnectClientPlatformKindError;

impl fmt::Display for ParseOpenIdConnectClientPlatformKindError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("invalid openid connect client platform")
    }
}

impl std::error::Error for ParseOpenIdConnectClientPlatformKindError {}

impl FromStr for OpenIdConnectClientPlatformType {
    type Err = ParseOpenIdConnectClientPlatformKindError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::iter()
            .find(|variant| variant.as_ref() == value)
            .ok_or(ParseOpenIdConnectClientPlatformKindError)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpenIdConnectClientPlatform {
    pub platform: OpenIdConnectClientPlatformType,
    /// Preserve the registered spelling for OAuth's simple string comparison.
    pub redirect_uris: Vec<String>,
}

/// Grant types a client may use when its registration omitted `grant_types`.
///
/// RFC 7591 §2 defines `authorization_code` as the registration default, so a
/// stored `None` (legacy rows and registrations that omitted the field) allows
/// only the code flow. An explicitly registered empty list allows no grant.
pub const DEFAULT_GRANT_TYPES: [GrantType; 1] = [GrantType::AuthorizationCode];
pub const DEFAULT_TOKEN_ENDPOINT_AUTH_METHODS: [TokenEndpointAuthMethod; 1] =
    [TokenEndpointAuthMethod::ClientSecretBasic];

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct OpenIdConnectClientMetadata {
    pub post_logout_redirect_uris: Option<Vec<Url>>,
    pub frontchannel_logout_uri: Option<Url>,
    pub frontchannel_logout_session_required: Option<bool>,
    pub backchannel_logout_uri: Option<Url>,
    pub backchannel_logout_session_required: Option<bool>,
    pub response_types: Option<Vec<ResponseType>>,
    pub grant_types: Option<Vec<GrantType>>,
    pub contacts: Option<Vec<String>>,
    pub logo_uri: Option<Url>,
    pub client_uri: Option<Url>,
    pub policy_uri: Option<Url>,
    pub tos_uri: Option<Url>,
    pub sector_identifier_uri: Option<Url>,
    pub subject_type: Option<SubjectType>,
    pub id_token_signed_response_algs: Option<Vec<JwsAlgorithm>>,
    pub id_token_encrypted_response_algs: Option<Vec<JwaEncryptionAlgorithm>>,
    pub id_token_encrypted_response_encs: Option<Vec<JweContentEncryption>>,
    pub userinfo_signed_response_algs: Option<Vec<JwsAlgorithm>>,
    pub userinfo_encrypted_response_algs: Option<Vec<JwaEncryptionAlgorithm>>,
    pub userinfo_encrypted_response_encs: Option<Vec<JweContentEncryption>>,
    pub request_object_signing_algs: Option<Vec<JwsAlgorithm>>,
    pub request_object_encryption_algs: Option<Vec<JwaEncryptionAlgorithm>>,
    pub request_object_encryption_encs: Option<Vec<JweContentEncryption>>,
    pub token_endpoint_auth_methods: Option<Vec<TokenEndpointAuthMethod>>,
    pub token_endpoint_auth_signing_algs: Option<Vec<JwsAlgorithm>>,
    pub default_max_age: Option<i32>,
    pub require_auth_time: Option<bool>,
    pub default_acr_values: Option<Vec<String>>,
    pub initiate_login_uri: Option<Url>,
    pub request_uris: Option<Vec<Url>>,
    pub settings: OpenIdConnectClientSettings,
}

impl OpenIdConnectClientMetadata {
    /// Grant types this registration permits.
    ///
    /// `None` falls back to [`DEFAULT_GRANT_TYPES`]; `Some([])` permits none.
    #[must_use]
    pub fn effective_grant_types(&self) -> &[GrantType] {
        self.grant_types.as_deref().unwrap_or(&DEFAULT_GRANT_TYPES)
    }

    #[must_use]
    pub fn allows_grant(&self, grant: GrantType) -> bool {
        self.effective_grant_types().contains(&grant)
    }

    #[must_use]
    pub fn effective_token_endpoint_auth_methods(&self) -> &[TokenEndpointAuthMethod] {
        self.token_endpoint_auth_methods
            .as_deref()
            .unwrap_or(&DEFAULT_TOKEN_ENDPOINT_AUTH_METHODS)
    }

    #[must_use]
    pub fn allows_token_endpoint_auth_method(&self, method: TokenEndpointAuthMethod) -> bool {
        self.effective_token_endpoint_auth_methods()
            .contains(&method)
    }
}

pub fn pairwise_subject_identifier(
    user_oid: uuid::Uuid,
    sector_identifier: &str,
    issuer: &Url,
) -> String {
    let mut digest = Sha256::new();
    digest.update(sector_identifier.as_bytes());
    digest.update(b"\0");
    digest.update(user_oid.as_bytes());
    digest.update(b"\0");
    digest.update(issuer.as_str().as_bytes());
    URL_SAFE_NO_PAD.encode(digest.finalize())
}

#[derive(Debug, Clone)]
pub struct OpenIdConnectClient {
    client: Client,
    metadata: OpenIdConnectClientMetadata,
    platforms: Vec<OpenIdConnectClientPlatform>,
    assigned_scopes: Vec<String>,
}

impl OpenIdConnectClient {
    pub fn new(
        client: Client,
        metadata: OpenIdConnectClientMetadata,
        platforms: Vec<OpenIdConnectClientPlatform>,
        assigned_scopes: Vec<String>,
    ) -> Result<Self, InvalidOpenIdConnectClientError> {
        if client.protocol != crate::client::model::ClientProtocol::OpenIdConnect {
            return Err(InvalidOpenIdConnectClientError);
        }

        Ok(Self {
            client,
            metadata,
            platforms,
            assigned_scopes,
        })
    }

    pub fn client(&self) -> &Client {
        &self.client
    }

    pub fn metadata(&self) -> &OpenIdConnectClientMetadata {
        &self.metadata
    }

    pub fn platforms(&self) -> &[OpenIdConnectClientPlatform] {
        &self.platforms
    }

    #[must_use]
    pub fn single_redirect_uri(&self) -> Option<&str> {
        let mut registered = self
            .platforms
            .iter()
            .flat_map(|platform| platform.redirect_uris.iter());
        registered
            .next()
            .filter(|_| registered.next().is_none())
            .map(String::as_str)
    }

    pub fn has_redirect_uri_str(&self, raw_redirect_uri: &str) -> bool {
        let Ok(requested) = Url::parse(raw_redirect_uri) else {
            return false;
        };
        self.platforms.iter().any(|platform| {
            platform.redirect_uris.iter().any(|registered| {
                let Ok(registered_url) = Url::parse(registered) else {
                    return false;
                };
                if !platform
                    .platform
                    .allows_redirect_uri_scheme(&registered_url)
                    || !platform.platform.allows_redirect_uri_scheme(&requested)
                {
                    return false;
                }
                if registered == raw_redirect_uri {
                    return true;
                }
                let raw_host = match registered_url.host() {
                    Some(url::Host::Domain("localhost")) => "http://localhost",
                    Some(url::Host::Ipv4(ip)) if ip == std::net::Ipv4Addr::LOCALHOST => {
                        "http://127.0.0.1"
                    }
                    Some(url::Host::Ipv6(ip)) if ip == std::net::Ipv6Addr::LOCALHOST => {
                        "http://[::1]"
                    }
                    _ => return false,
                };
                if platform.platform != OpenIdConnectClientPlatformType::Native
                    || registered_url.scheme() != "http"
                    || requested.host() != registered_url.host()
                {
                    return false;
                }
                let Some(registered_suffix) = registered.strip_prefix(raw_host) else {
                    return false;
                };
                let Some(requested_suffix) = raw_redirect_uri.strip_prefix(raw_host) else {
                    return false;
                };
                matches!(
                    (
                        strip_loopback_port(registered_suffix),
                        strip_loopback_port(requested_suffix),
                    ),
                    (Some(registered_path), Some(requested_path))
                        if registered_path == requested_path
                )
            })
        })
    }

    pub fn assigned_scopes(&self) -> &[String] {
        &self.assigned_scopes
    }

    pub fn has_assigned_scope(&self, scope_name: &str) -> bool {
        self.assigned_scopes
            .iter()
            .any(|assigned| assigned == scope_name)
    }

    /// Whether this client's registration permits the given grant type.
    #[must_use]
    pub fn allows_grant(&self, grant: GrantType) -> bool {
        self.metadata.allows_grant(grant)
    }

    /// Whether this client may request the given `response_type`, which
    /// requires every grant the response type relies on.
    #[must_use]
    pub fn allows_response_type(&self, response_type: &ResponseType) -> bool {
        self.metadata
            .response_types
            .as_ref()
            .is_none_or(|registered| registered.contains(response_type))
            && response_type
                .required_grants()
                .iter()
                .all(|grant| self.allows_grant(*grant))
    }

    pub fn subject_identifier(&self, user_oid: uuid::Uuid, issuer: &Url) -> String {
        match self.metadata.subject_type.unwrap_or(SubjectType::Public) {
            SubjectType::Public => user_oid.to_string(),
            SubjectType::Pairwise => {
                let sector_identifier = self
                    .metadata
                    .sector_identifier_uri
                    .as_ref()
                    .and_then(Url::host_str)
                    .map(str::to_owned)
                    .or_else(|| {
                        self.platforms
                            .iter()
                            .flat_map(|platform| platform.redirect_uris.iter())
                            .find_map(|raw| {
                                Url::parse(raw)
                                    .ok()
                                    .and_then(|uri| uri.host_str().map(str::to_owned))
                            })
                    });
                let fallback = self.client.oid.to_string();
                pairwise_subject_identifier(
                    user_oid,
                    sector_identifier.as_deref().unwrap_or(fallback.as_str()),
                    issuer,
                )
            }
        }
    }
}

/// Native loopback redirects may vary only in their port component.
fn strip_loopback_port(suffix: &str) -> Option<&str> {
    let Some(after_colon) = suffix.strip_prefix(':') else {
        return Some(suffix);
    };
    let end = after_colon
        .find(['/', '?', '#'])
        .unwrap_or(after_colon.len());
    after_colon[..end].parse::<u16>().ok()?;
    Some(&after_colon[end..])
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InvalidOpenIdConnectClientError;

impl std::fmt::Display for InvalidOpenIdConnectClientError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("client protocol must be openid_connect")
    }
}

impl std::error::Error for InvalidOpenIdConnectClientError {}

#[cfg(test)]
mod tests {
    use super::{
        GrantType, OAuthProtocolVersion, OpenIdConnectClient, OpenIdConnectClientMetadata,
        OpenIdConnectClientPlatform, OpenIdConnectClientPlatformType, OpenIdConnectClientSettings,
        pairwise_subject_identifier,
    };
    use crate::client::model::{Client, ClientProtocol};
    use crate::openid_connect::{ResponseType, SubjectType};
    use chrono::Utc;
    use url::Url;

    #[test]
    fn parses_protocol_platform_values() {
        assert_eq!(
            "web".parse::<OpenIdConnectClientPlatformType>().unwrap(),
            OpenIdConnectClientPlatformType::Web
        );
        assert_eq!(
            "native".parse::<OpenIdConnectClientPlatformType>().unwrap(),
            OpenIdConnectClientPlatformType::Native
        );
        assert!("ios".parse::<OpenIdConnectClientPlatformType>().is_err());
    }

    #[test]
    fn parses_subject_type_values() {
        assert_eq!(
            "public".parse::<SubjectType>().unwrap(),
            SubjectType::Public
        );
        assert_eq!(
            "pairwise".parse::<SubjectType>().unwrap(),
            SubjectType::Pairwise
        );
        assert!("sector".parse::<SubjectType>().is_err());
    }

    #[test]
    fn settings_defaults_include_scoped_claims_to_false() {
        assert!(!OpenIdConnectClientSettings::default().include_scoped_claims_in_id_token);
        assert!(!OpenIdConnectClientSettings::default().include_scoped_claims_in_access_token);
        assert!(!OpenIdConnectClientSettings::default().cors_enabled);

        // Stored settings without the version field retain OAuth 2.0 behavior.
        let parsed: OpenIdConnectClientSettings =
            serde_json::from_value(serde_json::json!({"skip_consent": true})).unwrap();
        assert!(parsed.skip_consent);
        assert!(!parsed.include_scoped_claims_in_id_token);
        assert!(!parsed.include_scoped_claims_in_access_token);
        assert!(!parsed.allow_nonce_without_pkce);
        assert_eq!(parsed.oauth_version, OAuthProtocolVersion::V2_0);
    }

    #[test]
    fn settings_roundtrips_oauth_protocol_version() {
        let settings = OpenIdConnectClientSettings {
            oauth_version: OAuthProtocolVersion::V2_1,
            ..OpenIdConnectClientSettings::default()
        };
        let json = serde_json::to_value(&settings).unwrap();
        assert_eq!(json["oauth_version"], "2.1");
        let parsed: OpenIdConnectClientSettings = serde_json::from_value(json).unwrap();
        assert_eq!(parsed.oauth_version, OAuthProtocolVersion::V2_1);
        assert!(
            serde_json::from_value::<OpenIdConnectClientSettings>(
                serde_json::json!({"oauth_version": "3.0"})
            )
            .is_err()
        );
    }

    #[test]
    fn settings_roundtrips_include_scoped_claims_flag() {
        let settings = OpenIdConnectClientSettings {
            skip_consent: true,
            include_scoped_claims_in_id_token: true,
            include_scoped_claims_in_access_token: true,
            ..OpenIdConnectClientSettings::default()
        };
        let json = serde_json::to_value(&settings).unwrap();
        let parsed: OpenIdConnectClientSettings = serde_json::from_value(json).unwrap();
        assert_eq!(parsed, settings);
    }

    #[test]
    fn pairwise_subject_identifier_uses_sector_identifier() {
        let user_oid = uuid::Uuid::parse_str("11111111-1111-1111-1111-111111111111").unwrap();
        let issuer = Url::parse("https://identity.example.com/").unwrap();
        let sector_a = Url::parse("https://rp-a.example.com/sector.json").unwrap();
        let sector_b = Url::parse("https://rp-b.example.com/sector.json").unwrap();

        let subject_a = pairwise_subject_identifier(user_oid, "rp-a.example.com", &issuer);
        let subject_a_from_uri =
            pairwise_subject_identifier(user_oid, sector_a.host_str().unwrap(), &issuer);
        let subject_b =
            pairwise_subject_identifier(user_oid, sector_b.host_str().unwrap(), &issuer);

        assert_eq!(subject_a, subject_a_from_uri);
        assert_ne!(subject_a, user_oid.to_string());
        assert_ne!(subject_a, subject_b);
    }

    #[test]
    fn displays_protocol_platform_values() {
        assert_eq!(OpenIdConnectClientPlatformType::Web.to_string(), "web");
        assert_eq!(
            OpenIdConnectClientPlatformType::Native.to_string(),
            "native"
        );
    }

    #[test]
    fn rejects_non_openid_connect_clients() {
        let client = Client {
            oid: uuid::Uuid::nil(),
            protocol: ClientProtocol::Other("saml".to_string()),
            name: "Example RP".to_string(),
            names: vec![],
            description: None,
            built_in: false,
            created_at: Utc::now(),
            updated_at: None,
        };

        let metadata = OpenIdConnectClientMetadata {
            post_logout_redirect_uris: None,
            frontchannel_logout_uri: None,
            frontchannel_logout_session_required: None,
            backchannel_logout_uri: None,
            backchannel_logout_session_required: None,
            response_types: None,
            grant_types: None,
            contacts: None,
            logo_uri: None,
            client_uri: None,
            policy_uri: None,
            tos_uri: None,
            sector_identifier_uri: None,
            subject_type: None,
            id_token_signed_response_algs: None,
            id_token_encrypted_response_algs: None,
            id_token_encrypted_response_encs: None,
            userinfo_signed_response_algs: None,
            userinfo_encrypted_response_algs: None,
            userinfo_encrypted_response_encs: None,
            request_object_signing_algs: None,
            request_object_encryption_algs: None,
            request_object_encryption_encs: None,
            token_endpoint_auth_methods: None,
            token_endpoint_auth_signing_algs: None,
            default_max_age: None,
            require_auth_time: None,
            default_acr_values: None,
            initiate_login_uri: None,
            request_uris: None,
            settings: OpenIdConnectClientSettings::default(),
        };

        assert!(OpenIdConnectClient::new(client, metadata, vec![], vec![]).is_err());
    }

    #[test]
    fn accepts_redirect_uri_from_any_client_platform() {
        let client = Client {
            oid: uuid::Uuid::nil(),
            protocol: ClientProtocol::OpenIdConnect,
            name: "Example RP".to_string(),
            names: vec![],
            description: None,
            built_in: false,
            created_at: Utc::now(),
            updated_at: None,
        };

        let metadata = OpenIdConnectClientMetadata {
            post_logout_redirect_uris: None,
            frontchannel_logout_uri: None,
            frontchannel_logout_session_required: None,
            backchannel_logout_uri: None,
            backchannel_logout_session_required: None,
            response_types: None,
            grant_types: None,
            contacts: None,
            logo_uri: None,
            client_uri: None,
            policy_uri: None,
            tos_uri: None,
            sector_identifier_uri: None,
            subject_type: None,
            id_token_signed_response_algs: None,
            id_token_encrypted_response_algs: None,
            userinfo_signed_response_algs: None,
            userinfo_encrypted_response_algs: None,
            userinfo_encrypted_response_encs: None,
            id_token_encrypted_response_encs: None,
            request_object_signing_algs: None,
            request_object_encryption_algs: None,
            request_object_encryption_encs: None,
            token_endpoint_auth_methods: None,
            token_endpoint_auth_signing_algs: None,
            default_max_age: None,
            require_auth_time: None,
            default_acr_values: None,
            initiate_login_uri: None,
            request_uris: None,
            settings: OpenIdConnectClientSettings::default(),
        };

        let oidc_client = OpenIdConnectClient::new(
            client,
            metadata,
            vec![
                OpenIdConnectClientPlatform {
                    platform: OpenIdConnectClientPlatformType::Web,
                    redirect_uris: vec![
                        "https://rp.example.com/callback".to_owned(),
                        "http://localhost:3000/callback".to_owned(),
                        "http://localhost:53000".to_owned(),
                        "http://rp.example.com/callback".to_owned(),
                    ],
                },
                OpenIdConnectClientPlatform {
                    platform: OpenIdConnectClientPlatformType::Native,
                    redirect_uris: vec![
                        "com.example.app:/callback".to_owned(),
                        "http://127.0.0.1:49152/callback?source=app".to_owned(),
                        "http://127.0.0.1:49152".to_owned(),
                    ],
                },
            ],
            vec![],
        )
        .unwrap();

        assert!(oidc_client.has_redirect_uri_str("https://rp.example.com/callback"));
        assert!(!oidc_client.has_redirect_uri_str("https://rp.example.com/callback/"));
        assert!(oidc_client.has_redirect_uri_str("http://localhost:3000/callback"));
        assert!(!oidc_client.has_redirect_uri_str("http://localhost:3000/callback/"));
        assert!(oidc_client.has_redirect_uri_str("http://localhost:53000"));
        assert!(!oidc_client.has_redirect_uri_str("http://localhost:53000/"));
        assert!(!oidc_client.has_redirect_uri_str("http://localhost:53000?source=other"));
        assert!(!oidc_client.has_redirect_uri_str("http://localhost:53001"));
        assert!(!oidc_client.has_redirect_uri_str("http://rp.example.com/callback"));
        assert!(!oidc_client.has_redirect_uri_str("http://localhost.evil.test:3000/callback"));
        assert!(oidc_client.has_redirect_uri_str("com.example.app:/callback"));
        assert!(oidc_client.has_redirect_uri_str("http://127.0.0.1:55000/callback?source=app"));
        assert!(oidc_client.has_redirect_uri_str("http://127.0.0.1:55000"));
        assert!(!oidc_client.has_redirect_uri_str("http://127.0.0.1:55000/"));
        assert!(!oidc_client.has_redirect_uri_str("http://127.0.0.1:55000/callback/?source=app"));
        assert!(oidc_client.has_redirect_uri_str("http://127.0.0.1:80/callback?source=app"));
        assert!(!oidc_client.has_redirect_uri_str("http://127.0.0.1:55000/callback/?source=other"));
        assert!(!oidc_client.has_redirect_uri_str("http://127.0.0.1:55000/other?source=app"));
        assert!(!oidc_client.has_redirect_uri_str("http://127.0.0.2:55000/callback?source=app"));
        assert!(!oidc_client.has_redirect_uri_str("https://RP.example.com/callback"));
        assert!(!oidc_client.has_redirect_uri_str("https://rp.example.com:443/callback"));
        assert!(!oidc_client.has_redirect_uri_str("https://rp.example.com/other"));
    }

    #[test]
    fn native_localhost_redirect_allows_variable_port_in_both_oauth_versions() {
        for oauth_version in [OAuthProtocolVersion::V2_0, OAuthProtocolVersion::V2_1] {
            let client = Client {
                oid: uuid::Uuid::nil(),
                protocol: ClientProtocol::OpenIdConnect,
                name: "Native RP".to_owned(),
                names: vec![],
                description: None,
                built_in: false,
                created_at: Utc::now(),
                updated_at: None,
            };
            let metadata = OpenIdConnectClientMetadata {
                settings: OpenIdConnectClientSettings {
                    oauth_version,
                    ..Default::default()
                },
                ..Default::default()
            };
            let oidc_client = OpenIdConnectClient::new(
                client,
                metadata,
                vec![OpenIdConnectClientPlatform {
                    platform: OpenIdConnectClientPlatformType::Native,
                    redirect_uris: vec![
                        "http://localhost:53000/callback?source=app".to_owned(),
                        "http://localhost:53000".to_owned(),
                    ],
                }],
                vec![],
            )
            .unwrap();

            assert!(oidc_client.has_redirect_uri_str("http://localhost:49152/callback?source=app"));
            assert!(oidc_client.has_redirect_uri_str("http://localhost:49152"));
            assert!(!oidc_client.has_redirect_uri_str("http://localhost:49152/"));
            assert!(!oidc_client.has_redirect_uri_str("http://localhost:49152/callback/"));
            assert!(
                !oidc_client.has_redirect_uri_str("http://localhost:49152/callback?source=other")
            );
            assert!(
                !oidc_client.has_redirect_uri_str("http://app.localhost:49152/callback?source=app")
            );
            assert!(
                !oidc_client
                    .has_redirect_uri_str("http://localhost.evil.test:49152/callback?source=app")
            );
        }
    }

    #[test]
    fn stores_assigned_scope_names() {
        let client = Client {
            oid: uuid::Uuid::nil(),
            protocol: ClientProtocol::OpenIdConnect,
            name: "Example RP".to_string(),
            names: vec![],
            description: None,
            built_in: false,
            created_at: Utc::now(),
            updated_at: None,
        };
        let metadata = OpenIdConnectClientMetadata {
            post_logout_redirect_uris: None,
            frontchannel_logout_uri: None,
            frontchannel_logout_session_required: None,
            backchannel_logout_uri: None,
            backchannel_logout_session_required: None,
            response_types: None,
            grant_types: None,
            contacts: None,
            logo_uri: None,
            client_uri: None,
            policy_uri: None,
            tos_uri: None,
            sector_identifier_uri: None,
            subject_type: None,
            id_token_signed_response_algs: None,
            id_token_encrypted_response_algs: None,
            id_token_encrypted_response_encs: None,
            userinfo_signed_response_algs: None,
            userinfo_encrypted_response_algs: None,
            userinfo_encrypted_response_encs: None,
            request_object_signing_algs: None,
            request_object_encryption_algs: None,
            request_object_encryption_encs: None,
            token_endpoint_auth_methods: None,
            token_endpoint_auth_signing_algs: None,
            default_max_age: None,
            require_auth_time: None,
            default_acr_values: None,
            initiate_login_uri: None,
            request_uris: None,
            settings: OpenIdConnectClientSettings::default(),
        };

        let oidc_client = OpenIdConnectClient::new(
            client,
            metadata,
            vec![],
            vec!["openid".to_string(), "email".to_string()],
        )
        .unwrap();

        assert!(oidc_client.has_assigned_scope("openid"));
        assert!(oidc_client.has_assigned_scope("email"));
        assert!(!oidc_client.has_assigned_scope("profile"));
    }

    fn client_with_grant_types(grant_types: Option<Vec<GrantType>>) -> OpenIdConnectClient {
        let client = Client {
            oid: uuid::Uuid::nil(),
            protocol: ClientProtocol::OpenIdConnect,
            name: "Example RP".to_string(),
            names: vec![],
            description: None,
            built_in: false,
            created_at: Utc::now(),
            updated_at: None,
        };
        let metadata = OpenIdConnectClientMetadata {
            grant_types,
            ..OpenIdConnectClientMetadata::default()
        };

        OpenIdConnectClient::new(client, metadata, vec![], vec![]).unwrap()
    }

    #[test]
    fn omitted_grant_types_default_to_authorization_code() {
        let client = client_with_grant_types(None);

        assert!(client.allows_grant(GrantType::AuthorizationCode));
        assert!(!client.allows_grant(GrantType::Implicit));
        assert!(!client.allows_grant(GrantType::RefreshToken));
        assert!(!client.allows_grant(GrantType::DeviceCode));
    }

    #[test]
    fn empty_grant_types_allow_no_grant() {
        let client = client_with_grant_types(Some(vec![]));

        assert!(!client.allows_grant(GrantType::AuthorizationCode));
        assert!(!client.allows_grant(GrantType::Implicit));
        assert!(!client.allows_grant(GrantType::RefreshToken));
    }

    #[test]
    fn explicit_grant_types_allow_only_the_registered_grants() {
        let client = client_with_grant_types(Some(vec![GrantType::DeviceCode]));

        assert!(client.allows_grant(GrantType::DeviceCode));
        assert!(!client.allows_grant(GrantType::AuthorizationCode));
        assert!(!client.allows_grant(GrantType::RefreshToken));
    }

    #[test]
    fn hybrid_response_types_require_code_and_implicit_grants() {
        let code_only = client_with_grant_types(Some(vec![GrantType::AuthorizationCode]));
        let implicit_only = client_with_grant_types(Some(vec![GrantType::Implicit]));
        let both = client_with_grant_types(Some(vec![
            GrantType::AuthorizationCode,
            GrantType::Implicit,
        ]));

        assert!(code_only.allows_response_type(&ResponseType::Code));
        assert!(!code_only.allows_response_type(&ResponseType::IdToken));
        assert!(!code_only.allows_response_type(&ResponseType::CodeIdToken));

        assert!(implicit_only.allows_response_type(&ResponseType::IdToken));
        assert!(implicit_only.allows_response_type(&ResponseType::TokenIdToken));
        assert!(!implicit_only.allows_response_type(&ResponseType::Code));
        assert!(!implicit_only.allows_response_type(&ResponseType::CodeIdToken));

        assert!(both.allows_response_type(&ResponseType::CodeIdToken));
        assert!(both.allows_response_type(&ResponseType::CodeTokenIdToken));
    }

    #[test]
    fn registered_response_types_restrict_allowed_responses_even_with_both_grants() {
        let base = client_with_grant_types(Some(vec![
            GrantType::AuthorizationCode,
            GrantType::Implicit,
        ]));
        let mut metadata = base.metadata().clone();
        metadata.response_types = Some(vec![ResponseType::Code]);
        let client = OpenIdConnectClient::new(
            base.client().clone(),
            metadata,
            base.platforms().to_vec(),
            base.assigned_scopes().to_vec(),
        )
        .unwrap();

        assert!(client.allows_response_type(&ResponseType::Code));
        assert!(!client.allows_response_type(&ResponseType::IdToken));
        assert!(!client.allows_response_type(&ResponseType::CodeIdToken));
    }

    #[test]
    fn device_code_grant_uses_the_rfc_8628_urn() {
        let urn = "urn:ietf:params:oauth:grant-type:device_code";

        assert_eq!(urn.parse::<GrantType>().unwrap(), GrantType::DeviceCode);
        assert_eq!(GrantType::DeviceCode.to_string(), urn);
    }
}
