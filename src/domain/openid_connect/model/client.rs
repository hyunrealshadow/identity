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
            _ => Err(ParseGrantTypeError),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default, serde::Deserialize, serde::Serialize)]
pub struct OpenIdConnectClientSettings {
    #[serde(default)]
    pub skip_consent: bool,
    #[serde(default)]
    pub allow_public_client_flow: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Display, AsRefStr, EnumIter)]
#[strum(serialize_all = "snake_case")]
pub enum OpenIdConnectClientPlatformType {
    Web,
    Native,
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
    pub redirect_uris: Vec<Url>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
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
    pub id_token_signed_response_alg: Option<JwsAlgorithm>,
    pub id_token_encrypted_response_alg: Option<JwaEncryptionAlgorithm>,
    pub id_token_encrypted_response_enc: Option<JweContentEncryption>,
    pub userinfo_signed_response_alg: Option<JwsAlgorithm>,
    pub userinfo_encrypted_response_alg: Option<JwaEncryptionAlgorithm>,
    pub userinfo_encrypted_response_enc: Option<JweContentEncryption>,
    pub request_object_signing_alg: Option<JwsAlgorithm>,
    pub request_object_encryption_alg: Option<JwaEncryptionAlgorithm>,
    pub request_object_encryption_enc: Option<JweContentEncryption>,
    pub token_endpoint_auth_method: Option<TokenEndpointAuthMethod>,
    pub token_endpoint_auth_signing_alg: Option<JwsAlgorithm>,
    pub default_max_age: Option<i32>,
    pub require_auth_time: Option<bool>,
    pub default_acr_values: Option<Vec<String>>,
    pub initiate_login_uri: Option<Url>,
    pub request_uris: Option<Vec<Url>>,
    pub settings: OpenIdConnectClientSettings,
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

    pub fn has_redirect_uri(&self, redirect_uri: &Url) -> bool {
        self.platforms.iter().any(|platform| {
            platform
                .redirect_uris
                .iter()
                .any(|registered| registered == redirect_uri)
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

    pub fn subject_identifier(&self, user_oid: uuid::Uuid, issuer: &Url) -> String {
        match self.metadata.subject_type.unwrap_or(SubjectType::Public) {
            SubjectType::Public => user_oid.to_string(),
            SubjectType::Pairwise => {
                let sector_identifier = self
                    .metadata
                    .sector_identifier_uri
                    .as_ref()
                    .and_then(Url::host_str)
                    .or_else(|| {
                        self.platforms
                            .iter()
                            .flat_map(|platform| platform.redirect_uris.iter())
                            .find_map(Url::host_str)
                    });
                let fallback = self.client.oid.to_string();
                pairwise_subject_identifier(
                    user_oid,
                    sector_identifier.unwrap_or(fallback.as_str()),
                    issuer,
                )
            }
        }
    }
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
        OpenIdConnectClient, OpenIdConnectClientMetadata, OpenIdConnectClientPlatform,
        OpenIdConnectClientPlatformType, OpenIdConnectClientSettings, pairwise_subject_identifier,
    };
    use crate::client::model::{Client, ClientProtocol};
    use crate::openid_connect::SubjectType;
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
            id_token_signed_response_alg: None,
            id_token_encrypted_response_alg: None,
            id_token_encrypted_response_enc: None,
            userinfo_signed_response_alg: None,
            userinfo_encrypted_response_alg: None,
            userinfo_encrypted_response_enc: None,
            request_object_signing_alg: None,
            request_object_encryption_alg: None,
            request_object_encryption_enc: None,
            token_endpoint_auth_method: None,
            token_endpoint_auth_signing_alg: None,
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
            id_token_signed_response_alg: None,
            id_token_encrypted_response_alg: None,
            userinfo_signed_response_alg: None,
            userinfo_encrypted_response_alg: None,
            userinfo_encrypted_response_enc: None,
            id_token_encrypted_response_enc: None,
            request_object_signing_alg: None,
            request_object_encryption_alg: None,
            request_object_encryption_enc: None,
            token_endpoint_auth_method: None,
            token_endpoint_auth_signing_alg: None,
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
                    redirect_uris: vec![Url::parse("https://rp.example.com/callback").unwrap()],
                },
                OpenIdConnectClientPlatform {
                    platform: OpenIdConnectClientPlatformType::Native,
                    redirect_uris: vec![Url::parse("com.example.app:/callback").unwrap()],
                },
            ],
            vec![],
        )
        .unwrap();

        assert!(
            oidc_client.has_redirect_uri(&Url::parse("https://rp.example.com/callback").unwrap())
        );
        assert!(oidc_client.has_redirect_uri(&Url::parse("com.example.app:/callback").unwrap()));
        assert!(
            !oidc_client.has_redirect_uri(&Url::parse("https://rp.example.com/other").unwrap())
        );
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
            id_token_signed_response_alg: None,
            id_token_encrypted_response_alg: None,
            id_token_encrypted_response_enc: None,
            userinfo_signed_response_alg: None,
            userinfo_encrypted_response_alg: None,
            userinfo_encrypted_response_enc: None,
            request_object_signing_alg: None,
            request_object_encryption_alg: None,
            request_object_encryption_enc: None,
            token_endpoint_auth_method: None,
            token_endpoint_auth_signing_alg: None,
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
}
