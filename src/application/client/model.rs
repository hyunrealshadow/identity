//! OAuth client management types.

use chrono::{DateTime, Utc};
use identity_domain::{
    client::model::ClientOid,
    openid_connect::{
        GrantType, OAuthProtocolVersion, OpenIdConnectClientPlatformType,
        OpenIdConnectCredentialOid, OpenIdConnectCredentialType, TokenEndpointAuthMethod,
    },
    rbac::LocalizedText,
};
use serde::Serialize;
use uuid::Uuid;

pub const MAX_CLIENT_NAME_LENGTH: usize = 256;
pub const MAX_CLIENT_DESCRIPTION_LENGTH: usize = 1_024;
pub const MAX_REDIRECT_URIS: usize = 20;
pub const MAX_URI_LENGTH: usize = 2_048;
pub const MAX_REASON_LENGTH: usize = 1_000;
pub const MAX_CLIENT_MUTATION_ID_LENGTH: usize = 255;
pub const MAX_QUERY_FILTER_LENGTH: usize = 255;
pub const MIN_SECRET_LIFETIME_DAYS: u32 = 1;
pub const MAX_SECRET_LIFETIME_DAYS: u32 = 3_650;
pub const DEFAULT_SECRET_LIFETIME_DAYS: u32 = 365;

/// Grant types an administrator can configure here. Implicit flows remain
/// readable for existing registrations but cannot be newly selected.
pub const MANAGEABLE_GRANT_TYPES: [GrantType; 4] = [
    GrantType::AuthorizationCode,
    GrantType::RefreshToken,
    GrantType::ClientCredentials,
    GrantType::DeviceCode,
];

/// Authentication methods an administrator can configure here. Key-based
/// methods need public key management, which this surface does not offer.
pub const MANAGEABLE_AUTH_METHODS: [TokenEndpointAuthMethod; 4] = [
    TokenEndpointAuthMethod::ClientSecretBasic,
    TokenEndpointAuthMethod::ClientSecretPost,
    TokenEndpointAuthMethod::ClientSecretJwt,
    TokenEndpointAuthMethod::None,
];

/// Whether any configured method authenticates with a shared client secret.
#[must_use]
pub fn uses_client_secret(methods: &[TokenEndpointAuthMethod]) -> bool {
    methods.iter().copied().any(is_secret_method)
}

/// Whether the method authenticates with a shared client secret.
#[must_use]
pub const fn is_secret_method(method: TokenEndpointAuthMethod) -> bool {
    matches!(
        method,
        TokenEndpointAuthMethod::ClientSecretBasic
            | TokenEndpointAuthMethod::ClientSecretPost
            | TokenEndpointAuthMethod::ClientSecretJwt
    )
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientPlatform {
    pub platform: OpenIdConnectClientPlatformType,
    /// Registered spelling is preserved for exact redirect URI comparison.
    pub redirect_uris: Vec<String>,
}

/// Protocol configuration an administrator edits as one unit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientProtocolSettings {
    pub platforms: Vec<ClientPlatform>,
    pub post_logout_redirect_uris: Vec<String>,
    pub grant_types: Vec<GrantType>,
    /// Methods the client may use at the token endpoint. A public client uses
    /// only `none`; a confidential client may accept several secret methods.
    pub token_endpoint_auth_methods: Vec<TokenEndpointAuthMethod>,
    /// Whether the public client flow is enabled. It is a separate switch:
    /// registering `none` alone does not let a client skip authentication.
    pub allow_public_client_flow: bool,
    pub require_pushed_authorization_requests: bool,
    pub skip_consent: bool,
    /// Allow browser requests from the origins of the redirect URIs.
    pub cors_enabled: bool,
    /// OAuth rules for this client's authorization-code exchanges. `None`
    /// inherits the live global `openid_connect.oauth_version` setting.
    pub oauth_version: Option<OAuthProtocolVersion>,
    /// Include the standard claims covered by the granted scopes in issued ID
    /// Tokens, matching implicit-flow behaviour.
    pub include_scoped_claims_in_id_token: bool,
    /// Include the standard user claims covered by the granted scopes in access
    /// tokens issued for a user.
    pub include_scoped_claims_in_access_token: bool,
}

/// One managed OAuth client plus its UUID optimistic-lock version.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientRecord {
    pub oid: ClientOid,
    pub name: String,
    pub description: String,
    pub names: Vec<LocalizedText>,
    pub descriptions: Vec<LocalizedText>,
    pub built_in: bool,
    pub enabled: bool,
    pub settings: ClientProtocolSettings,
    /// Read-only projection of the CORS origins derived from the settings.
    pub cors_origins: Vec<String>,
    /// `client.version`; shared with client scope assignment.
    pub version: Uuid,
    pub created_at: DateTime<Utc>,
    pub updated_at: Option<DateTime<Utc>>,
}

/// Credential metadata. The secret value is never part of a record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientCredentialRecord {
    pub oid: OpenIdConnectCredentialOid,
    pub kind: OpenIdConnectCredentialType,
    pub hint: String,
    pub expires_at: DateTime<Utc>,
    pub revoked_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize)]
pub struct ClientFilter {
    /// Matches the name, or the exact client ID.
    pub query: Option<String>,
    pub enabled: Option<bool>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum ClientOrder {
    CreatedAtAsc,
    #[default]
    CreatedAtDesc,
    NameAsc,
    NameDesc,
}

impl ClientOrder {
    #[must_use]
    pub const fn as_u8(self) -> u8 {
        match self {
            Self::CreatedAtAsc => 0,
            Self::CreatedAtDesc => 1,
            Self::NameAsc => 2,
            Self::NameDesc => 3,
        }
    }

    #[must_use]
    pub const fn is_descending(self) -> bool {
        matches!(self, Self::CreatedAtDesc | Self::NameDesc)
    }
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct ClientPageRequest {
    pub filter: ClientFilter,
    pub order: ClientOrder,
    pub first: Option<u32>,
    pub after: Option<String>,
    pub last: Option<u32>,
    pub before: Option<String>,
}

#[derive(Debug, Clone)]
pub struct ClientPageItem {
    pub record: ClientRecord,
    pub cursor: String,
}

#[derive(Debug, Clone)]
pub struct ClientPage {
    pub items: Vec<ClientPageItem>,
    pub has_previous_page: bool,
    pub has_next_page: bool,
}

#[derive(Debug, Clone)]
pub struct CreateClientCommand {
    pub name: String,
    pub description: String,
    pub names: Vec<LocalizedText>,
    pub descriptions: Vec<LocalizedText>,
    pub settings: ClientProtocolSettings,
    pub reason: String,
    pub client_mutation_id: Option<String>,
}

#[derive(Debug, Clone)]
pub struct UpdateClientCommand {
    pub client_oid: ClientOid,
    pub expected_version: Uuid,
    pub name: Option<String>,
    pub description: Option<String>,
    pub names: Option<Vec<LocalizedText>>,
    pub descriptions: Option<Vec<LocalizedText>>,
    pub settings: Option<ClientProtocolSettings>,
    pub reason: String,
    pub client_mutation_id: Option<String>,
}

/// Enable, disable or delete one client.
#[derive(Debug, Clone)]
pub struct ClientStateCommand {
    pub client_oid: ClientOid,
    pub expected_version: Uuid,
    pub reason: String,
    pub client_mutation_id: Option<String>,
}

#[derive(Debug, Clone)]
pub struct CreateClientSecretCommand {
    pub client_oid: ClientOid,
    pub expected_version: Uuid,
    /// A secret to revoke in the same change, for rotation.
    pub replaces: Option<OpenIdConnectCredentialOid>,
    pub lifetime_days: u32,
    pub reason: String,
    pub client_mutation_id: Option<String>,
}

#[derive(Debug, Clone)]
pub struct RevokeClientCredentialCommand {
    pub client_oid: ClientOid,
    pub credential_oid: OpenIdConnectCredentialOid,
    pub expected_version: Uuid,
    pub reason: String,
    pub client_mutation_id: Option<String>,
}

/// A newly issued secret. `secret` is returned exactly once and never stored
/// anywhere the caller can read it back.
#[derive(Debug, Clone)]
pub struct IssuedClientSecret {
    pub credential: ClientCredentialRecord,
    pub secret: String,
}

#[derive(Debug, Clone)]
pub struct ClientSecretResult {
    pub client: ClientRecord,
    pub secret: IssuedClientSecret,
    pub revoked: Option<ClientCredentialRecord>,
}

#[derive(Debug, Clone)]
pub struct ClientCredentialRevokeResult {
    pub client: ClientRecord,
    pub credential: ClientCredentialRecord,
}
