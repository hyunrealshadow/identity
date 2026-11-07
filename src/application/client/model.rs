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

/// Token endpoint methods follow the client's live credentials instead of
/// being chosen directly: an active secret enables HTTP Basic and the request
/// body, an active public key or JWKS URI enables `private_key_jwt`, and the
/// public client flow switch adds `none`. The order is stable so equal inputs
/// persist identically.
#[must_use]
pub fn derived_auth_methods(
    has_secret: bool,
    has_public_key: bool,
    allow_public_client_flow: bool,
) -> Vec<TokenEndpointAuthMethod> {
    let mut methods = Vec::new();
    if has_secret {
        methods.push(TokenEndpointAuthMethod::ClientSecretBasic);
        methods.push(TokenEndpointAuthMethod::ClientSecretPost);
    }
    if has_public_key {
        methods.push(TokenEndpointAuthMethod::PrivateKeyJwt);
    }
    if allow_public_client_flow {
        methods.push(TokenEndpointAuthMethod::None);
    }
    methods
}

/// Usable credentials a client may hold at once, per kind. Rotation counts
/// after the replaced secret is revoked.
#[must_use]
pub const fn max_active_credentials(kind: &OpenIdConnectCredentialType) -> usize {
    match kind {
        OpenIdConnectCredentialType::ClientSecret
        | OpenIdConnectCredentialType::ClientPublicKey => 5,
        OpenIdConnectCredentialType::ClientJsonWebKeySet => 1,
    }
}

pub const MIN_PUBLIC_KEY_LIFETIME_DAYS: i64 = 1;
pub const MAX_PUBLIC_KEY_LIFETIME_DAYS: i64 = 3_650;
/// Upper bound for a pasted PEM key, certificate or JWK.
pub const MAX_PUBLIC_KEY_INPUT_LENGTH: usize = 16 * 1024;

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
    /// Methods the client may use at the token endpoint. Read-only: they are
    /// derived from the live credentials and the public flow switch (see
    /// [`derived_auth_methods`]), and a write ignores this field.
    pub token_endpoint_auth_methods: Vec<TokenEndpointAuthMethod>,
    /// Whether the public client flow is enabled, which also lists `none`.
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
    /// Identifies the credential without revealing it: the last characters of
    /// a secret, a key's SHA-256 thumbprint, or a JWKS URI. Masking is left to
    /// the presentation.
    pub hint: String,
    /// `None` for a JWKS URI, whose keys refresh from the URI.
    pub expires_at: Option<DateTime<Utc>>,
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

/// Register a public key for `private_key_jwt`. `key` is a PEM public key,
/// a PEM certificate or a single public JWK. A certificate supplies its own
/// expiry; other keys need `expires_at`.
#[derive(Debug, Clone)]
pub struct AddClientPublicKeyCommand {
    pub client_oid: ClientOid,
    pub expected_version: Uuid,
    pub key: String,
    pub expires_at: Option<DateTime<Utc>>,
    pub reason: String,
    pub client_mutation_id: Option<String>,
}

/// Register a JWKS URI for `private_key_jwt`. The key set is fetched once to
/// validate it and refreshed from the URI afterwards, so it does not expire.
#[derive(Debug, Clone)]
pub struct AddClientJwksUriCommand {
    pub client_oid: ClientOid,
    pub expected_version: Uuid,
    pub jwks_uri: String,
    pub reason: String,
    pub client_mutation_id: Option<String>,
}

#[derive(Debug, Clone)]
pub struct ClientCredentialResult {
    pub client: ClientRecord,
    pub credential: ClientCredentialRecord,
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
