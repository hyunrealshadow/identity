use crate::graphql::schema::access::access;
use async_graphql::{Context, Enum, ID, InputObject, Object, Result as GraphqlResult};
use chrono::{DateTime, Utc};
use identity_application::{
    authorization::ManagementTarget,
    client::{
        ClientCredentialRecord, ClientFilter as ApplicationFilter, ClientOrder as ApplicationOrder,
        ClientPlatform, ClientProtocolSettings, ClientRecord,
    },
};
use identity_domain::{
    authorization::ManagementScope,
    client::model::ClientOid,
    openid_connect::{
        GrantType, OpenIdConnectClientPlatformType, OpenIdConnectCredentialOid,
        OpenIdConnectCredentialType, TokenEndpointAuthMethod,
    },
};
use identity_infrastructure::graphql::id::{GlobalId, GlobalIdType};
use uuid::Uuid;

use super::{
    super::{
        group::types::{LocalizedTextInput, LocalizedTextNode},
        resource::support::{decode_oid, page_args},
        scope::{
            client::{ClientScopeConnection, load_client_scopes},
            types::ScopeOrder,
        },
    },
    integration,
};
use crate::graphql::schema::{
    authorization::request_context, error::app_error, management_guard::ManagementGuard,
};

pub(crate) struct ClientGlobalId;

impl GlobalIdType for ClientGlobalId {
    const TYPE_NAME: &'static str = "Client";
}

pub(crate) fn client_global_id(oid: ClientOid) -> ID {
    GlobalId::<ClientGlobalId>::new(oid).into()
}

pub(crate) fn decode_client_oid(ctx: &Context<'_>, id: &ID) -> GraphqlResult<ClientOid> {
    decode_oid::<ClientGlobalId>(ctx, id)
}

pub(crate) struct ClientCredentialGlobalId;

impl GlobalIdType for ClientCredentialGlobalId {
    const TYPE_NAME: &'static str = "ClientCredential";
}

pub(crate) fn decode_credential_oid(
    ctx: &Context<'_>,
    id: &ID,
) -> GraphqlResult<OpenIdConnectCredentialOid> {
    decode_oid::<ClientCredentialGlobalId>(ctx, id)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Enum)]
pub(crate) enum ClientPlatformType {
    Web,
    Native,
}

impl From<OpenIdConnectClientPlatformType> for ClientPlatformType {
    fn from(value: OpenIdConnectClientPlatformType) -> Self {
        match value {
            OpenIdConnectClientPlatformType::Web => Self::Web,
            OpenIdConnectClientPlatformType::Native => Self::Native,
        }
    }
}

impl From<ClientPlatformType> for OpenIdConnectClientPlatformType {
    fn from(value: ClientPlatformType) -> Self {
        match value {
            ClientPlatformType::Web => Self::Web,
            ClientPlatformType::Native => Self::Native,
        }
    }
}

/// OAuth grant type. `IMPLICIT` is shown for existing registrations only and
/// cannot be newly selected.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Enum)]
pub(crate) enum ClientGrantType {
    AuthorizationCode,
    RefreshToken,
    ClientCredentials,
    DeviceCode,
    Implicit,
}

impl From<GrantType> for ClientGrantType {
    fn from(value: GrantType) -> Self {
        match value {
            GrantType::AuthorizationCode => Self::AuthorizationCode,
            GrantType::RefreshToken => Self::RefreshToken,
            GrantType::ClientCredentials => Self::ClientCredentials,
            GrantType::DeviceCode => Self::DeviceCode,
            GrantType::Implicit => Self::Implicit,
        }
    }
}

impl From<ClientGrantType> for GrantType {
    fn from(value: ClientGrantType) -> Self {
        match value {
            ClientGrantType::AuthorizationCode => Self::AuthorizationCode,
            ClientGrantType::RefreshToken => Self::RefreshToken,
            ClientGrantType::ClientCredentials => Self::ClientCredentials,
            ClientGrantType::DeviceCode => Self::DeviceCode,
            ClientGrantType::Implicit => Self::Implicit,
        }
    }
}

/// Token endpoint client authentication. Key-based `PRIVATE_KEY_JWT` is shown
/// for existing registrations only.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Enum)]
pub(crate) enum ClientAuthMethod {
    ClientSecretBasic,
    ClientSecretPost,
    ClientSecretJwt,
    PrivateKeyJwt,
    None,
}

impl From<TokenEndpointAuthMethod> for ClientAuthMethod {
    fn from(value: TokenEndpointAuthMethod) -> Self {
        match value {
            TokenEndpointAuthMethod::ClientSecretBasic => Self::ClientSecretBasic,
            TokenEndpointAuthMethod::ClientSecretPost => Self::ClientSecretPost,
            TokenEndpointAuthMethod::ClientSecretJwt => Self::ClientSecretJwt,
            TokenEndpointAuthMethod::PrivateKeyJwt => Self::PrivateKeyJwt,
            TokenEndpointAuthMethod::None => Self::None,
        }
    }
}

impl From<ClientAuthMethod> for TokenEndpointAuthMethod {
    fn from(value: ClientAuthMethod) -> Self {
        match value {
            ClientAuthMethod::ClientSecretBasic => Self::ClientSecretBasic,
            ClientAuthMethod::ClientSecretPost => Self::ClientSecretPost,
            ClientAuthMethod::ClientSecretJwt => Self::ClientSecretJwt,
            ClientAuthMethod::PrivateKeyJwt => Self::PrivateKeyJwt,
            ClientAuthMethod::None => Self::None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Enum)]
pub(crate) enum ClientCredentialKind {
    ClientSecret,
    PublicKey,
    JwksUri,
}

impl From<&OpenIdConnectCredentialType> for ClientCredentialKind {
    fn from(value: &OpenIdConnectCredentialType) -> Self {
        match value {
            OpenIdConnectCredentialType::ClientSecret => Self::ClientSecret,
            OpenIdConnectCredentialType::ClientPublicKey => Self::PublicKey,
            OpenIdConnectCredentialType::ClientJsonWebKeySet => Self::JwksUri,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Enum)]
pub(crate) enum ClientOrder {
    #[graphql(name = "CREATED_AT_ASC")]
    CreatedAtAsc,
    #[graphql(name = "CREATED_AT_DESC")]
    CreatedAtDesc,
    #[graphql(name = "NAME_ASC")]
    NameAsc,
    #[graphql(name = "NAME_DESC")]
    NameDesc,
}

impl From<ClientOrder> for ApplicationOrder {
    fn from(order: ClientOrder) -> Self {
        match order {
            ClientOrder::CreatedAtAsc => Self::CreatedAtAsc,
            ClientOrder::CreatedAtDesc => Self::CreatedAtDesc,
            ClientOrder::NameAsc => Self::NameAsc,
            ClientOrder::NameDesc => Self::NameDesc,
        }
    }
}

#[derive(Clone, Default, InputObject)]
pub(crate) struct ClientFilter {
    /// Matches the name, or the exact client ID.
    #[graphql(validator(chars_max_length = 255))]
    pub query: Option<String>,
    pub enabled: Option<bool>,
}

impl From<ClientFilter> for ApplicationFilter {
    fn from(filter: ClientFilter) -> Self {
        Self {
            query: filter.query,
            enabled: filter.enabled,
        }
    }
}

pub(crate) struct ClientPlatformNode(ClientPlatform);

#[Object(name = "ClientPlatform")]
impl ClientPlatformNode {
    async fn platform(&self) -> ClientPlatformType {
        self.0.platform.clone().into()
    }

    async fn redirect_uris(&self) -> &[String] {
        &self.0.redirect_uris
    }
}

pub(crate) struct ClientCredentialNode {
    id: ID,
    record: ClientCredentialRecord,
}

impl ClientCredentialNode {
    pub(crate) fn new(record: ClientCredentialRecord) -> Self {
        Self {
            id: GlobalId::<ClientCredentialGlobalId>::new(record.oid).into(),
            record,
        }
    }
}

/// Credential metadata. Secret values are never readable.
#[Object(name = "ClientCredential")]
impl ClientCredentialNode {
    async fn id(&self) -> &ID {
        &self.id
    }

    #[graphql(name = "type")]
    async fn kind(&self) -> ClientCredentialKind {
        (&self.record.kind).into()
    }

    /// Masked identification, such as the last characters of a secret.
    async fn hint(&self) -> &str {
        &self.record.hint
    }

    async fn expires_at(&self) -> DateTime<Utc> {
        self.record.expires_at
    }

    async fn revoked_at(&self) -> Option<DateTime<Utc>> {
        self.record.revoked_at
    }

    /// Neither revoked nor expired.
    async fn active(&self) -> bool {
        self.record.revoked_at.is_none() && self.record.expires_at > Utc::now()
    }

    async fn created_at(&self) -> DateTime<Utc> {
        self.record.created_at
    }
}

pub(crate) struct ClientNode {
    id: ID,
    record: ClientRecord,
}

impl ClientNode {
    pub(crate) fn new(record: ClientRecord) -> Self {
        Self {
            id: client_global_id(record.oid),
            record,
        }
    }
}

#[Object(name = "Client")]
impl ClientNode {
    pub(crate) async fn id(&self) -> &ID {
        &self.id
    }

    /// The OAuth `client_id` used in protocol requests.
    async fn client_id(&self) -> String {
        self.record.oid.to_string()
    }

    /// Independent default name; viewers choose matching translations from `names`.
    async fn name(&self) -> &str {
        &self.record.name
    }

    async fn description(&self) -> &str {
        &self.record.description
    }

    async fn names(&self) -> Vec<LocalizedTextNode> {
        self.record.names.iter().cloned().map(Into::into).collect()
    }

    async fn descriptions(&self) -> Vec<LocalizedTextNode> {
        self.record
            .descriptions
            .iter()
            .cloned()
            .map(Into::into)
            .collect()
    }

    async fn built_in(&self) -> bool {
        self.record.built_in
    }

    async fn enabled(&self) -> bool {
        self.record.enabled
    }

    async fn platforms(&self) -> Vec<ClientPlatformNode> {
        self.record
            .settings
            .platforms
            .iter()
            .cloned()
            .map(ClientPlatformNode)
            .collect()
    }

    async fn post_logout_redirect_uris(&self) -> &[String] {
        &self.record.settings.post_logout_redirect_uris
    }

    async fn grant_types(&self) -> Vec<ClientGrantType> {
        self.record
            .settings
            .grant_types
            .iter()
            .copied()
            .map(Into::into)
            .collect()
    }

    async fn token_endpoint_auth_methods(&self) -> Vec<ClientAuthMethod> {
        self.record
            .settings
            .token_endpoint_auth_methods
            .iter()
            .copied()
            .map(Into::into)
            .collect()
    }

    /// Whether the public client flow is enabled. A client that registers
    /// `none` still cannot skip authentication while this is off.
    async fn allow_public_client_flow(&self) -> bool {
        self.record.settings.allow_public_client_flow
    }

    async fn require_pushed_authorization_requests(&self) -> bool {
        self.record.settings.require_pushed_authorization_requests
    }

    async fn skip_consent(&self) -> bool {
        self.record.settings.skip_consent
    }

    async fn cors_enabled(&self) -> bool {
        self.record.settings.cors_enabled
    }

    /// Browser origins derived from the redirect URIs while CORS is enabled.
    async fn cors_origins(&self) -> &[String] {
        &self.record.cors_origins
    }

    /// UUID optimistic-lock version, shared with scope assignment.
    async fn version(&self) -> Uuid {
        self.record.version
    }

    async fn created_at(&self) -> DateTime<Utc> {
        self.record.created_at
    }

    async fn updated_at(&self) -> Option<DateTime<Utc>> {
        self.record.updated_at
    }

    /// Credential metadata, newest first.
    #[graphql(
        guard = "ManagementGuard::new(ManagementScope::ClientCredentialsRead, ManagementTarget::instance())",
        directive = access::apply(ManagementGuard::policy(ManagementScope::ClientCredentialsRead))
    )]
    async fn credentials(&self, ctx: &Context<'_>) -> GraphqlResult<Vec<ClientCredentialNode>> {
        let records = integration::list_credentials(request_context(ctx)?, self.record.oid)
            .await
            .map_err(|error| app_error(ctx, error))?;
        Ok(records.into_iter().map(ClientCredentialNode::new).collect())
    }

    /// API and protocol scopes assigned to this client.
    #[graphql(
        guard = "ManagementGuard::new(ManagementScope::ClientsRead, ManagementTarget::instance())",
        directive = access::apply(ManagementGuard::policy(ManagementScope::ClientsRead)),
        complexity = "1 + first.or(last).unwrap_or(20).clamp(1, 100) as usize * (1 + child_complexity)"
    )]
    #[allow(clippy::too_many_arguments)]
    async fn scopes(
        &self,
        ctx: &Context<'_>,
        order_by: Option<ScopeOrder>,
        #[graphql(validator(minimum = 1, maximum = 100))] first: Option<i32>,
        after: Option<String>,
        #[graphql(validator(minimum = 1, maximum = 100))] last: Option<i32>,
        before: Option<String>,
    ) -> GraphqlResult<ClientScopeConnection> {
        let page = page_args(ctx, first, after, last, before)?;
        load_client_scopes(
            ctx,
            request_context(ctx)?,
            self.record.oid,
            order_by.unwrap_or_else(ScopeOrder::default_order),
            page,
        )
        .await
    }
}

#[derive(Clone, InputObject)]
pub(crate) struct ClientPlatformInput {
    pub platform: ClientPlatformType,
    #[graphql(validator(max_items = 20))]
    pub redirect_uris: Vec<String>,
}

/// Protocol configuration, replaced as one unit.
#[derive(Clone, InputObject)]
pub(crate) struct ClientSettingsInput {
    #[graphql(validator(max_items = 2))]
    pub platforms: Vec<ClientPlatformInput>,
    #[graphql(default, validator(max_items = 20))]
    pub post_logout_redirect_uris: Vec<String>,
    #[graphql(validator(min_items = 1, max_items = 4))]
    pub grant_types: Vec<ClientGrantType>,
    #[graphql(validator(min_items = 1, max_items = 4))]
    pub token_endpoint_auth_methods: Vec<ClientAuthMethod>,
    #[graphql(default)]
    pub allow_public_client_flow: bool,
    #[graphql(default)]
    pub require_pushed_authorization_requests: bool,
    #[graphql(default)]
    pub skip_consent: bool,
    #[graphql(default)]
    pub cors_enabled: bool,
}

impl From<ClientSettingsInput> for ClientProtocolSettings {
    fn from(input: ClientSettingsInput) -> Self {
        Self {
            platforms: input
                .platforms
                .into_iter()
                .map(|platform| ClientPlatform {
                    platform: platform.platform.into(),
                    redirect_uris: platform.redirect_uris,
                })
                .collect(),
            post_logout_redirect_uris: input.post_logout_redirect_uris,
            grant_types: input.grant_types.into_iter().map(Into::into).collect(),
            token_endpoint_auth_methods: input
                .token_endpoint_auth_methods
                .into_iter()
                .map(Into::into)
                .collect(),
            allow_public_client_flow: input.allow_public_client_flow,
            require_pushed_authorization_requests: input.require_pushed_authorization_requests,
            skip_consent: input.skip_consent,
            cors_enabled: input.cors_enabled,
        }
    }
}

#[derive(Clone, InputObject)]
pub(crate) struct CreateClientInput {
    #[graphql(validator(chars_min_length = 1, chars_max_length = 256))]
    pub name: String,
    #[graphql(default, validator(chars_max_length = 1024))]
    pub description: String,
    #[graphql(default, validator(max_items = 20))]
    pub names: Vec<LocalizedTextInput>,
    #[graphql(default, validator(max_items = 20))]
    pub descriptions: Vec<LocalizedTextInput>,
    pub settings: ClientSettingsInput,
    #[graphql(default, validator(chars_max_length = 1000))]
    pub reason: String,
    #[graphql(validator(chars_max_length = 255))]
    pub client_mutation_id: Option<String>,
}

#[derive(Clone, InputObject)]
pub(crate) struct UpdateClientInput {
    pub id: ID,
    pub expected_version: Uuid,
    #[graphql(validator(chars_min_length = 1, chars_max_length = 256))]
    pub name: Option<String>,
    #[graphql(validator(chars_max_length = 1024))]
    pub description: Option<String>,
    #[graphql(validator(max_items = 20))]
    pub names: Option<Vec<LocalizedTextInput>>,
    #[graphql(validator(max_items = 20))]
    pub descriptions: Option<Vec<LocalizedTextInput>>,
    pub settings: Option<ClientSettingsInput>,
    #[graphql(default, validator(chars_max_length = 1000))]
    pub reason: String,
    #[graphql(validator(chars_max_length = 255))]
    pub client_mutation_id: Option<String>,
}

/// Enable, disable or delete one client.
#[derive(Clone, InputObject)]
pub(crate) struct ClientStateInput {
    pub id: ID,
    pub expected_version: Uuid,
    #[graphql(default, validator(chars_max_length = 1000))]
    pub reason: String,
    #[graphql(validator(chars_max_length = 255))]
    pub client_mutation_id: Option<String>,
}

#[derive(Clone, InputObject)]
pub(crate) struct CreateClientSecretInput {
    pub client_id: ID,
    pub expected_version: Uuid,
    #[graphql(default = 365, validator(minimum = 1, maximum = 3650))]
    pub lifetime_days: u32,
    #[graphql(default, validator(chars_max_length = 1000))]
    pub reason: String,
    #[graphql(validator(chars_max_length = 255))]
    pub client_mutation_id: Option<String>,
}

/// Issue a new secret and revoke `credentialId` in the same change.
#[derive(Clone, InputObject)]
pub(crate) struct RotateClientSecretInput {
    pub client_id: ID,
    pub credential_id: ID,
    pub expected_version: Uuid,
    #[graphql(default = 365, validator(minimum = 1, maximum = 3650))]
    pub lifetime_days: u32,
    #[graphql(default, validator(chars_max_length = 1000))]
    pub reason: String,
    #[graphql(validator(chars_max_length = 255))]
    pub client_mutation_id: Option<String>,
}

#[derive(Clone, InputObject)]
pub(crate) struct RevokeClientCredentialInput {
    pub client_id: ID,
    pub credential_id: ID,
    pub expected_version: Uuid,
    #[graphql(default, validator(chars_max_length = 1000))]
    pub reason: String,
    #[graphql(validator(chars_max_length = 255))]
    pub client_mutation_id: Option<String>,
}

pub(crate) struct ClientPayload {
    record: ClientRecord,
    client_mutation_id: Option<String>,
}

impl ClientPayload {
    pub(crate) fn new(record: ClientRecord, client_mutation_id: Option<String>) -> Self {
        Self {
            record,
            client_mutation_id,
        }
    }
}

#[Object]
impl ClientPayload {
    async fn client_id(&self) -> ID {
        client_global_id(self.record.oid)
    }

    async fn version(&self) -> Uuid {
        self.record.version
    }

    #[graphql(
        guard = "ManagementGuard::new(ManagementScope::ClientsRead, ManagementTarget::instance())",
        directive = access::apply(ManagementGuard::policy(ManagementScope::ClientsRead))
    )]
    async fn client(&self) -> ClientNode {
        ClientNode::new(self.record.clone())
    }

    async fn client_mutation_id(&self) -> Option<&str> {
        self.client_mutation_id.as_deref()
    }
}

pub(crate) struct DeleteClientPayload {
    pub(crate) client_oid: ClientOid,
    pub(crate) client_mutation_id: Option<String>,
}

#[Object]
impl DeleteClientPayload {
    async fn client_id(&self) -> ID {
        client_global_id(self.client_oid)
    }

    async fn deleted(&self) -> bool {
        true
    }

    async fn client_mutation_id(&self) -> Option<&str> {
        self.client_mutation_id.as_deref()
    }
}

/// A newly issued secret. `secret` is returned only in this response.
pub(crate) struct ClientSecretPayload {
    pub(crate) client_oid: ClientOid,
    pub(crate) version: Uuid,
    pub(crate) credential: ClientCredentialRecord,
    pub(crate) secret: String,
    pub(crate) revoked: Option<ClientCredentialRecord>,
    pub(crate) client_mutation_id: Option<String>,
}

#[Object]
impl ClientSecretPayload {
    async fn client_id(&self) -> ID {
        client_global_id(self.client_oid)
    }

    async fn version(&self) -> Uuid {
        self.version
    }

    async fn credential(&self) -> ClientCredentialNode {
        ClientCredentialNode::new(self.credential.clone())
    }

    /// The plaintext secret. It cannot be read again after this response.
    async fn secret(&self) -> &str {
        &self.secret
    }

    /// The secret revoked by a rotation.
    async fn revoked_credential(&self) -> Option<ClientCredentialNode> {
        self.revoked.clone().map(ClientCredentialNode::new)
    }

    async fn client_mutation_id(&self) -> Option<&str> {
        self.client_mutation_id.as_deref()
    }
}

pub(crate) struct ClientCredentialPayload {
    pub(crate) client_oid: ClientOid,
    pub(crate) version: Uuid,
    pub(crate) credential: ClientCredentialRecord,
    pub(crate) client_mutation_id: Option<String>,
}

#[Object]
impl ClientCredentialPayload {
    async fn client_id(&self) -> ID {
        client_global_id(self.client_oid)
    }

    async fn version(&self) -> Uuid {
        self.version
    }

    async fn credential(&self) -> ClientCredentialNode {
        ClientCredentialNode::new(self.credential.clone())
    }

    async fn client_mutation_id(&self) -> Option<&str> {
        self.client_mutation_id.as_deref()
    }
}
