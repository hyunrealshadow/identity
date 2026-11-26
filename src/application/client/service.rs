//! OAuth client management use cases.
//!
//! Entry guards establish that the caller held a management scope when the
//! request started. The service validates and normalizes input; every write
//! passes the immutable request authority to the repository, which re-checks
//! live authority inside the mutation transaction.

use identity_domain::audit::AuditAction;
use std::sync::Arc;

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::{Duration, Utc};
use identity_domain::{
    client::model::ClientOid,
    key::PublicJwk,
    openid_connect::{
        GrantType, OpenIdConnectClientPlatformType, OpenIdConnectCredentialData,
        OpenIdConnectCredentialOid, SubjectType,
    },
    rbac::{LocalizedMetadata, LocalizedTextError},
};
use rand::{RngExt as _, rng};
use url::Url;
use uuid::Uuid;

use super::{
    model::{
        AddClientJwksUriCommand, AddClientPublicKeyCommand, ClientAdvancedSettings,
        ClientCredentialRecord, ClientCredentialResult, ClientCredentialRevokeResult, ClientFilter,
        ClientPage, ClientPageItem, ClientPageRequest, ClientPlatform, ClientProtocolSettings,
        ClientRecord, ClientSecretResult, ClientStateCommand, CreateClientCommand,
        CreateClientSecretCommand, MANAGEABLE_GRANT_TYPES, MAX_CLIENT_DESCRIPTION_LENGTH,
        MAX_CLIENT_NAME_LENGTH, MAX_PUBLIC_KEY_LIFETIME_DAYS, MAX_QUERY_FILTER_LENGTH,
        MAX_REDIRECT_URIS, MAX_SECRET_LIFETIME_DAYS, MAX_URI_LENGTH, MIN_PUBLIC_KEY_LIFETIME_DAYS,
        MIN_SECRET_LIFETIME_DAYS, RevokeClientCredentialCommand, UpdateClientCommand,
    },
    public_key::{ClientPublicKeyReader, PublicKeyError, PublicKeyMaterial},
    repository::{
        AddClientCredentialTransaction, ClientEntityKind, ClientManagementRepository,
        ClientManagementRepositoryError, ClientQuery, ClientStateTransaction,
        CreateClientSecretTransaction, CreateClientTransaction, NewClientSecret,
        RevokeClientCredentialTransaction, UpdateClientTransaction,
    },
};
use crate::{
    data_protection::DataProtector,
    error::{
        AppError,
        codes::{authorization, client},
    },
    observability::{BusinessEvent, EventSink, EventValue, NoopEventSink, error_outcome},
    openid_connect::provider::{
        ClientMetadataOptions, OpenIdProviderCapabilities, OpenIdProviderService,
    },
    openid_connect::remote::{
        DEFAULT_REMOTE_DOCUMENT_MAX_BYTES, RemoteDocumentFetcher,
        UnconfiguredRemoteDocumentFetcher, validate_https_public_url,
    },
    rbac::{
        RbacManagementAuthority,
        cursor::{CURSOR_KIND_CLIENT, PageArguments, encode_cursors, prepare_page},
    },
};

const SECRET_BYTES: usize = 32;

pub struct ClientManagementService {
    repository: Arc<dyn ClientManagementRepository>,
    data_protector: Arc<dyn DataProtector>,
    public_keys: Arc<dyn ClientPublicKeyReader>,
    remote_fetcher: Arc<dyn RemoteDocumentFetcher>,
    /// Live supported metadata values; without it the static capabilities apply.
    provider: Option<Arc<OpenIdProviderService>>,
    events: Arc<dyn EventSink>,
}

impl ClientManagementService {
    #[must_use]
    pub fn new(
        repository: Arc<dyn ClientManagementRepository>,
        data_protector: Arc<dyn DataProtector>,
        public_keys: Arc<dyn ClientPublicKeyReader>,
    ) -> Self {
        Self {
            repository,
            data_protector,
            public_keys,
            remote_fetcher: Arc::new(UnconfiguredRemoteDocumentFetcher),
            provider: None,
            events: Arc::new(NoopEventSink),
        }
    }

    #[must_use]
    pub fn with_remote_fetcher(mut self, remote_fetcher: Arc<dyn RemoteDocumentFetcher>) -> Self {
        self.remote_fetcher = remote_fetcher;
        self
    }

    /// Validate advanced metadata against the provider's capabilities.
    #[must_use]
    pub fn with_provider(mut self, provider: Arc<OpenIdProviderService>) -> Self {
        self.provider = Some(provider);
        self
    }

    async fn metadata_options(&self) -> Result<ClientMetadataOptions, AppError> {
        match &self.provider {
            Some(provider) => Ok(provider.client_metadata_options()),
            None => Ok(ClientMetadataOptions::from_capabilities(
                &OpenIdProviderCapabilities::default(),
            )),
        }
    }

    #[must_use]
    pub fn with_events(mut self, events: Arc<dyn EventSink>) -> Self {
        self.events = events;
        self
    }

    // ------------------------------------------------------------------
    // Reads
    // ------------------------------------------------------------------

    #[tracing::instrument(skip_all, name = "client.find")]
    pub async fn find_client(&self, oid: ClientOid) -> Result<Option<ClientRecord>, AppError> {
        self.repository
            .find_client(oid)
            .await
            .map_err(map_repository_error)
    }

    #[tracing::instrument(skip_all, name = "client.find_many")]
    pub async fn find_clients(&self, oids: Vec<ClientOid>) -> Result<Vec<ClientRecord>, AppError> {
        if oids.is_empty() {
            return Ok(Vec::new());
        }
        self.repository
            .find_clients(oids)
            .await
            .map_err(map_repository_error)
    }

    #[tracing::instrument(skip_all, name = "client.count")]
    pub async fn count_clients(&self, filter: ClientFilter) -> Result<u64, AppError> {
        let filter = normalize_filter(filter)?;
        self.repository
            .count_clients(filter)
            .await
            .map_err(map_repository_error)
    }

    #[tracing::instrument(skip_all, name = "client.list")]
    pub async fn list_clients(&self, request: ClientPageRequest) -> Result<ClientPage, AppError> {
        let filter = normalize_filter(request.filter)?;
        let order = request.order;
        let prepared = prepare_page(
            self.data_protector.as_ref(),
            CURSOR_KIND_CLIENT,
            order.as_u8(),
            &filter,
            PageArguments {
                first: request.first,
                after: request.after,
                last: request.last,
                before: request.before,
            },
        )
        .await?;
        let data = self
            .repository
            .list_clients(ClientQuery {
                filter,
                order,
                direction: prepared.direction,
                after: prepared.after,
                before: prepared.before,
                limit: prepared.limit,
            })
            .await
            .map_err(map_repository_error)?;
        let sort_keys = data
            .items
            .iter()
            .map(|entry| &entry.sort_key)
            .collect::<Vec<_>>();
        let cursors = encode_cursors(
            self.data_protector.as_ref(),
            CURSOR_KIND_CLIENT,
            order.as_u8(),
            &prepared.filter_fingerprint,
            &sort_keys,
        )
        .await?;
        let items = data
            .items
            .into_iter()
            .zip(cursors)
            .map(|(entry, cursor)| ClientPageItem {
                record: entry.record,
                cursor,
            })
            .collect();
        Ok(ClientPage {
            items,
            has_previous_page: data.has_previous_page,
            has_next_page: data.has_next_page,
        })
    }

    #[tracing::instrument(skip_all, name = "client.credentials.list")]
    pub async fn list_client_credentials(
        &self,
        oid: ClientOid,
    ) -> Result<Vec<ClientCredentialRecord>, AppError> {
        self.repository
            .list_client_credentials(oid)
            .await
            .map_err(map_repository_error)
    }

    // ------------------------------------------------------------------
    // Writes
    // ------------------------------------------------------------------

    #[tracing::instrument(skip_all, name = "client.create")]
    pub async fn create_client(
        &self,
        authority: &RbacManagementAuthority,
        command: CreateClientCommand,
    ) -> Result<ClientRecord, AppError> {
        let result = async {
            validate_reason(&command.reason)?;
            validate_client_mutation_id(command.client_mutation_id.as_deref())?;
            let metadata = LocalizedMetadata::canonicalize(command.names, command.descriptions)
                .map_err(map_localized_error)?;
            let settings = validate_settings(command.settings)?;
            self.repository
                .create_client(CreateClientTransaction {
                    client_oid: Uuid::new_v4(),
                    name: validate_name(&command.name)?,
                    description: validate_description(&command.description)?,
                    names: metadata.names,
                    descriptions: metadata.descriptions,
                    settings,
                    authority: authority.clone(),
                })
                .await
                .map_err(map_repository_error)
        }
        .await;
        self.emit_result("client.create", &result);
        result
    }

    #[tracing::instrument(skip_all, name = "client.update")]
    pub async fn update_client(
        &self,
        authority: &RbacManagementAuthority,
        command: UpdateClientCommand,
    ) -> Result<ClientRecord, AppError> {
        let result = async {
            validate_reason(&command.reason)?;
            validate_client_mutation_id(command.client_mutation_id.as_deref())?;
            if command.name.is_none()
                && command.description.is_none()
                && command.names.is_none()
                && command.descriptions.is_none()
                && command.settings.is_none()
                && command.advanced.is_none()
            {
                return Err(client::error::EmptyUpdate.into());
            }
            let settings = command.settings.map(validate_settings).transpose()?;
            let current = if settings.is_some() || command.advanced.is_some() {
                Some(
                    self.repository
                        .find_client(command.client_oid)
                        .await
                        .map_err(map_repository_error)?
                        .ok_or(client::error::ClientNotFound)?,
                )
            } else {
                None
            };
            let advanced = match (command.advanced, &current) {
                (Some(advanced), Some(current)) => Some(advanced::validate_advanced_settings(
                    advanced,
                    &self.metadata_options().await?,
                    &current.advanced,
                )?),
                _ => None,
            };
            if let Some(current) = &current {
                validate_subject_change(
                    self.remote_fetcher.as_ref(),
                    current,
                    settings.as_ref(),
                    advanced.as_ref(),
                )
                .await?;
            }
            let names = command
                .names
                .map(LocalizedMetadata::canonicalize_names)
                .transpose()
                .map_err(map_localized_error)?;
            let descriptions = command
                .descriptions
                .map(LocalizedMetadata::canonicalize_descriptions)
                .transpose()
                .map_err(map_localized_error)?;
            self.repository
                .update_client(UpdateClientTransaction {
                    client_oid: command.client_oid,
                    expected_version: command.expected_version,
                    name: command.name.as_deref().map(validate_name).transpose()?,
                    description: command
                        .description
                        .as_deref()
                        .map(validate_description)
                        .transpose()?,
                    names,
                    descriptions,
                    settings,
                    advanced,
                    authority: authority.clone(),
                })
                .await
                .map_err(map_repository_error)
        }
        .await;
        self.emit_result("client.update", &result);
        result
    }

    #[tracing::instrument(skip_all, name = "client.enable")]
    pub async fn enable_client(
        &self,
        authority: &RbacManagementAuthority,
        command: ClientStateCommand,
    ) -> Result<ClientRecord, AppError> {
        self.set_client_enabled(authority, command, true).await
    }

    #[tracing::instrument(skip_all, name = "client.disable")]
    pub async fn disable_client(
        &self,
        authority: &RbacManagementAuthority,
        command: ClientStateCommand,
    ) -> Result<ClientRecord, AppError> {
        self.set_client_enabled(authority, command, false).await
    }

    async fn set_client_enabled(
        &self,
        authority: &RbacManagementAuthority,
        command: ClientStateCommand,
        enabled: bool,
    ) -> Result<ClientRecord, AppError> {
        let result = async {
            let transaction = state_transaction(authority, command)?;
            self.repository
                .set_client_enabled(transaction, enabled)
                .await
                .map_err(map_repository_error)
        }
        .await;
        self.emit_result(
            if enabled {
                "client.enable"
            } else {
                "client.disable"
            },
            &result,
        );
        result
    }

    #[tracing::instrument(skip_all, name = "client.delete")]
    pub async fn delete_client(
        &self,
        authority: &RbacManagementAuthority,
        command: ClientStateCommand,
    ) -> Result<ClientOid, AppError> {
        let result = async {
            let transaction = state_transaction(authority, command)?;
            self.repository
                .delete_client(transaction)
                .await
                .map_err(map_repository_error)
        }
        .await;
        self.emit_result("client.delete", &result);
        result
    }

    /// Issue an additional secret. Existing secrets stay valid, so clients can
    /// switch over before the old secret is revoked.
    #[tracing::instrument(skip_all, name = "client.secret.create")]
    pub async fn create_client_secret(
        &self,
        authority: &RbacManagementAuthority,
        command: CreateClientSecretCommand,
    ) -> Result<ClientSecretResult, AppError> {
        let action = if command.replaces.is_some() {
            "client.secret.rotate"
        } else {
            "client.secret.create"
        };
        let result = async {
            validate_reason(&command.reason)?;
            validate_client_mutation_id(command.client_mutation_id.as_deref())?;
            validate_secret_lifetime(command.lifetime_days)?;
            // Issuing a secret is what enables the secret methods; the
            // repository derives them from the credentials it stores.
            self.repository
                .create_client_secret(CreateClientSecretTransaction {
                    client_oid: command.client_oid,
                    expected_version: command.expected_version,
                    replaces: command.replaces,
                    secret: new_secret(command.lifetime_days),
                    authority: authority.clone(),
                })
                .await
                .map_err(map_repository_error)
        }
        .await;
        self.emit_result(action, &result);
        result
    }

    /// Register a public key for `private_key_jwt`. Existing credentials stay
    /// valid.
    #[tracing::instrument(skip_all, name = "client.public_key.create")]
    pub async fn add_client_public_key(
        &self,
        authority: &RbacManagementAuthority,
        command: AddClientPublicKeyCommand,
    ) -> Result<ClientCredentialResult, AppError> {
        let result = async {
            validate_reason(&command.reason)?;
            validate_client_mutation_id(command.client_mutation_id.as_deref())?;
            let parsed = self
                .public_keys
                .read(&command.key)
                .map_err(map_public_key_error)?;
            // A certificate states its own validity; a bare key needs one.
            let expires_at = match parsed.certificate_expiry {
                Some(expiry) => expiry,
                None => {
                    let expires_at = command.expires_at.ok_or_else(|| {
                        client::error::PublicKeyExpiryRequired.with_field("expires_at")
                    })?;
                    validate_key_expiry(expires_at)?;
                    expires_at
                }
            };
            self.repository
                .add_client_credential(AddClientCredentialTransaction {
                    client_oid: command.client_oid,
                    expected_version: command.expected_version,
                    credential_oid: Uuid::new_v4(),
                    data: key_credential(parsed.material),
                    hint: Some(parsed.hint),
                    expires_at: Some(expires_at),
                    action: AuditAction::ClientPublicKeyAdd,
                    authority: authority.clone(),
                })
                .await
                .map_err(map_repository_error)
        }
        .await;
        self.emit_result("client.public_key.create", &result);
        result
    }

    /// Register a JWKS URI for `private_key_jwt`. The key set is fetched now to
    /// prove it is reachable and usable; verification refreshes it later.
    #[tracing::instrument(skip_all, name = "client.jwks_uri.create")]
    pub async fn add_client_jwks_uri(
        &self,
        authority: &RbacManagementAuthority,
        command: AddClientJwksUriCommand,
    ) -> Result<ClientCredentialResult, AppError> {
        let result = async {
            validate_reason(&command.reason)?;
            validate_client_mutation_id(command.client_mutation_id.as_deref())?;
            let jwks_uri = parse_jwks_uri(&command.jwks_uri)?;
            let keys = fetch_client_jwks(
                self.remote_fetcher.as_ref(),
                self.public_keys.as_ref(),
                &jwks_uri,
            )
            .await?;
            let now = Utc::now();
            self.repository
                .add_client_credential(AddClientCredentialTransaction {
                    client_oid: command.client_oid,
                    expected_version: command.expected_version,
                    credential_oid: Uuid::new_v4(),
                    data: OpenIdConnectCredentialData::ClientJsonWebKeySet {
                        jwks_uri,
                        last_updated: now,
                        expires_at: now + Duration::hours(1),
                        public_keys: keys
                            .iter()
                            .map(|jwk| serde_json::to_string(jwk).unwrap_or_default())
                            .collect(),
                        jwks: keys,
                    },
                    hint: None,
                    expires_at: None,
                    action: AuditAction::ClientJwksUriSet,
                    authority: authority.clone(),
                })
                .await
                .map_err(map_repository_error)
        }
        .await;
        self.emit_result("client.jwks_uri.create", &result);
        result
    }

    /// Revoke one credential and permanently withdraw what the client has
    /// already been issued.
    #[tracing::instrument(skip_all, name = "client.credential.revoke")]
    pub async fn revoke_client_credential(
        &self,
        authority: &RbacManagementAuthority,
        command: RevokeClientCredentialCommand,
    ) -> Result<ClientCredentialRevokeResult, AppError> {
        let result = async {
            validate_reason(&command.reason)?;
            validate_client_mutation_id(command.client_mutation_id.as_deref())?;
            self.repository
                .revoke_client_credential(RevokeClientCredentialTransaction {
                    client_oid: command.client_oid,
                    credential_oid: command.credential_oid,
                    expected_version: command.expected_version,
                    authority: authority.clone(),
                })
                .await
                .map_err(map_repository_error)
        }
        .await;
        self.emit_result("client.credential.revoke", &result);
        result
    }

    fn emit_result<T>(&self, name: &'static str, result: &Result<T, AppError>) {
        let mut event = BusinessEvent::business(name);
        match result {
            Ok(_) => event = event.outcome("success"),
            Err(error) => {
                let (outcome, reason) = error_outcome(error);
                event = event
                    .outcome(outcome)
                    .reason(reason)
                    .attribute("error_code", EventValue::Integer(i64::from(error.code())));
            }
        }
        self.events.emit(event);
    }
}

fn new_secret(lifetime_days: u32) -> NewClientSecret {
    let mut bytes = [0_u8; SECRET_BYTES];
    rng().fill(&mut bytes);
    let plaintext = URL_SAFE_NO_PAD.encode(bytes);
    NewClientSecret {
        credential_oid: OpenIdConnectCredentialOid::new_v4(),
        data: OpenIdConnectCredentialData::ClientSecret {
            secret: plaintext.clone(),
        },
        plaintext,
        lifetime_days,
    }
}

fn state_transaction(
    authority: &RbacManagementAuthority,
    command: ClientStateCommand,
) -> Result<ClientStateTransaction, AppError> {
    validate_reason(&command.reason)?;
    validate_client_mutation_id(command.client_mutation_id.as_deref())?;
    Ok(ClientStateTransaction {
        client_oid: command.client_oid,
        expected_version: command.expected_version,
        authority: authority.clone(),
    })
}

// ----------------------------------------------------------------------
// Validation
// ----------------------------------------------------------------------

fn validate_reason(reason: &str) -> Result<String, AppError> {
    crate::authorization::validate_reason_with(reason, |max| {
        client::error::InvalidReason::new(max).with_field("reason")
    })
}

fn validate_client_mutation_id(value: Option<&str>) -> Result<(), AppError> {
    crate::authorization::validate_client_mutation_id_with(value, |max| {
        client::error::InvalidClientMutationId::new(max).with_field("client_mutation_id")
    })
}

fn normalize_filter(mut filter: ClientFilter) -> Result<ClientFilter, AppError> {
    filter.query = match filter.query.as_deref().map(str::trim) {
        None | Some("") => None,
        Some(value) if value.chars().count() > MAX_QUERY_FILTER_LENGTH => {
            return Err(
                client::error::InvalidFilter::new(MAX_QUERY_FILTER_LENGTH).with_field("query")
            );
        }
        Some(value) => Some(value.to_owned()),
    };
    Ok(filter)
}

fn validate_name(value: &str) -> Result<String, AppError> {
    let value = value.trim();
    if value.is_empty() || value.chars().count() > MAX_CLIENT_NAME_LENGTH {
        return Err(client::error::InvalidName::new()
            .max(MAX_CLIENT_NAME_LENGTH)
            .with_field("name"));
    }
    Ok(value.to_owned())
}

fn validate_description(value: &str) -> Result<String, AppError> {
    let value = value.trim();
    if value.chars().count() > MAX_CLIENT_DESCRIPTION_LENGTH {
        return Err(
            client::error::InvalidDescription::new(MAX_CLIENT_DESCRIPTION_LENGTH)
                .with_field("description"),
        );
    }
    Ok(value.to_owned())
}

fn validate_secret_lifetime(days: u32) -> Result<(), AppError> {
    if !(MIN_SECRET_LIFETIME_DAYS..=MAX_SECRET_LIFETIME_DAYS).contains(&days) {
        return Err(client::error::InvalidSecretLifetime::new(
            MIN_SECRET_LIFETIME_DAYS,
            MAX_SECRET_LIFETIME_DAYS,
        )
        .with_field("lifetime_days"));
    }
    Ok(())
}

/// Validate one URI and return it with its registered spelling.
fn parse_uri(
    raw: &str,
    allowed: impl Fn(&Url) -> bool,
    make_error: impl Fn(String) -> AppError,
    field: &'static str,
) -> Result<String, AppError> {
    let invalid = || make_error(raw.to_owned()).with_field(field);
    let value = raw.trim();
    if value.is_empty() || value.len() > MAX_URI_LENGTH {
        return Err(invalid());
    }
    let url = Url::parse(value).map_err(|_| invalid())?;
    if url.fragment().is_some() {
        return Err(invalid());
    }
    if !allowed(&url) {
        return Err(invalid());
    }
    Ok(value.to_owned())
}

fn bounded<T>(items: Vec<T>, field: &'static str) -> Result<Vec<T>, AppError> {
    if items.len() > MAX_REDIRECT_URIS {
        return Err(client::error::InvalidCollectionSize::new(MAX_REDIRECT_URIS).with_field(field));
    }
    Ok(items)
}

pub(crate) fn validate_settings(
    settings: ClientProtocolSettings,
) -> Result<ClientProtocolSettings, AppError> {
    let mut seen_platforms = Vec::new();
    let mut platforms = Vec::with_capacity(settings.platforms.len());
    for platform in settings.platforms {
        if seen_platforms.contains(&platform.platform) {
            return Err(
                client::error::DuplicatePlatform::new(&platform.platform).with_field("platforms")
            );
        }
        seen_platforms.push(platform.platform.clone());
        let mut uris = Vec::new();
        for raw in bounded(platform.redirect_uris, "platforms.redirectUris")? {
            let uri = parse_uri(
                &raw,
                |url| platform.platform.allows_redirect_uri_scheme(url),
                |uri| client::error::InvalidRedirectUri::new(uri).into_error(),
                "platforms.redirectUris",
            )?;
            if !uris.contains(&uri) {
                uris.push(uri);
            }
        }
        if !uris.is_empty() {
            platforms.push(ClientPlatform {
                platform: platform.platform,
                redirect_uris: uris,
            });
        }
    }

    let native = platforms
        .iter()
        .any(|platform| platform.platform == OpenIdConnectClientPlatformType::Native);
    let mut post_logout_redirect_uris = Vec::new();
    for raw in bounded(
        settings.post_logout_redirect_uris,
        "post_logout_redirect_uris",
    )? {
        let uri = parse_uri(
            &raw,
            |url| {
                OpenIdConnectClientPlatformType::Web.allows_redirect_uri_scheme(url)
                    || native
                        && OpenIdConnectClientPlatformType::Native.allows_redirect_uri_scheme(url)
            },
            |uri| client::error::InvalidPostLogoutRedirectUri::new(uri).into_error(),
            "post_logout_redirect_uris",
        )?;
        if !post_logout_redirect_uris.contains(&uri) {
            post_logout_redirect_uris.push(uri);
        }
    }

    let mut grant_types = Vec::new();
    for grant in settings.grant_types {
        if !MANAGEABLE_GRANT_TYPES.contains(&grant) {
            return Err(
                client::error::UnsupportedGrantType::new(grant.as_str()).with_field("grant_types")
            );
        }
        if !grant_types.contains(&grant) {
            grant_types.push(grant);
        }
    }
    if grant_types.is_empty() {
        return Err(client::error::InvalidGrantTypes.with_field("grant_types"));
    }
    if grant_types.contains(&GrantType::RefreshToken)
        && !grant_types.contains(&GrantType::AuthorizationCode)
        && !grant_types.contains(&GrantType::DeviceCode)
    {
        return Err(client::error::RefreshTokenRequiresInteractiveGrant.with_field("grant_types"));
    }
    if grant_types.contains(&GrantType::AuthorizationCode) && platforms.is_empty() {
        return Err(client::error::RedirectUriRequired.with_field("platforms.redirectUris"));
    }
    // Keep a stable order so equal settings compare and persist identically.
    grant_types.sort_by_key(|grant| {
        MANAGEABLE_GRANT_TYPES
            .iter()
            .position(|candidate| candidate == grant)
    });

    Ok(ClientProtocolSettings {
        platforms,
        post_logout_redirect_uris,
        grant_types,
        // Derived from the credentials by the repository; never taken from input.
        token_endpoint_auth_methods: Vec::new(),
        allow_public_client_flow: settings.allow_public_client_flow,
        require_pushed_authorization_requests: settings.require_pushed_authorization_requests,
        skip_consent: settings.skip_consent,
        cors_enabled: settings.cors_enabled,
        oauth_version: settings.oauth_version,
        include_scoped_claims_in_id_token: settings.include_scoped_claims_in_id_token,
        include_scoped_claims_in_access_token: settings.include_scoped_claims_in_access_token,
    })
}

fn validate_key_expiry(expires_at: chrono::DateTime<Utc>) -> Result<(), AppError> {
    let now = Utc::now();
    let earliest = now + Duration::days(MIN_PUBLIC_KEY_LIFETIME_DAYS) - Duration::minutes(5);
    let latest = now + Duration::days(MAX_PUBLIC_KEY_LIFETIME_DAYS) + Duration::days(1);
    if expires_at < earliest || expires_at > latest {
        return Err(client::error::InvalidCredentialExpiry::new(
            MIN_PUBLIC_KEY_LIFETIME_DAYS,
            MAX_PUBLIC_KEY_LIFETIME_DAYS,
        )
        .with_field("expires_at"));
    }
    Ok(())
}

fn parse_jwks_uri(raw: &str) -> Result<Url, AppError> {
    let invalid = || client::error::InvalidJwksUri.with_field("jwks_uri");
    let raw = raw.trim();
    if raw.is_empty() || raw.len() > MAX_URI_LENGTH {
        return Err(invalid());
    }
    let url = Url::parse(raw).map_err(|_| invalid())?;
    if url.fragment().is_some() || !url.username().is_empty() || url.password().is_some() {
        return Err(invalid());
    }
    validate_https_public_url(&url).map_err(|_| invalid())?;
    Ok(url)
}

#[derive(serde::Deserialize)]
struct RemoteJwks {
    keys: Vec<serde_json::Value>,
}

/// Store a read key in the form client assertion verification reads it. A JWK
/// is also kept as its JSON text, matching keys registered dynamically.
fn key_credential(material: PublicKeyMaterial) -> OpenIdConnectCredentialData {
    match material {
        PublicKeyMaterial::Pem(public_key) => OpenIdConnectCredentialData::ClientPublicKey {
            public_key,
            jwk: None,
        },
        PublicKeyMaterial::Jwk(jwk) => OpenIdConnectCredentialData::ClientPublicKey {
            public_key: serde_json::to_string(&jwk).unwrap_or_default(),
            jwk: Some(jwk),
        },
    }
}

/// Fetch the key set once and keep the keys that are usable public keys.
async fn fetch_client_jwks(
    remote_fetcher: &dyn RemoteDocumentFetcher,
    reader: &dyn ClientPublicKeyReader,
    jwks_uri: &Url,
) -> Result<Vec<PublicJwk>, AppError> {
    let unavailable = || client::error::JwksUnavailable.with_field("jwks_uri");
    let body = remote_fetcher
        .fetch_https_public_document(jwks_uri, DEFAULT_REMOTE_DOCUMENT_MAX_BYTES)
        .await
        .map_err(|error| unavailable().with_source(error))?;
    let document: RemoteJwks = serde_json::from_slice(&body).map_err(|_| unavailable())?;
    let keys: Vec<PublicJwk> = document
        .keys
        .into_iter()
        .filter_map(|key| match reader.read(&key.to_string()) {
            Ok(read) => match read.material {
                PublicKeyMaterial::Jwk(jwk) => Some(jwk),
                PublicKeyMaterial::Pem(_) => None,
            },
            Err(_) => None,
        })
        .collect();
    if keys.is_empty() {
        return Err(unavailable());
    }
    Ok(keys)
}

// ----------------------------------------------------------------------
// Error mapping
// ----------------------------------------------------------------------

fn map_public_key_error(error: PublicKeyError) -> AppError {
    match error {
        PublicKeyError::Length | PublicKeyError::Unusable => {
            client::error::InvalidPublicKey.with_field("key")
        }
        PublicKeyError::Private => client::error::PrivateKeyNotAccepted.with_field("key"),
        PublicKeyError::CertificateExpired => client::error::CertificateExpired.with_field("key"),
    }
}

fn map_localized_error(error: LocalizedTextError) -> AppError {
    use LocalizedTextError as Error;
    match error {
        Error::InvalidLocale { .. } => {
            client::error::InvalidLocale::new(35).with_field("names.locale")
        }
        Error::DuplicateLocale { locale } => {
            client::error::DuplicateLocale::new(locale).with_field("names")
        }
        Error::EmptyName { .. } => client::error::InvalidName::new().with_field("names"),
        Error::TextTooLong { max, .. } => {
            client::error::InvalidDescription::new(max).with_field("descriptions")
        }
        Error::TooManyEntries { field, max } => {
            client::error::InvalidCollectionSize::new(max).with_field(field)
        }
    }
}

fn map_repository_error(error: ClientManagementRepositoryError) -> AppError {
    use ClientManagementRepositoryError as Error;
    match error {
        error @ Error::Storage(_) => client::error::StorageFailed.with_source(error),
        Error::Authorization(source) => AppError::from(source),
        error @ Error::AuditFailed(_) => authorization::error::AuditWriteFailed.with_source(error),
        Error::LastRecoverableAdministrator => authorization::error::LastOwnerProtected.into(),
        Error::CorruptRecord => client::error::StorageFailed.into(),
        Error::NotFound(ClientEntityKind::Client) => client::error::ClientNotFound.into(),
        Error::NotFound(ClientEntityKind::Credential) => client::error::CredentialNotFound.into(),
        Error::VersionConflict { current_version } => {
            client::error::VersionConflict::new(current_version).with_field("expected_version")
        }
        Error::BuiltInProtected => client::error::BuiltInProtected.into(),
        Error::CredentialNotSecret => client::error::CredentialNotSecret.into(),
        Error::CredentialRevoked => client::error::CredentialRevoked.into(),
        Error::CredentialLimitReached { max } => {
            client::error::CredentialLimitReached::new(max).into()
        }
    }
}

/// Pairwise subject rules depend on both the subject settings and the
/// redirect URIs. Either side may change alone; the other comes from the
/// stored client, and the repository's version check rejects a concurrent
/// edit. The sector document is fetched only when an input actually changed.
async fn validate_subject_change(
    remote_fetcher: &dyn RemoteDocumentFetcher,
    current: &ClientRecord,
    settings: Option<&ClientProtocolSettings>,
    advanced: Option<&ClientAdvancedSettings>,
) -> Result<(), AppError> {
    let settings = settings.unwrap_or(&current.settings);
    let advanced = advanced.unwrap_or(&current.advanced);
    if advanced.subject_type != SubjectType::Pairwise && advanced.sector_identifier_uri.is_none() {
        return Ok(());
    }
    if settings.platforms == current.settings.platforms
        && advanced.subject_type == current.advanced.subject_type
        && advanced.sector_identifier_uri == current.advanced.sector_identifier_uri
    {
        return Ok(());
    }
    let redirect_uris = settings
        .platforms
        .iter()
        .flat_map(|platform| platform.redirect_uris.iter().cloned())
        .collect::<Vec<_>>();
    advanced::validate_subject_identifier(remote_fetcher, advanced, &redirect_uris).await
}

mod advanced;
#[cfg(test)]
mod tests;
