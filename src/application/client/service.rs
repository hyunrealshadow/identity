//! OAuth client management use cases.
//!
//! Entry guards establish that the caller held a management scope when the
//! request started. The service validates and normalizes input; every write
//! passes the immutable request authority to the repository, which re-checks
//! live authority inside the mutation transaction.

use std::sync::Arc;

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use identity_domain::{
    client::model::ClientOid,
    openid_connect::{
        GrantType, OpenIdConnectClientPlatformType, OpenIdConnectCredentialData,
        OpenIdConnectCredentialOid, TokenEndpointAuthMethod,
    },
    rbac::{LocalizedMetadata, LocalizedTextError},
};
use rand::{RngExt as _, rng};
use url::Url;
use uuid::Uuid;

use super::{
    model::{
        ClientCredentialRecord, ClientCredentialRevokeResult, ClientFilter, ClientPage,
        ClientPageItem, ClientPageRequest, ClientPlatform, ClientProtocolSettings, ClientRecord,
        ClientSecretResult, ClientStateCommand, CreateClientCommand, CreateClientSecretCommand,
        MANAGEABLE_AUTH_METHODS, MANAGEABLE_GRANT_TYPES, MAX_CLIENT_DESCRIPTION_LENGTH,
        MAX_CLIENT_MUTATION_ID_LENGTH, MAX_CLIENT_NAME_LENGTH, MAX_QUERY_FILTER_LENGTH,
        MAX_REASON_LENGTH, MAX_REDIRECT_URIS, MAX_SECRET_LIFETIME_DAYS, MAX_URI_LENGTH,
        MIN_SECRET_LIFETIME_DAYS, RevokeClientCredentialCommand, UpdateClientCommand,
        uses_client_secret,
    },
    repository::{
        ClientEntityKind, ClientManagementRepository, ClientManagementRepositoryError, ClientQuery,
        ClientStateTransaction, CreateClientSecretTransaction, CreateClientTransaction,
        NewClientSecret, RevokeClientCredentialTransaction, UpdateClientTransaction,
    },
};
use crate::{
    data_protection::DataProtector,
    error::{
        AppError,
        codes::{authorization::AuthorizationErrorCode, client::ClientErrorCode},
    },
    observability::{BusinessEvent, EventSink, EventValue, NoopEventSink, error_outcome},
    rbac::{
        RbacManagementAuthority,
        cursor::{CURSOR_KIND_CLIENT, PageArguments, encode_cursor, prepare_page},
    },
};

const SECRET_BYTES: usize = 32;

pub struct ClientManagementService {
    repository: Arc<dyn ClientManagementRepository>,
    data_protector: Arc<dyn DataProtector>,
    events: Arc<dyn EventSink>,
}

impl ClientManagementService {
    #[must_use]
    pub fn new(
        repository: Arc<dyn ClientManagementRepository>,
        data_protector: Arc<dyn DataProtector>,
    ) -> Self {
        Self {
            repository,
            data_protector,
            events: Arc::new(NoopEventSink),
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
        let mut items = Vec::with_capacity(data.items.len());
        for entry in data.items {
            let cursor = encode_cursor(
                self.data_protector.as_ref(),
                CURSOR_KIND_CLIENT,
                order.as_u8(),
                &prepared.filter_fingerprint,
                &entry.sort_key,
            )
            .await?;
            items.push(ClientPageItem {
                record: entry.record,
                cursor,
            });
        }
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
            let reason = validate_reason(&command.reason)?;
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
                    reason,
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
            let reason = validate_reason(&command.reason)?;
            validate_client_mutation_id(command.client_mutation_id.as_deref())?;
            if command.name.is_none()
                && command.description.is_none()
                && command.names.is_none()
                && command.descriptions.is_none()
                && command.settings.is_none()
            {
                return Err(AppError::from_code(ClientErrorCode::EmptyUpdate));
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
                    settings: command.settings.map(validate_settings).transpose()?,
                    reason,
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
            let reason = validate_reason(&command.reason)?;
            validate_client_mutation_id(command.client_mutation_id.as_deref())?;
            validate_secret_lifetime(command.lifetime_days)?;
            let client = self
                .repository
                .find_client(command.client_oid)
                .await
                .map_err(map_repository_error)?
                .ok_or_else(|| AppError::from_code(ClientErrorCode::ClientNotFound))?;
            if !uses_client_secret(&client.settings.token_endpoint_auth_methods) {
                return Err(AppError::from_code(ClientErrorCode::SecretNotUsed));
            }
            self.repository
                .create_client_secret(CreateClientSecretTransaction {
                    client_oid: command.client_oid,
                    expected_version: command.expected_version,
                    replaces: command.replaces,
                    secret: new_secret(command.lifetime_days),
                    reason,
                    authority: authority.clone(),
                })
                .await
                .map_err(map_repository_error)
        }
        .await;
        self.emit_result(action, &result);
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
            let reason = validate_reason(&command.reason)?;
            validate_client_mutation_id(command.client_mutation_id.as_deref())?;
            self.repository
                .revoke_client_credential(RevokeClientCredentialTransaction {
                    client_oid: command.client_oid,
                    credential_oid: command.credential_oid,
                    expected_version: command.expected_version,
                    reason,
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
    let reason = validate_reason(&command.reason)?;
    validate_client_mutation_id(command.client_mutation_id.as_deref())?;
    Ok(ClientStateTransaction {
        client_oid: command.client_oid,
        expected_version: command.expected_version,
        reason,
        authority: authority.clone(),
    })
}

// ----------------------------------------------------------------------
// Validation
// ----------------------------------------------------------------------

fn validate_reason(reason: &str) -> Result<String, AppError> {
    let reason = reason.trim();
    if reason.chars().count() > MAX_REASON_LENGTH {
        return Err(AppError::from_code(ClientErrorCode::InvalidReason)
            .with_param("max", MAX_REASON_LENGTH.to_string())
            .with_field("reason"));
    }
    Ok(reason.to_owned())
}

fn validate_client_mutation_id(value: Option<&str>) -> Result<(), AppError> {
    if value.is_some_and(|value| value.chars().count() > MAX_CLIENT_MUTATION_ID_LENGTH) {
        return Err(
            AppError::from_code(ClientErrorCode::InvalidClientMutationId)
                .with_param("max", MAX_CLIENT_MUTATION_ID_LENGTH.to_string())
                .with_field("clientMutationId"),
        );
    }
    Ok(())
}

fn normalize_filter(mut filter: ClientFilter) -> Result<ClientFilter, AppError> {
    filter.query = match filter.query.as_deref().map(str::trim) {
        None | Some("") => None,
        Some(value) if value.chars().count() > MAX_QUERY_FILTER_LENGTH => {
            return Err(AppError::from_code(ClientErrorCode::InvalidFilter)
                .with_param("max", MAX_QUERY_FILTER_LENGTH.to_string())
                .with_field("query"));
        }
        Some(value) => Some(value.to_owned()),
    };
    Ok(filter)
}

fn validate_name(value: &str) -> Result<String, AppError> {
    let value = value.trim();
    if value.is_empty() || value.chars().count() > MAX_CLIENT_NAME_LENGTH {
        return Err(AppError::from_code(ClientErrorCode::InvalidName)
            .with_param("max", MAX_CLIENT_NAME_LENGTH.to_string())
            .with_field("name"));
    }
    Ok(value.to_owned())
}

fn validate_description(value: &str) -> Result<String, AppError> {
    let value = value.trim();
    if value.chars().count() > MAX_CLIENT_DESCRIPTION_LENGTH {
        return Err(AppError::from_code(ClientErrorCode::InvalidDescription)
            .with_param("max", MAX_CLIENT_DESCRIPTION_LENGTH.to_string())
            .with_field("description"));
    }
    Ok(value.to_owned())
}

fn validate_secret_lifetime(days: u32) -> Result<(), AppError> {
    if !(MIN_SECRET_LIFETIME_DAYS..=MAX_SECRET_LIFETIME_DAYS).contains(&days) {
        return Err(AppError::from_code(ClientErrorCode::InvalidSecretLifetime)
            .with_param("min", MIN_SECRET_LIFETIME_DAYS.to_string())
            .with_param("max", MAX_SECRET_LIFETIME_DAYS.to_string())
            .with_field("lifetimeDays"));
    }
    Ok(())
}

/// Validate one URI and return it with its registered spelling.
fn parse_uri(
    raw: &str,
    allowed: impl Fn(&Url) -> bool,
    code: ClientErrorCode,
    field: &'static str,
) -> Result<String, AppError> {
    let invalid = || {
        AppError::from_code(code)
            .with_param("uri", raw.to_owned())
            .with_field(field)
    };
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
        return Err(AppError::from_code(ClientErrorCode::InvalidCollectionSize)
            .with_param("max", MAX_REDIRECT_URIS.to_string())
            .with_field(field));
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
            return Err(AppError::from_code(ClientErrorCode::DuplicatePlatform)
                .with_param("platform", platform.platform.to_string())
                .with_field("platforms"));
        }
        seen_platforms.push(platform.platform.clone());
        let mut uris = Vec::new();
        for raw in bounded(platform.redirect_uris, "platforms.redirectUris")? {
            let uri = parse_uri(
                &raw,
                |url| platform.platform.allows_redirect_uri_scheme(url),
                ClientErrorCode::InvalidRedirectUri,
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
    for raw in bounded(settings.post_logout_redirect_uris, "postLogoutRedirectUris")? {
        let uri = parse_uri(
            &raw,
            |url| {
                OpenIdConnectClientPlatformType::Web.allows_redirect_uri_scheme(url)
                    || native
                        && OpenIdConnectClientPlatformType::Native.allows_redirect_uri_scheme(url)
            },
            ClientErrorCode::InvalidPostLogoutRedirectUri,
            "postLogoutRedirectUris",
        )?;
        if !post_logout_redirect_uris.contains(&uri) {
            post_logout_redirect_uris.push(uri);
        }
    }

    let mut methods: Vec<TokenEndpointAuthMethod> = Vec::new();
    for method in settings.token_endpoint_auth_methods {
        if !MANAGEABLE_AUTH_METHODS.contains(&method) {
            return Err(AppError::from_code(ClientErrorCode::UnsupportedAuthMethod)
                .with_param("method", method.to_string())
                .with_field("tokenEndpointAuthMethods"));
        }
        if !methods.contains(&method) {
            methods.push(method);
        }
    }
    if methods.is_empty() {
        return Err(AppError::from_code(ClientErrorCode::ValidationFailed)
            .with_param("field", "tokenEndpointAuthMethods")
            .with_field("tokenEndpointAuthMethods"));
    }
    methods.sort_by_key(|method| {
        MANAGEABLE_AUTH_METHODS
            .iter()
            .position(|candidate| candidate == method)
    });

    let mut grant_types = Vec::new();
    for grant in settings.grant_types {
        if !MANAGEABLE_GRANT_TYPES.contains(&grant) {
            return Err(AppError::from_code(ClientErrorCode::UnsupportedGrantType)
                .with_param("grant_type", grant.as_str())
                .with_field("grantTypes"));
        }
        if !grant_types.contains(&grant) {
            grant_types.push(grant);
        }
    }
    if grant_types.is_empty() {
        return Err(
            AppError::from_code(ClientErrorCode::InvalidGrantTypes).with_field("grantTypes")
        );
    }
    if grant_types.contains(&GrantType::RefreshToken)
        && !grant_types.contains(&GrantType::AuthorizationCode)
        && !grant_types.contains(&GrantType::DeviceCode)
    {
        return Err(
            AppError::from_code(ClientErrorCode::RefreshTokenRequiresInteractiveGrant)
                .with_field("grantTypes"),
        );
    }
    // `none` coexists with secret methods (the public client flow is a
    // separate switch), but client credentials always needs a real secret.
    if grant_types.contains(&GrantType::ClientCredentials) && !uses_client_secret(&methods) {
        return Err(
            AppError::from_code(ClientErrorCode::PublicClientGrantNotAllowed)
                .with_param("grant_type", GrantType::ClientCredentials.as_str())
                .with_field("grantTypes"),
        );
    }
    if grant_types.contains(&GrantType::AuthorizationCode) && platforms.is_empty() {
        return Err(AppError::from_code(ClientErrorCode::RedirectUriRequired)
            .with_field("platforms.redirectUris"));
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
        token_endpoint_auth_methods: methods,
        allow_public_client_flow: settings.allow_public_client_flow,
        require_pushed_authorization_requests: settings.require_pushed_authorization_requests,
        skip_consent: settings.skip_consent,
        cors_enabled: settings.cors_enabled,
        oauth_version: settings.oauth_version,
        include_scoped_claims_in_id_token: settings.include_scoped_claims_in_id_token,
        include_scoped_claims_in_access_token: settings.include_scoped_claims_in_access_token,
    })
}

// ----------------------------------------------------------------------
// Error mapping
// ----------------------------------------------------------------------

fn map_localized_error(error: LocalizedTextError) -> AppError {
    use LocalizedTextError as Error;
    match error {
        Error::InvalidLocale { .. } => AppError::from_code(ClientErrorCode::InvalidLocale)
            .with_param("max", "35")
            .with_field("names.locale"),
        Error::DuplicateLocale { locale } => AppError::from_code(ClientErrorCode::DuplicateLocale)
            .with_param("locale", locale)
            .with_field("names"),
        Error::EmptyName { .. } => {
            AppError::from_code(ClientErrorCode::InvalidName).with_field("names")
        }
        Error::TextTooLong { max, .. } => AppError::from_code(ClientErrorCode::InvalidDescription)
            .with_param("max", max.to_string())
            .with_field("descriptions"),
        Error::TooManyEntries { field, max } => {
            AppError::from_code(ClientErrorCode::InvalidCollectionSize)
                .with_param("max", max.to_string())
                .with_field(field)
        }
    }
}

fn map_repository_error(error: ClientManagementRepositoryError) -> AppError {
    use ClientManagementRepositoryError as Error;
    match error {
        error @ Error::Storage(_) => {
            AppError::from_code(ClientErrorCode::StorageFailed).with_source(error)
        }
        Error::Authorization(source) => AppError::from(source),
        error @ Error::AuditFailed(_) => {
            AppError::from_code(AuthorizationErrorCode::AuditWriteFailed).with_source(error)
        }
        Error::LastRecoverableAdministrator => {
            AppError::from_code(AuthorizationErrorCode::LastOwnerProtected)
        }
        Error::CorruptRecord => AppError::from_code(ClientErrorCode::StorageFailed),
        Error::NotFound(ClientEntityKind::Client) => {
            AppError::from_code(ClientErrorCode::ClientNotFound)
        }
        Error::NotFound(ClientEntityKind::Credential) => {
            AppError::from_code(ClientErrorCode::CredentialNotFound)
        }
        Error::VersionConflict { current_version } => {
            AppError::from_code(ClientErrorCode::VersionConflict)
                .with_param("current_version", current_version.to_string())
                .with_field("expectedVersion")
        }
        Error::BuiltInProtected => AppError::from_code(ClientErrorCode::BuiltInProtected),
        Error::CredentialNotSecret => AppError::from_code(ClientErrorCode::CredentialNotSecret),
        Error::CredentialRevoked => AppError::from_code(ClientErrorCode::CredentialRevoked),
    }
}

#[cfg(test)]
mod tests;
