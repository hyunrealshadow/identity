use crate::domain::key::JwsAlgorithm;
use crate::domain::openid_connect::OpenIdConnectClientRepositoryError;
use crate::domain::openid_connect::ScopeSet;
use crate::domain::openid_connect::scope_catalog::ScopeCatalogRepository;
use crate::observability::BusinessEvent;
use crate::observability::EventSink;
use crate::observability::EventValue;
use crate::observability::NoopEventSink;
use std::collections::BTreeSet;
use std::sync::Arc;

use chrono::{Duration, Utc};
use url::Url;
use uuid::Uuid;

use crate::{
    application::{
        error::{AppError, codes::registration::RegistrationErrorCode},
        setting::{OpenIdConnectSettings, SettingsSource},
    },
    domain::{
        client::model::{Client, ClientProtocol},
        openid_connect::{
            DEFAULT_GRANT_TYPES, GrantType, OpenIdConnectClientMetadata,
            OpenIdConnectClientPlatform, OpenIdConnectClientRegistration,
            OpenIdConnectClientRegistrationRepository, OpenIdConnectClientSettings,
            OpenIdConnectCredentialData, ResponseType, SubjectType, TokenEndpointAuthMethod,
        },
    },
};

mod credential;
mod request;
mod response;
#[cfg(test)]
mod tests;
mod token;
mod validation;

pub use request::{
    DynamicClientJwks, DynamicClientRegistrationRequest, DynamicClientUpdateRequest,
};
pub use response::DynamicClientRegistrationResponse;

use credential::{client_credentials_from_jwks, client_credentials_from_jwks_uri};
use response::{registration_client_uri, response_from_client};
use token::{default_skip_consent, generate_client_secret, generate_registration_access_token};
use validation::{
    default_response_types, parse_application_type, parse_metadata_value, parse_metadata_values,
    reject_none_algorithm, split_scope, validate_grant_response_type_consistency,
    validate_initiate_login_uri, validate_request_object_encryption,
    validate_request_object_signing, validate_response_encryption_algorithm,
    validate_response_signing_algorithm, validate_sector_identifier_uri,
};

pub struct DynamicClientRegistrationService {
    settings: Arc<dyn SettingsSource>,
    repo: Arc<dyn OpenIdConnectClientRegistrationRepository>,
    scope_catalog: Option<Arc<dyn ScopeCatalogRepository>>,
    events: Arc<dyn EventSink>,
}

impl DynamicClientRegistrationService {
    #[must_use]
    pub fn new(
        settings: Arc<dyn SettingsSource>,
        repo: Arc<dyn OpenIdConnectClientRegistrationRepository>,
    ) -> Self {
        Self {
            settings,
            repo,
            scope_catalog: None,
            events: Arc::new(NoopEventSink),
        }
    }

    /// Attach the key event and audit sink.
    #[must_use]
    pub fn with_events(mut self, events: Arc<dyn EventSink>) -> Self {
        self.events = events;
        self
    }

    pub fn with_scope_catalog(mut self, repo: Arc<dyn ScopeCatalogRepository>) -> Self {
        self.scope_catalog = Some(repo);
        self
    }

    fn enabled(&self) -> bool {
        self.settings
            .snapshot()
            .section::<OpenIdConnectSettings>()
            .dynamic_registration
            .enabled
    }

    fn record_client_change(&self, event: &'static str, client_oid: Uuid, outcome: &'static str) {
        self.events.emit(
            BusinessEvent::audit(event)
                .outcome(outcome)
                .attribute("client_oid", EventValue::Text(client_oid.to_string())),
        );
    }

    #[tracing::instrument(skip_all, name = "client.register")]
    pub async fn register(
        &self,
        request: DynamicClientRegistrationRequest,
        issuer: &Url,
    ) -> Result<DynamicClientRegistrationResponse, AppError> {
        let (registration, mut response) = self.prepare_registration(request, issuer).await?;
        let client_id = self.repo.create(registration).await.map_err(|error| {
            if matches!(
                &error,
                OpenIdConnectClientRepositoryError::InvalidMetadataValue { field: "scope", .. }
            ) {
                return AppError::from_code(RegistrationErrorCode::InvalidClientMetadata)
                    .with_param("field", "scope")
                    .with_source(error);
            }
            AppError::from_code(RegistrationErrorCode::ClientCreateFailed).with_source(error)
        })?;
        response.client_id = client_id.to_string();
        response.registration_client_uri = Some(registration_client_uri(issuer, client_id)?);
        self.record_client_change("client.registered", client_id, "success");
        Ok(response)
    }

    async fn prepare_registration(
        &self,
        request: DynamicClientRegistrationRequest,
        issuer: &Url,
    ) -> Result<
        (
            OpenIdConnectClientRegistration,
            DynamicClientRegistrationResponse,
        ),
        AppError,
    > {
        if !self.enabled() {
            return Err(AppError::from_code(
                RegistrationErrorCode::DynamicRegistrationDisabled,
            ));
        }
        let response_types = parse_metadata_values::<ResponseType>(
            "response_types",
            request.response_types.as_deref(),
        )?
        .unwrap_or_else(default_response_types);
        let grant_types =
            parse_metadata_values::<GrantType>("grant_types", request.grant_types.as_deref())?
                .unwrap_or_else(|| DEFAULT_GRANT_TYPES.to_vec());
        validate_grant_response_type_consistency(&response_types, &grant_types)?;

        // `redirect_uris` is only meaningful for clients that use a redirect
        // based flow; a device-only client registers without one (RFC 7591 §2
        // requires it for authorization code clients, RFC 8628 has no redirect).
        let uses_redirect_flow = grant_types
            .iter()
            .any(|grant| matches!(grant, GrantType::AuthorizationCode | GrantType::Implicit));
        if request.redirect_uris.is_empty() && uses_redirect_flow {
            return Err(AppError::from_code(
                RegistrationErrorCode::RedirectUrisRequired,
            ));
        }
        let parsed_redirect_uris = request
            .redirect_uris
            .iter()
            .map(|raw| {
                Url::parse(raw).map_err(AppError::map_source(
                    RegistrationErrorCode::InvalidRedirectUri,
                ))
            })
            .collect::<Result<Vec<_>, _>>()?;
        if parsed_redirect_uris
            .iter()
            .any(|uri| uri.fragment().is_some())
        {
            return Err(AppError::from_code(
                RegistrationErrorCode::InvalidRedirectUri,
            ));
        }

        let platform = parse_application_type(request.application_type.as_deref())?;
        if parsed_redirect_uris
            .iter()
            .any(|uri| !platform.allows_redirect_uri_scheme(uri))
        {
            return Err(AppError::from_code(
                RegistrationErrorCode::InvalidRedirectUri,
            ));
        }
        let subject_type = request
            .subject_type
            .as_deref()
            .map(str::parse::<SubjectType>)
            .transpose()
            .map_err(|error| {
                AppError::from_code(RegistrationErrorCode::UnsupportedSubjectType)
                    .with_param(
                        "subject_type",
                        request.subject_type.as_deref().unwrap_or_default(),
                    )
                    .with_source(error)
            })?;
        validate_sector_identifier_uri(
            request.sector_identifier_uri.as_ref(),
            &request.redirect_uris,
        )
        .await?;
        validate_initiate_login_uri(request.initiate_login_uri.as_ref())?;
        if request.default_max_age.is_some_and(|value| value < 0) {
            return Err(
                AppError::from_code(RegistrationErrorCode::InvalidClientMetadata)
                    .with_param("field", "default_max_age"),
            );
        }
        let token_auth_method = request
            .token_endpoint_auth_method
            .as_deref()
            .unwrap_or("client_secret_basic")
            .parse::<TokenEndpointAuthMethod>()
            .map_err(|error| {
                AppError::from_code(RegistrationErrorCode::InvalidClientMetadata)
                    .with_param("field", "token_endpoint_auth_method")
                    .with_source(error)
            })?;
        if grant_types.contains(&GrantType::ClientCredentials)
            && token_auth_method == TokenEndpointAuthMethod::None
        {
            return Err(
                AppError::from_code(RegistrationErrorCode::InvalidClientMetadata)
                    .with_param("field", "token_endpoint_auth_method"),
            );
        }
        if request.id_token_encrypted_response_enc.is_some()
            && request.id_token_encrypted_response_alg.is_none()
        {
            return Err(
                AppError::from_code(RegistrationErrorCode::InvalidClientMetadata)
                    .with_param("field", "id_token_encrypted_response_alg"),
            );
        }
        if request.userinfo_encrypted_response_enc.is_some()
            && request.userinfo_encrypted_response_alg.is_none()
        {
            return Err(
                AppError::from_code(RegistrationErrorCode::InvalidClientMetadata)
                    .with_param("field", "userinfo_encrypted_response_alg"),
            );
        }
        if request.frontchannel_logout_session_required == Some(true)
            && request.frontchannel_logout_uri.is_none()
        {
            return Err(
                AppError::from_code(RegistrationErrorCode::InvalidClientMetadata)
                    .with_param("field", "frontchannel_logout_uri"),
            );
        }
        if request.backchannel_logout_session_required == Some(true)
            && request.backchannel_logout_uri.is_none()
        {
            return Err(
                AppError::from_code(RegistrationErrorCode::InvalidClientMetadata)
                    .with_param("field", "backchannel_logout_uri"),
            );
        }
        for (field, value) in [
            (
                "userinfo_signed_response_alg",
                request.userinfo_signed_response_alg.as_deref(),
            ),
            (
                "id_token_encrypted_response_alg",
                request.id_token_encrypted_response_alg.as_deref(),
            ),
            (
                "token_endpoint_auth_signing_alg",
                request.token_endpoint_auth_signing_alg.as_deref(),
            ),
        ] {
            reject_none_algorithm(field, value)?;
        }
        let auth_signing_alg = request
            .token_endpoint_auth_signing_alg
            .as_deref()
            .map(str::parse::<JwsAlgorithm>)
            .transpose()
            .map_err(|_| {
                AppError::from_code(RegistrationErrorCode::InvalidClientMetadata)
                    .with_param("field", "token_endpoint_auth_signing_alg")
            })?;
        if auth_signing_alg.is_some_and(|alg| {
            !matches!(
                (token_auth_method, alg),
                (
                    TokenEndpointAuthMethod::ClientSecretJwt,
                    JwsAlgorithm::Hs256 | JwsAlgorithm::Hs384 | JwsAlgorithm::Hs512
                ) | (
                    TokenEndpointAuthMethod::PrivateKeyJwt,
                    JwsAlgorithm::Asymmetric(_)
                )
            )
        }) {
            return Err(
                AppError::from_code(RegistrationErrorCode::InvalidClientMetadata)
                    .with_param("field", "token_endpoint_auth_signing_alg"),
            );
        }
        reject_none_algorithm(
            "id_token_signed_response_alg",
            request.id_token_signed_response_alg.as_deref(),
        )?;
        validate_response_signing_algorithm(
            "id_token_signed_response_alg",
            request.id_token_signed_response_alg.as_deref(),
            !response_types.iter().any(ResponseType::includes_id_token),
        )?;
        validate_response_signing_algorithm(
            "userinfo_signed_response_alg",
            request.userinfo_signed_response_alg.as_deref(),
            false,
        )?;
        validate_response_encryption_algorithm(
            "id_token_encrypted_response_alg",
            request.id_token_encrypted_response_alg.as_deref(),
        )?;
        validate_response_encryption_algorithm(
            "userinfo_encrypted_response_alg",
            request.userinfo_encrypted_response_alg.as_deref(),
        )?;
        for (field, value) in [
            (
                "id_token_encrypted_response_alg",
                request.id_token_encrypted_response_alg.as_deref(),
            ),
            (
                "id_token_encrypted_response_enc",
                request.id_token_encrypted_response_enc.as_deref(),
            ),
            (
                "userinfo_signed_response_alg",
                request.userinfo_signed_response_alg.as_deref(),
            ),
            (
                "userinfo_encrypted_response_alg",
                request.userinfo_encrypted_response_alg.as_deref(),
            ),
            (
                "userinfo_encrypted_response_enc",
                request.userinfo_encrypted_response_enc.as_deref(),
            ),
            (
                "token_endpoint_auth_signing_alg",
                request.token_endpoint_auth_signing_alg.as_deref(),
            ),
        ] {
            reject_none_algorithm(field, value)?;
        }
        validate_request_object_signing(request.request_object_signing_alg.as_deref())?;
        validate_request_object_encryption(
            request.request_object_encryption_alg.as_deref(),
            request.request_object_encryption_enc.as_deref(),
        )?;
        let public_client = token_auth_method == TokenEndpointAuthMethod::None;
        let client_secret = (!public_client).then(generate_client_secret);
        let client_secret_expires_at = client_secret
            .as_ref()
            .map(|_| (Utc::now() + Duration::days(365)).timestamp());
        let registration_access_token = generate_registration_access_token();
        let assigned_scopes = split_scope(request.scope.as_deref());
        let raw_scope = assigned_scopes.join(" ");
        ScopeSet::parse(request.scope.as_deref().unwrap_or(&raw_scope)).map_err(|error| {
            AppError::from_code(RegistrationErrorCode::InvalidClientMetadata)
                .with_param("field", "scope")
                .with_source(error)
        })?;
        let mut seen = BTreeSet::new();
        let assigned_scopes = assigned_scopes
            .into_iter()
            .filter(|name| seen.insert(name.clone()))
            .collect::<Vec<_>>();
        if let Some(catalog) = &self.scope_catalog {
            let names = catalog.list_names().await.map_err(AppError::internal)?;
            if assigned_scopes.iter().any(|scope| !names.contains(scope)) {
                return Err(
                    AppError::from_code(RegistrationErrorCode::InvalidClientMetadata)
                        .with_param("field", "scope"),
                );
            }
        }
        let client_name = request
            .client_name
            .clone()
            .unwrap_or_else(|| "Dynamic OpenID Connect Client".to_owned());
        let mut credentials = client_credentials_from_jwks(request.jwks.as_ref())?;
        if let Some(credential) =
            client_credentials_from_jwks_uri(request.jwks_uri.as_ref()).await?
        {
            credentials.push(credential);
        }
        if let Some(secret) = client_secret.as_ref() {
            credentials.push(OpenIdConnectCredentialData::ClientSecret {
                secret: secret.clone(),
            });
        }

        let metadata = OpenIdConnectClientMetadata {
            post_logout_redirect_uris: request.post_logout_redirect_uris.clone(),
            frontchannel_logout_uri: request.frontchannel_logout_uri.clone(),
            frontchannel_logout_session_required: request.frontchannel_logout_session_required,
            backchannel_logout_uri: request.backchannel_logout_uri.clone(),
            backchannel_logout_session_required: request.backchannel_logout_session_required,
            response_types: Some(response_types.clone()),
            grant_types: Some(grant_types.clone()),
            contacts: request.contacts.clone(),
            logo_uri: request.logo_uri.clone(),
            client_uri: request.client_uri.clone(),
            policy_uri: request.policy_uri.clone(),
            tos_uri: request.tos_uri.clone(),
            sector_identifier_uri: request.sector_identifier_uri.clone(),
            subject_type,
            id_token_signed_response_algs: parse_metadata_value(
                "id_token_signed_response_alg",
                request.id_token_signed_response_alg.as_deref(),
            )?
            .map(|value| vec![value]),
            id_token_encrypted_response_algs: parse_metadata_value(
                "id_token_encrypted_response_alg",
                request.id_token_encrypted_response_alg.as_deref(),
            )?
            .map(|value| vec![value]),
            id_token_encrypted_response_encs: parse_metadata_value(
                "id_token_encrypted_response_enc",
                request.id_token_encrypted_response_enc.as_deref(),
            )?
            .map(|value| vec![value]),
            userinfo_signed_response_algs: parse_metadata_value(
                "userinfo_signed_response_alg",
                request.userinfo_signed_response_alg.as_deref(),
            )?
            .map(|value| vec![value]),
            userinfo_encrypted_response_algs: parse_metadata_value(
                "userinfo_encrypted_response_alg",
                request.userinfo_encrypted_response_alg.as_deref(),
            )?
            .map(|value| vec![value]),
            userinfo_encrypted_response_encs: parse_metadata_value(
                "userinfo_encrypted_response_enc",
                request.userinfo_encrypted_response_enc.as_deref(),
            )?
            .map(|value| vec![value]),
            request_object_signing_algs: parse_metadata_value(
                "request_object_signing_alg",
                request.request_object_signing_alg.as_deref(),
            )?
            .map(|value| vec![value]),
            request_object_encryption_algs: parse_metadata_value(
                "request_object_encryption_alg",
                request.request_object_encryption_alg.as_deref(),
            )?
            .map(|value| vec![value]),
            request_object_encryption_encs: parse_metadata_value(
                "request_object_encryption_enc",
                request.request_object_encryption_enc.as_deref(),
            )?
            .map(|value| vec![value]),
            token_endpoint_auth_methods: Some(vec![token_auth_method]),
            token_endpoint_auth_signing_algs: parse_metadata_value(
                "token_endpoint_auth_signing_alg",
                request.token_endpoint_auth_signing_alg.as_deref(),
            )?
            .map(|value| vec![value]),
            default_max_age: request.default_max_age,
            require_auth_time: request.require_auth_time,
            default_acr_values: request.default_acr_values.clone(),
            initiate_login_uri: request.initiate_login_uri.clone(),
            request_uris: request.request_uris.clone(),
            settings: OpenIdConnectClientSettings {
                require_pushed_authorization_requests: request
                    .require_pushed_authorization_requests
                    .unwrap_or(false),
                skip_consent: default_skip_consent(),
                allow_public_client_flow: public_client,
                oauth_version: Default::default(),
                cors_enabled: false,
                include_scoped_claims_in_id_token: false,
                include_scoped_claims_in_access_token: false,
            },
        };

        let client = Client {
            oid: Uuid::new_v4(),
            protocol: ClientProtocol::OpenIdConnect,
            name: client_name,
            names: vec![],
            description: None,
            built_in: false,
            created_at: Utc::now(),
            updated_at: None,
        };
        let application_type = platform.to_string();
        let registration = OpenIdConnectClientRegistration {
            client,
            metadata,
            platforms: vec![OpenIdConnectClientPlatform {
                platform,
                redirect_uris: request.redirect_uris.clone(),
            }],
            assigned_scopes: assigned_scopes.clone(),
            credentials,
            registration_access_token: registration_access_token.clone(),
        };
        let client_id = registration.client.oid;
        let registration_client_uri = registration_client_uri(issuer, client_id)?;
        Ok((
            registration,
            DynamicClientRegistrationResponse {
                client_id: client_id.to_string(),
                registration_access_token: Some(registration_access_token),
                registration_client_uri: Some(registration_client_uri),
                client_secret,
                client_secret_expires_at,
                redirect_uris: request.redirect_uris,
                response_types: Some(response_types.iter().map(ToString::to_string).collect()),
                grant_types: Some(grant_types.iter().map(ToString::to_string).collect()),
                application_type: Some(application_type),
                contacts: request.contacts,
                client_name: request.client_name,
                logo_uri: request.logo_uri,
                client_uri: request.client_uri,
                policy_uri: request.policy_uri,
                tos_uri: request.tos_uri,
                sector_identifier_uri: request.sector_identifier_uri,
                subject_type: subject_type.map(|value| value.to_string()),
                id_token_signed_response_alg: request.id_token_signed_response_alg,
                id_token_encrypted_response_alg: request.id_token_encrypted_response_alg,
                id_token_encrypted_response_enc: request.id_token_encrypted_response_enc,
                userinfo_signed_response_alg: request.userinfo_signed_response_alg,
                userinfo_encrypted_response_alg: request.userinfo_encrypted_response_alg,
                userinfo_encrypted_response_enc: request.userinfo_encrypted_response_enc,
                request_object_signing_alg: request.request_object_signing_alg,
                request_object_encryption_alg: request.request_object_encryption_alg,
                request_object_encryption_enc: request.request_object_encryption_enc,
                token_endpoint_auth_method: Some(token_auth_method.to_string()),
                token_endpoint_auth_signing_alg: request.token_endpoint_auth_signing_alg,
                jwks: request.jwks,
                jwks_uri: request.jwks_uri,
                default_max_age: request.default_max_age,
                require_auth_time: request.require_auth_time,
                require_pushed_authorization_requests: request
                    .require_pushed_authorization_requests,
                default_acr_values: request.default_acr_values,
                initiate_login_uri: request.initiate_login_uri,
                request_uris: request.request_uris,
                post_logout_redirect_uris: request.post_logout_redirect_uris,
                frontchannel_logout_uri: request.frontchannel_logout_uri,
                frontchannel_logout_session_required: request.frontchannel_logout_session_required,
                backchannel_logout_uri: request.backchannel_logout_uri,
                backchannel_logout_session_required: request.backchannel_logout_session_required,
                scope: (!assigned_scopes.is_empty()).then(|| assigned_scopes.join(" ")),
            },
        ))
    }

    /// RFC 7592 replaces metadata; omitted optional fields are cleared.
    #[tracing::instrument(skip_all, name = "client.update")]
    pub async fn update(
        &self,
        client_id: &str,
        registration_access_token: &str,
        request: DynamicClientUpdateRequest,
        issuer: &Url,
    ) -> Result<DynamicClientRegistrationResponse, AppError> {
        let current = self
            .read(client_id, registration_access_token, issuer)
            .await?;
        if request.client_id != current.client_id
            || request.forbidden_fields.keys().any(|field| {
                matches!(
                    field.as_str(),
                    "registration_access_token"
                        | "registration_client_uri"
                        | "client_secret_expires_at"
                        | "client_id_issued_at"
                )
            })
        {
            return Err(AppError::from_code(
                RegistrationErrorCode::InvalidClientMetadata,
            ));
        }
        let client_oid = Uuid::parse_str(client_id).map_err(|_| {
            AppError::from_code(RegistrationErrorCode::InvalidRegistrationAccessToken)
        })?;
        let existing = self
            .repo
            .find_by_registration_access_token(client_oid, registration_access_token)
            .await
            .map_err(AppError::map_source(
                RegistrationErrorCode::ClientLookupFailed,
            ))?
            .ok_or_else(|| {
                AppError::from_code(RegistrationErrorCode::InvalidRegistrationAccessToken)
            })?;
        if existing.client().built_in {
            return Err(AppError::from_code(
                RegistrationErrorCode::ClientUpdateForbidden,
            ));
        }
        let (mut registration, mut response) =
            self.prepare_registration(request.metadata, issuer).await?;
        registration.client.oid = client_oid;
        registration.client.created_at = existing.client().created_at;
        registration.client.updated_at = Some(Utc::now());
        let require_par = registration
            .metadata
            .settings
            .require_pushed_authorization_requests;
        registration.metadata.settings = existing.metadata().settings.clone();
        registration
            .metadata
            .settings
            .require_pushed_authorization_requests = require_par;
        registration.registration_access_token = registration_access_token.to_owned();
        self.repo
            .update(
                registration,
                registration_access_token,
                request.client_secret,
            )
            .await
            .map_err(|error| match error {
                OpenIdConnectClientRepositoryError::InvalidMetadataValue { .. } => {
                    AppError::from_code(RegistrationErrorCode::InvalidClientMetadata)
                }
                OpenIdConnectClientRepositoryError::ClientNotFound => {
                    AppError::from_code(RegistrationErrorCode::InvalidRegistrationAccessToken)
                }
                _ => AppError::from_code(RegistrationErrorCode::ClientUpdateFailed)
                    .with_source(error),
            })?;
        response.client_id = client_oid.to_string();
        response.registration_client_uri = Some(registration_client_uri(issuer, client_oid)?);
        response.registration_access_token = Some(registration_access_token.to_owned());
        self.record_client_change("client.updated", client_oid, "success");
        Ok(response)
    }

    pub async fn read(
        &self,
        client_id: &str,
        registration_access_token: &str,
        issuer: &Url,
    ) -> Result<DynamicClientRegistrationResponse, AppError> {
        if !self.enabled() {
            return Err(AppError::from_code(
                RegistrationErrorCode::DynamicRegistrationDisabled,
            ));
        }

        let client_oid = Uuid::parse_str(client_id).map_err(|_| {
            AppError::from_code(RegistrationErrorCode::InvalidRegistrationAccessToken)
        })?;
        let client = self
            .repo
            .find_by_registration_access_token(client_oid, registration_access_token)
            .await
            .map_err(AppError::map_source(
                RegistrationErrorCode::ClientLookupFailed,
            ))?
            .ok_or_else(|| {
                AppError::from_code(RegistrationErrorCode::InvalidRegistrationAccessToken)
            })?;

        response_from_client(&client, Some(registration_access_token.to_owned()), issuer)
    }

    #[tracing::instrument(skip_all, name = "client.delete")]
    pub async fn delete(
        &self,
        client_id: &str,
        registration_access_token: &str,
    ) -> Result<(), AppError> {
        if !self.enabled() {
            return Err(AppError::from_code(
                RegistrationErrorCode::DynamicRegistrationDisabled,
            ));
        }

        let client_oid = Uuid::parse_str(client_id).map_err(|_| {
            AppError::from_code(RegistrationErrorCode::InvalidRegistrationAccessToken)
        })?;
        let client = self
            .repo
            .find_by_registration_access_token(client_oid, registration_access_token)
            .await
            .map_err(AppError::map_source(
                RegistrationErrorCode::ClientLookupFailed,
            ))?
            .ok_or_else(|| {
                AppError::from_code(RegistrationErrorCode::InvalidRegistrationAccessToken)
            })?;

        if client.client().built_in {
            return Err(AppError::from_code(
                RegistrationErrorCode::BuiltInClientCannotBeDeleted,
            ));
        }

        let client_oid = client.client().oid;
        self.repo
            .delete_by_oid(client_oid)
            .await
            .map_err(AppError::map_source(
                RegistrationErrorCode::ClientDeleteFailed,
            ))?;
        self.record_client_change("client.deleted", client_oid, "success");

        Ok(())
    }
}
