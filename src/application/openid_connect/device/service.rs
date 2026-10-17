//! Device authorization request issuance (RFC 8628 §3.1, §3.2).

use crate::{
    error::{
        AppError,
        code::AppErrorCode,
        codes::{common::CommonErrorCode, device::DeviceAuthorizationErrorCode},
    },
    observability::{BusinessEvent, EventSink, EventValue, NoopEventSink},
    openid_connect::{
        client_authentication::ClientAuthenticator, provider::OpenIdProviderService,
        token::resolve_client_id,
    },
    setting::{AppSettings, OpenIdConnectSettings, SettingsSource},
};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::{DateTime, Duration, Utc};
use identity_domain::{
    client_authorization::{
        ClientAuthenticationMode, DeviceAuthorizationRepository,
        DeviceAuthorizationRepositoryError, DeviceAuthorizationRequestData, DeviceRequestStatus,
        USER_CODE_ALPHABET, USER_CODE_LENGTH, device_code_digest, format_user_code,
    },
    openid_connect::{
        ClientAssertionType, GrantType, OpenIdConnectClient, OpenIdConnectClientRepository,
        ScopeSet,
    },
};
use rand::{RngExt, rng as random_rng};
use std::sync::Arc;
use url::Url;
use uuid::Uuid;

mod login;
mod verification;
pub use verification::{
    DeviceVerificationDecision, DeviceVerificationDescription, DeviceVerificationOutcome,
    DeviceVerificationStatus, DeviceVerificationUser,
};

struct DeviceRequestInput<'a> {
    client: &'a OpenIdConnectClient,
    scope: &'a ScopeSet,
    resources: &'a [String],
    device_code: &'a str,
    interval_seconds: i64,
    expires_at: DateTime<Utc>,
    client_authentication_mode: ClientAuthenticationMode,
}

/// Bytes of entropy behind a device code (RFC 8628 §6.1 recommends at least
/// 128 bits; 256 are cheap and remove any doubt about guessability).
const DEVICE_CODE_BYTES: usize = 32;

/// Collisions of the 20^8 user code space are rare, so a handful of retries is
/// enough to place a request even when the space is busy.
const USER_CODE_ATTEMPTS: usize = 5;

/// Path of the device verification page, relative to the installed
/// application URL: the application that serves `/login` and `/consent` also
/// serves `/device`.
pub const DEVICE_VERIFICATION_PATH: &str = "device";

#[derive(Debug, Clone, Default)]
pub struct DeviceAuthorizationParams {
    pub resources: Vec<String>,
    pub client_id: Option<String>,
    pub client_secret: Option<String>,
    pub client_secret_basic: bool,
    pub client_assertion_type: Option<ClientAssertionType>,
    pub client_assertion: Option<String>,
    pub scope: Option<String>,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct DeviceAuthorizationResponse {
    pub device_code: String,
    pub user_code: String,
    pub verification_uri: String,
    pub verification_uri_complete: String,
    pub expires_in: i64,
    pub interval: i64,
}

pub struct DeviceAuthorizationService {
    client_authentication: Arc<ClientAuthenticator>,
    client_repo: Arc<dyn OpenIdConnectClientRepository>,
    device_repo: Arc<dyn DeviceAuthorizationRepository>,
    provider_service: Arc<OpenIdProviderService>,
    settings: Arc<dyn SettingsSource>,
    events: Arc<dyn EventSink>,
}

pub struct DeviceAuthorizationServiceDependencies {
    pub client_authentication: Arc<ClientAuthenticator>,
    pub client_repo: Arc<dyn OpenIdConnectClientRepository>,
    pub device_repo: Arc<dyn DeviceAuthorizationRepository>,
    pub provider_service: Arc<OpenIdProviderService>,
    pub settings: Arc<dyn SettingsSource>,
}

impl DeviceAuthorizationService {
    #[must_use]
    pub fn new(deps: DeviceAuthorizationServiceDependencies) -> Self {
        Self {
            client_authentication: deps.client_authentication,
            client_repo: deps.client_repo,
            device_repo: deps.device_repo,
            provider_service: deps.provider_service,
            settings: deps.settings,
            events: Arc::new(NoopEventSink),
        }
    }

    /// Attach the key event and audit sink.
    #[must_use]
    pub fn with_events(mut self, events: Arc<dyn EventSink>) -> Self {
        self.events = events;
        self
    }

    #[tracing::instrument(skip_all, name = "device_authorization.request")]
    pub async fn authorize(
        &self,
        params: DeviceAuthorizationParams,
    ) -> Result<DeviceAuthorizationResponse, AppError> {
        let snapshot = self.settings.snapshot();
        let settings = snapshot
            .section::<OpenIdConnectSettings>()
            .device_authorization;
        // A JWT authenticated client may identify itself through the
        // assertion alone (RFC 7523 §2.2). The unverified subject only locates
        // the client; the assertion is fully verified before it authenticates
        // anything (RFC 8628 §3.1 requires client_id only when the request
        // performs no client authentication).
        let client_id = resolve_client_id(
            params.client_id.filter(|value| !value.trim().is_empty()),
            params.client_assertion_type,
            params.client_assertion.as_deref(),
        )?;

        let client = self
            .client_authentication
            .authenticate_client_request(
                &client_id,
                params.client_secret.as_deref(),
                params.client_secret_basic,
                params.client_assertion_type,
                params.client_assertion.as_deref(),
            )
            .await?;

        let client_authentication_mode = ClientAuthenticationMode::from_credentials(
            params.client_secret.is_some() || params.client_assertion.is_some(),
        );

        self.check_client_grant(&client)?;
        self.provider_service
            .validate_scope_names(params.scope.as_deref().unwrap_or("openid"))
            .await
            .map_err(|error| {
                if error.code() == CommonErrorCode::InvalidScope.code() {
                    AppError::from_code(DeviceAuthorizationErrorCode::ScopeInvalid)
                        .with_source(error)
                } else {
                    error
                }
            })?;
        let scope = self.resolve_scope(&client, params.scope.as_deref())?;
        let resources = if params.resources.is_empty() {
            let selection = self
                .provider_service
                .select_resources(&[], &[], &scope.to_scope_string())
                .await?;
            if selection.scope != scope.to_scope_string() {
                return Err(AppError::from_code(CommonErrorCode::InvalidTarget));
            }
            selection.resources
        } else {
            // Device authorization also records the full grant, before token target selection.
            self.provider_service
                .validate_authorization_resources(&params.resources, &scope)
                .await?
        };
        let issuer = self.provider_service.issuer()?;

        let device_code = generate_device_code();
        let now = Utc::now();
        let expires_at = now + Duration::seconds(settings.request_ttl_seconds);
        let (request_oid, request) = self
            .create_request(DeviceRequestInput {
                client: &client,
                scope: &scope,
                resources: &resources,
                device_code: &device_code,
                interval_seconds: settings.polling_interval_seconds,
                expires_at,
                client_authentication_mode,
            })
            .await?;

        let user_code_display = request.user_code_display.clone();
        let login_domain = snapshot.section::<AppSettings>().login_domain;
        let verification_uri = self.verification_uri(&issuer, login_domain.as_deref())?;
        let verification_uri_complete =
            verification_uri_complete(&verification_uri, &user_code_display);

        self.events.emit(
            BusinessEvent::audit("device_authorization.requested")
                .outcome("success")
                .attribute("request_oid", EventValue::Text(request_oid.to_string()))
                .attribute(
                    "client_oid",
                    EventValue::Text(client.client().oid.to_string()),
                )
                .attribute("scope", EventValue::Text(scope.to_scope_string())),
        );

        Ok(DeviceAuthorizationResponse {
            device_code,
            user_code: user_code_display,
            verification_uri: verification_uri.to_string(),
            verification_uri_complete: verification_uri_complete.to_string(),
            expires_in: settings.request_ttl_seconds,
            interval: settings.polling_interval_seconds,
        })
    }

    /// Page the user opens to enter the code (`RFC 8628` §3.2).
    ///
    /// The login application renders it, so the link is built from the login
    /// domain recorded during installation (`app.login_domain`) — the identity
    /// service and the login application may well live on different hosts.
    /// Installations without that record fall back to the issuer.
    fn verification_uri(&self, issuer: &Url, login_domain: Option<&str>) -> Result<Url, AppError> {
        match login_domain
            .map(str::trim)
            .filter(|value| !value.is_empty())
        {
            Some(base) => device_page(base),
            None => verification_uri(issuer),
        }
    }

    fn check_client_grant(&self, client: &OpenIdConnectClient) -> Result<(), AppError> {
        if !client.allows_grant(GrantType::DeviceCode) {
            return Err(
                AppError::from_code(DeviceAuthorizationErrorCode::GrantNotAllowed)
                    .with_param("grant_type", GrantType::DeviceCode.as_str()),
            );
        }

        Ok(())
    }

    fn resolve_scope(
        &self,
        client: &OpenIdConnectClient,
        requested: Option<&str>,
    ) -> Result<ScopeSet, AppError> {
        let requested = requested.unwrap_or("openid");
        let scope = ScopeSet::parse(requested).map_err(AppError::map_source(
            DeviceAuthorizationErrorCode::ScopeInvalid,
        ))?;

        if scope
            .names()
            .iter()
            .any(|name| !client.has_assigned_scope(name))
        {
            return Err(AppError::from_code(
                DeviceAuthorizationErrorCode::ScopeNotAssignedToClient,
            )
            .with_param("scope", scope.to_scope_string()));
        }

        Ok(scope)
    }

    async fn create_request(
        &self,
        input: DeviceRequestInput<'_>,
    ) -> Result<(Uuid, DeviceAuthorizationRequestData), AppError> {
        let DeviceRequestInput {
            client,
            scope,
            resources,
            device_code,
            interval_seconds,
            expires_at,
            client_authentication_mode,
        } = input;
        for _ in 0..USER_CODE_ATTEMPTS {
            let user_code = generate_user_code();
            let data = DeviceAuthorizationRequestData {
                resources: resources.to_vec(),
                scope: scope.to_scope_string(),
                device_code_digest: device_code_digest(device_code),
                user_code_display: format_user_code(&user_code),
                user_code,
                interval_seconds,
                slow_down_seconds: 0,
                last_polled_at: None,
                claimed_login_oid: None,
                status: DeviceRequestStatus::Pending,
                approval: None,
                denied_by_user_oid: None,
                decided_at: None,
                device_authorization_oid: None,
                client_authentication_mode: Some(client_authentication_mode),
            };

            match self
                .device_repo
                .create_device_request(client.client().oid, data.clone(), expires_at)
                .await
            {
                Ok(record) => return Ok((record.oid, data)),
                Err(DeviceAuthorizationRepositoryError::UserCodeConflict) => continue,
                Err(error) => {
                    return Err(AppError::from_code(
                        DeviceAuthorizationErrorCode::StoreRequestFailed,
                    )
                    .with_source(error));
                }
            }
        }

        Err(AppError::from_code(
            DeviceAuthorizationErrorCode::UserCodeUnavailable,
        ))
    }
}

/// A device code is 256 bits of randomness, encoded as an URL safe string and
/// stored only as its digest.
fn generate_device_code() -> String {
    let mut bytes = [0_u8; DEVICE_CODE_BYTES];
    random_rng().fill(&mut bytes);

    URL_SAFE_NO_PAD.encode(bytes)
}

/// A user code is drawn from the unambiguous alphabet, so it stays typable.
fn generate_user_code() -> String {
    let alphabet = USER_CODE_ALPHABET;
    let mut rng = random_rng();

    (0..USER_CODE_LENGTH)
        .map(|_| char::from(alphabet[rng.random_range(0..alphabet.len())]))
        .collect()
}

/// Fallback for installations without an application URL: the issuer host
/// serves the same page path.
/// Joins the device page onto the login domain, e.g.
/// `https://login.example.com` -> `https://login.example.com/device`.
///
/// A malformed login domain fails the request rather than silently pointing
/// users at the wrong host.
fn device_page(base: &str) -> Result<Url, AppError> {
    let base = Url::parse(base).map_err(AppError::map_source(
        DeviceAuthorizationErrorCode::LoginDomainInvalid,
    ))?;

    base.join(DEVICE_VERIFICATION_PATH)
        .map_err(AppError::map_source(
            DeviceAuthorizationErrorCode::LoginDomainInvalid,
        ))
}

fn verification_uri(issuer: &Url) -> Result<Url, AppError> {
    let mut base = issuer.clone();
    base.set_path("");
    base.join(DEVICE_VERIFICATION_PATH)
        .map_err(AppError::map_source(
            DeviceAuthorizationErrorCode::IssuerInvalid,
        ))
}

fn verification_uri_complete(verification_uri: &Url, user_code: &str) -> Url {
    let mut url = verification_uri.clone();
    url.query_pairs_mut().append_pair("user_code", user_code);

    url
}
