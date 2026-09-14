//! Device authorization endpoint use case (RFC 8628 §3.1, §3.2).

use std::sync::Arc;

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::{DateTime, Utc};
use rand::RngExt;
use url::Url;
use uuid::Uuid;

use crate::{
    application::{
        error::{AppError, codes::device::DeviceAuthorizationErrorCode},
        setting::runtime::SettingProvider,
    },
    domain::{
        client_authorization::{
            ClientAuthorizationData, DeviceAuthorizationApproval, DeviceAuthorizationRepository,
            DeviceAuthorizationRepositoryError, DeviceAuthorizationRequestData,
            DeviceRequestStatus, USER_CODE_LENGTH, device_code_digest, format_user_code,
            normalize_user_code,
        },
        openid_connect::{GrantType, OpenIdConnectClient, OpenIdConnectClientRepository, ScopeSet},
        setting::{DeviceAuthorizationSetting, LoginDomainSetting},
    },
    observability::{BusinessEvent, EventSink, EventValue},
    openid_connect::client_authentication::ClientAuthenticator,
    openid_connect::provider::OpenIdProviderService,
    openid_connect::token::resolve_client_id,
};

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
    pub client_id: Option<String>,
    pub client_secret: Option<String>,
    pub client_assertion_type: Option<identity_domain::openid_connect::ClientAssertionType>,
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

/// What the verification UI shows for one user code.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DeviceVerificationStatus {
    Pending,
    Approved,
    Denied,
    Expired,
    Consumed,
}

/// The authenticated browser that is answering a device request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceVerificationUser {
    pub user_oid: Uuid,
    pub auth_time: Option<i64>,
    pub acr: Option<String>,
    pub amr: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct DeviceVerificationDescription {
    /// Grouped display form of the code the user entered.
    pub user_code: String,
    pub status: DeviceVerificationStatus,
    pub client_name: String,
    pub client_uri: Option<String>,
    pub logo_uri: Option<String>,
    pub scopes: Vec<String>,
    /// `false` for trusted (skip_consent) clients, which are approved as soon
    /// as the user is identified; every other client needs an explicit
    /// decision for this request, even when the user consented before.
    pub consent_required: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeviceVerificationDecision {
    Approve,
    Deny,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct DeviceVerificationOutcome {
    pub user_code: String,
    pub status: DeviceVerificationStatus,
}

pub struct DeviceAuthorizationService {
    client_authentication: Arc<ClientAuthenticator>,
    client_repo: Arc<dyn OpenIdConnectClientRepository>,
    device_repo: Arc<dyn DeviceAuthorizationRepository>,
    provider_service: Arc<OpenIdProviderService>,
    login_domain: Arc<dyn SettingProvider<LoginDomainSetting>>,
    settings: Arc<dyn SettingProvider<DeviceAuthorizationSetting>>,
    events: Arc<dyn EventSink>,
}

pub struct DeviceAuthorizationServiceDependencies {
    pub client_authentication: Arc<ClientAuthenticator>,
    pub client_repo: Arc<dyn OpenIdConnectClientRepository>,
    pub device_repo: Arc<dyn DeviceAuthorizationRepository>,
    pub provider_service: Arc<OpenIdProviderService>,
    pub login_domain: Arc<dyn SettingProvider<LoginDomainSetting>>,
    pub settings: Arc<dyn SettingProvider<DeviceAuthorizationSetting>>,
}

impl DeviceAuthorizationService {
    #[must_use]
    pub fn new(deps: DeviceAuthorizationServiceDependencies) -> Self {
        Self {
            client_authentication: deps.client_authentication,
            client_repo: deps.client_repo,
            device_repo: deps.device_repo,
            provider_service: deps.provider_service,
            login_domain: deps.login_domain,
            settings: deps.settings,
            events: Arc::new(crate::observability::NoopEventSink),
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
        let settings = self.settings.current_value();
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
                params.client_assertion_type,
                params.client_assertion.as_deref(),
            )
            .await?;

        self.check_client_grant(&client)?;
        let scope = self.resolve_scope(&client, params.scope.as_deref())?;
        let issuer = self.provider_service.issuer()?;

        let device_code = generate_device_code();
        let now = Utc::now();
        let expires_at = now + chrono::Duration::seconds(settings.request_ttl_seconds);
        let request = self
            .create_request(
                &client,
                &scope,
                &device_code,
                settings.polling_interval_seconds,
                expires_at,
            )
            .await?;

        let user_code_display = request.user_code_display.clone();
        let verification_uri = self.verification_uri(&issuer)?;
        let verification_uri_complete =
            verification_uri_complete(&verification_uri, &user_code_display);

        self.events.emit(
            BusinessEvent::audit("device_authorization.requested")
                .outcome("success")
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
    fn verification_uri(&self, issuer: &Url) -> Result<Url, AppError> {
        let login_domain = self.login_domain.current_value();

        match login_domain
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
        {
            Some(base) => device_page(base),
            None => verification_uri(issuer),
        }
    }

    /// Housekeeping: drops expired device requests, never their authorization relations.
    ///
    /// Returns the number of removed request rows.
    #[tracing::instrument(skip_all, name = "device_authorization.cleanup")]
    pub async fn maintain(&self) -> Result<u64, AppError> {
        let now = Utc::now();
        let removed = self
            .device_repo
            .delete_expired_device_requests(now)
            .await
            .map_err(|error| {
                AppError::from_code(DeviceAuthorizationErrorCode::StoreRequestFailed)
                    .with_source(error)
            })?;
        Ok(removed)
    }

    /// Resolves what the verification UI must show for a user code.
    ///
    /// Read-only by design: a GET carrying the browser session cookie must not
    /// change authorization state, otherwise a link opened on behalf of the
    /// user could approve a request without a CSRF protected action. Trusted
    /// (`skip_consent`) clients still skip the consent *decision* — the UI
    /// approves them through [`Self::decide_verification`] without asking the
    /// user, and that write goes through the CSRF protected POST. Every client
    /// is approved per request, even when the user consented to it before
    /// (RFC 8628 §3.3).
    #[tracing::instrument(skip_all, name = "device_authorization.verify")]
    pub async fn describe_verification(
        &self,
        user_code: &str,
    ) -> Result<DeviceVerificationDescription, AppError> {
        let record = self.resolve_verification(user_code).await?;
        let data = request_data(&record)?;
        let client = self.load_client(record.client_oid).await?;
        let status = verification_status(&record, Utc::now());

        Ok(description(&client, &data, status))
    }

    /// Records the user's decision on a device request.
    #[tracing::instrument(skip_all, name = "device_authorization.decide")]
    pub async fn decide_verification(
        &self,
        user_code: &str,
        user: &DeviceVerificationUser,
        decision: DeviceVerificationDecision,
    ) -> Result<DeviceVerificationOutcome, AppError> {
        let record = self.resolve_verification(user_code).await?;
        let data = request_data(&record)?;
        self.record_decision(&record, &data, user, decision).await?;

        Ok(DeviceVerificationOutcome {
            user_code: data.user_code_display.clone(),
            status: match decision {
                DeviceVerificationDecision::Approve => DeviceVerificationStatus::Approved,
                DeviceVerificationDecision::Deny => DeviceVerificationStatus::Denied,
            },
        })
    }

    /// Resolves the active request behind a user code.
    async fn resolve_verification(
        &self,
        user_code: &str,
    ) -> Result<identity_domain::client_authorization::ClientAuthorization, AppError> {
        let normalized = normalize_user_code(user_code);
        if normalized.len() != USER_CODE_LENGTH {
            return Err(AppError::from_code(
                DeviceAuthorizationErrorCode::UserCodeNotFound,
            ));
        }

        self.device_repo
            .find_active_device_request_by_user_code(&normalized)
            .await
            .map_err(|error| {
                AppError::from_code(DeviceAuthorizationErrorCode::LoadRequestFailed)
                    .with_source(error)
            })?
            .ok_or_else(|| AppError::from_code(DeviceAuthorizationErrorCode::UserCodeNotFound))
    }

    async fn record_decision(
        &self,
        record: &identity_domain::client_authorization::ClientAuthorization,
        data: &DeviceAuthorizationRequestData,
        user: &DeviceVerificationUser,
        decision: DeviceVerificationDecision,
    ) -> Result<(), AppError> {
        if record.expires_at <= Utc::now() {
            return Err(AppError::from_code(
                DeviceAuthorizationErrorCode::RequestExpired,
            ));
        }
        if !data.is_pending() {
            return Err(AppError::from_code(
                DeviceAuthorizationErrorCode::RequestAlreadyDecided,
            ));
        }

        let now = Utc::now();
        let applied = match decision {
            DeviceVerificationDecision::Approve => self
                .device_repo
                .approve_device_request(
                    record.oid,
                    DeviceAuthorizationApproval {
                        user_oid: user.user_oid.to_string(),
                        approved_scope: data.scope.clone(),
                        auth_time: user.auth_time,
                        acr: user.acr.clone(),
                        amr: user.amr.clone(),
                        device_authorization_oid: Uuid::new_v4(),
                    },
                    now,
                )
                .await
                .map_err(|error| {
                    AppError::from_code(DeviceAuthorizationErrorCode::StoreDecisionFailed)
                        .with_source(error)
                })?
                .is_some(),
            DeviceVerificationDecision::Deny => self
                .device_repo
                .deny_device_request(record.oid, user.user_oid, now)
                .await
                .map_err(|error| {
                    AppError::from_code(DeviceAuthorizationErrorCode::StoreDecisionFailed)
                        .with_source(error)
                })?,
        };

        if !applied {
            // Another tab, an expiry, or a concurrent decision won the race;
            // the stored decision stays authoritative.
            return Err(AppError::from_code(
                DeviceAuthorizationErrorCode::RequestAlreadyDecided,
            ));
        }

        self.events.emit(
            BusinessEvent::audit(match decision {
                DeviceVerificationDecision::Approve => "device_authorization.approved",
                DeviceVerificationDecision::Deny => "device_authorization.denied",
            })
            .outcome("success")
            .attribute(
                "client_oid",
                EventValue::Text(record.client_oid.to_string()),
            )
            .attribute("request_oid", EventValue::Text(record.oid.to_string())),
        );

        Ok(())
    }

    async fn load_client(&self, client_oid: Uuid) -> Result<OpenIdConnectClient, AppError> {
        self.client_repo
            .find_by_oid(client_oid)
            .await
            .map_err(|error| {
                AppError::from_code(DeviceAuthorizationErrorCode::ClientLookupFailed)
                    .with_source(error)
            })?
            .ok_or_else(|| AppError::from_code(DeviceAuthorizationErrorCode::ClientNotFound))
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
        let scope = ScopeSet::parse(requested).map_err(|error| {
            AppError::from_code(DeviceAuthorizationErrorCode::ScopeInvalid).with_source(error)
        })?;

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
        client: &OpenIdConnectClient,
        scope: &ScopeSet,
        device_code: &str,
        interval_seconds: i64,
        expires_at: DateTime<Utc>,
    ) -> Result<DeviceAuthorizationRequestData, AppError> {
        for _ in 0..USER_CODE_ATTEMPTS {
            let user_code = generate_user_code();
            let data = DeviceAuthorizationRequestData {
                scope: scope.to_scope_string(),
                device_code_digest: device_code_digest(device_code),
                user_code_display: format_user_code(&user_code),
                user_code,
                interval_seconds,
                slow_down_seconds: 0,
                last_polled_at: None,
                status: DeviceRequestStatus::Pending,
                approval: None,
                denied_by_user_oid: None,
                decided_at: None,
                device_authorization_oid: None,
            };

            match self
                .device_repo
                .create_device_request(client.client().oid, data.clone(), expires_at)
                .await
            {
                Ok(_) => return Ok(data),
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

fn request_data(
    record: &identity_domain::client_authorization::ClientAuthorization,
) -> Result<DeviceAuthorizationRequestData, AppError> {
    match &record.data {
        ClientAuthorizationData::DeviceAuthorizationRequest(data) => Ok(data.clone()),
        _ => Err(AppError::from_code(
            DeviceAuthorizationErrorCode::DeserializeRequestFailed,
        )),
    }
}

fn verification_status(
    record: &identity_domain::client_authorization::ClientAuthorization,
    now: DateTime<Utc>,
) -> DeviceVerificationStatus {
    if record.expires_at <= now {
        return DeviceVerificationStatus::Expired;
    }

    match record.data {
        ClientAuthorizationData::DeviceAuthorizationRequest(ref data) => match data.status {
            DeviceRequestStatus::Pending => DeviceVerificationStatus::Pending,
            DeviceRequestStatus::Approved => DeviceVerificationStatus::Approved,
            DeviceRequestStatus::Denied => DeviceVerificationStatus::Denied,
            DeviceRequestStatus::Consumed => DeviceVerificationStatus::Consumed,
        },
        _ => DeviceVerificationStatus::Consumed,
    }
}

fn description(
    client: &OpenIdConnectClient,
    data: &DeviceAuthorizationRequestData,
    status: DeviceVerificationStatus,
) -> DeviceVerificationDescription {
    let scopes = ScopeSet::parse(&data.scope)
        .map(|scope| {
            scope
                .names()
                .iter()
                .map(|name| (*name).to_owned())
                .collect()
        })
        .unwrap_or_default();

    DeviceVerificationDescription {
        user_code: data.user_code_display.clone(),
        status,
        client_name: client.client().name.clone(),
        client_uri: client.metadata().client_uri.as_ref().map(Url::to_string),
        logo_uri: client.metadata().logo_uri.as_ref().map(Url::to_string),
        scopes,
        consent_required: !client.metadata().settings.skip_consent,
    }
}

/// A device code is 256 bits of randomness, encoded as an URL safe string and
/// stored only as its digest.
fn generate_device_code() -> String {
    let mut bytes = [0_u8; DEVICE_CODE_BYTES];
    rand::rng().fill(&mut bytes);

    URL_SAFE_NO_PAD.encode(bytes)
}

/// A user code is drawn from the unambiguous alphabet, so it stays typable.
fn generate_user_code() -> String {
    let alphabet = identity_domain::client_authorization::USER_CODE_ALPHABET;
    let mut rng = rand::rng();

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
    let base = Url::parse(base).map_err(|error| {
        AppError::from_code(DeviceAuthorizationErrorCode::LoginDomainInvalid).with_source(error)
    })?;

    base.join(DEVICE_VERIFICATION_PATH).map_err(|error| {
        AppError::from_code(DeviceAuthorizationErrorCode::LoginDomainInvalid).with_source(error)
    })
}

fn verification_uri(issuer: &Url) -> Result<Url, AppError> {
    let mut base = issuer.clone();
    base.set_path("");
    base.join(DEVICE_VERIFICATION_PATH).map_err(|error| {
        AppError::from_code(DeviceAuthorizationErrorCode::IssuerInvalid).with_source(error)
    })
}

fn verification_uri_complete(verification_uri: &Url, user_code: &str) -> Url {
    let mut url = verification_uri.clone();
    url.query_pairs_mut().append_pair("user_code", user_code);

    url
}

#[cfg(test)]
mod tests;
