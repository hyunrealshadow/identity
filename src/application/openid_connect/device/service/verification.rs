//! User-code lookup, verification display, and per-request consent decisions.

use super::DeviceAuthorizationService;
use crate::{
    error::{AppError, codes::device::DeviceAuthorizationErrorCode},
    observability::{BusinessEvent, EventValue},
};
use chrono::{DateTime, Utc};
use identity_domain::{
    client_authorization::{
        ClientAuthorization, ClientAuthorizationData, DeviceAuthorizationApproval,
        DeviceAuthorizationRequestData, DeviceRequestStatus, USER_CODE_LENGTH, normalize_user_code,
    },
    openid_connect::{OpenIdConnectClient, ScopeSet},
};
use url::Url;
use uuid::Uuid;

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

impl DeviceAuthorizationService {
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
    pub(super) async fn resolve_verification(
        &self,
        user_code: &str,
    ) -> Result<ClientAuthorization, AppError> {
        let normalized = normalize_user_code(user_code);
        if normalized.len() != USER_CODE_LENGTH {
            return Err(AppError::from_code(
                DeviceAuthorizationErrorCode::UserCodeNotFound,
            ));
        }

        let record = self
            .device_repo
            .find_active_device_request_by_user_code(&normalized)
            .await
            .map_err(AppError::map_source(
                DeviceAuthorizationErrorCode::LoadRequestFailed,
            ))?
            .ok_or_else(|| AppError::from_code(DeviceAuthorizationErrorCode::UserCodeNotFound))?;
        if request_data(&record)?.claimed_login_oid.is_some() {
            return Err(AppError::from_code(
                DeviceAuthorizationErrorCode::UserCodeNotFound,
            ));
        }
        Ok(record)
    }

    pub(super) async fn record_decision(
        &self,
        record: &ClientAuthorization,
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
        let device_authorization_oid = Uuid::new_v4();
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
                        device_authorization_oid,
                    },
                    now,
                )
                .await
                .map_err(AppError::map_source(
                    DeviceAuthorizationErrorCode::StoreDecisionFailed,
                ))?
                .is_some(),
            DeviceVerificationDecision::Deny => self
                .device_repo
                .deny_device_request(record.oid, user.user_oid, now)
                .await
                .map_err(AppError::map_source(
                    DeviceAuthorizationErrorCode::StoreDecisionFailed,
                ))?,
        };

        if !applied {
            // Another tab, an expiry, or a concurrent decision won the race;
            // the stored decision stays authoritative.
            return Err(AppError::from_code(
                DeviceAuthorizationErrorCode::RequestAlreadyDecided,
            ));
        }

        let mut event = BusinessEvent::audit(match decision {
            DeviceVerificationDecision::Approve => "device_authorization.approved",
            DeviceVerificationDecision::Deny => "device_authorization.denied",
        })
        .outcome("success")
        .attribute(
            "client_oid",
            EventValue::Text(record.client_oid.to_string()),
        )
        .attribute("request_oid", EventValue::Text(record.oid.to_string()));
        if decision == DeviceVerificationDecision::Approve {
            event = event.attribute(
                "device_authorization_oid",
                EventValue::Text(device_authorization_oid.to_string()),
            );
        }
        self.events.emit(event);

        Ok(())
    }

    pub(super) async fn load_client(
        &self,
        client_oid: Uuid,
    ) -> Result<OpenIdConnectClient, AppError> {
        self.client_repo
            .find_by_oid(client_oid)
            .await
            .map_err(AppError::map_source(
                DeviceAuthorizationErrorCode::ClientLookupFailed,
            ))?
            .ok_or_else(|| AppError::from_code(DeviceAuthorizationErrorCode::ClientNotFound))
    }
}

pub(super) fn request_data(
    record: &ClientAuthorization,
) -> Result<DeviceAuthorizationRequestData, AppError> {
    match &record.data {
        ClientAuthorizationData::DeviceAuthorizationRequest(data) => Ok(data.clone()),
        _ => Err(AppError::from_code(
            DeviceAuthorizationErrorCode::DeserializeRequestFailed,
        )),
    }
}

pub(super) fn verification_status(
    record: &ClientAuthorization,
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

pub(super) fn description(
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
