use std::{sync::Arc, time::SystemTime};

use identity_domain::{auth::SessionOid, openid_connect::identifier};
use josekit::{
    jws::{
        ES256, ES256K, ES384, ES512, EdDSA, JwsHeader, JwsSigner, PS256, PS384, PS512, RS256,
        RS384, RS512,
    },
    jwt,
    jwt::JwtPayload,
};
use serde_json::json;
use url::Url;
use uuid::Uuid;

use crate::{
    application::{
        error::{
            AppError,
            codes::{common, openid_connect},
        },
        openid_connect::{jose::asymmetric_verifier_from_pem, provider::OpenIdProviderService},
    },
    domain::{
        auth::repository::SessionRepository,
        key::{JwaSigningAlgorithm, KeyData, KeyJwkRepository, repository::KeyRepository},
        openid_connect::{OpenIdConnectClient, OpenIdConnectClientRepository},
    },
    observability::{BusinessEvent, EventSink, EventValue, NoopEventSink, error_outcome},
    openid_connect::provider::SigningAlgorithmDetector,
};

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RpInitiatedLogoutRequest {
    pub id_token_hint: Option<String>,
    pub logout_hint: Option<String>,
    pub client_id: Option<String>,
    pub post_logout_redirect_uri: Option<String>,
    pub state: Option<String>,
    pub ui_locales: Option<String>,
    pub session_oid: Option<SessionOid>,
    pub protected_session_id: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FrontChannelLogoutNotification {
    pub client_id: Uuid,
    pub logout_uri: Url,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BackChannelLogoutNotification {
    pub client_id: Uuid,
    pub logout_uri: Url,
    pub logout_token: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BackChannelLogoutDelivery {
    Delivered,
    Rejected,
    TransportFailed,
}

#[async_trait::async_trait]
pub trait BackChannelLogoutSender: Send + Sync {
    async fn send(&self, notification: &BackChannelLogoutNotification)
    -> BackChannelLogoutDelivery;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LogoutOutcome {
    Redirect {
        redirect_uri: Url,
    },
    FrontChannel {
        notifications: Vec<FrontChannelLogoutNotification>,
        post_logout_redirect_uri: Option<Url>,
    },
    LoggedOut,
}

/// The response to an RP-initiated logout and the client that verifiably
/// started it: the audience of a verified `id_token_hint`, or the client whose
/// registered post-logout redirect URI was accepted.
#[derive(Debug)]
pub struct RpInitiatedLogout {
    pub outcome: LogoutOutcome,
    pub client_oid: Option<Uuid>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct IdTokenHintClaims {
    audience: Vec<String>,
    authorized_party: Option<String>,
    /// Protected browser session id (`sid`) the token was issued for.
    session_id: Option<String>,
}

pub struct LogoutService {
    client_repo: Arc<dyn OpenIdConnectClientRepository>,
    provider_service: Arc<OpenIdProviderService>,
    key_repo: Arc<dyn KeyRepository>,
    key_jwk_repo: Arc<dyn KeyJwkRepository>,
    signing_algorithm_detector: Arc<dyn SigningAlgorithmDetector>,
    pub(super) backchannel_sender: Arc<dyn BackChannelLogoutSender>,
    session_repo: Option<Arc<dyn SessionRepository>>,
    pub(super) events: Arc<dyn EventSink>,
}

pub struct LogoutServiceDependencies {
    pub client_repo: Arc<dyn OpenIdConnectClientRepository>,
    pub provider_service: Arc<OpenIdProviderService>,
    pub key_repo: Arc<dyn KeyRepository>,
    pub key_jwk_repo: Arc<dyn KeyJwkRepository>,
    pub signing_algorithm_detector: Arc<dyn SigningAlgorithmDetector>,
    pub backchannel_sender: Arc<dyn BackChannelLogoutSender>,
}

async fn deliver_backchannel_logout(
    sender: &dyn BackChannelLogoutSender,
    events: &dyn EventSink,
    notification: &BackChannelLogoutNotification,
) {
    let delivery = sender.send(notification).await;
    let (outcome, reason) = match delivery {
        BackChannelLogoutDelivery::Delivered => ("success", None),
        BackChannelLogoutDelivery::Rejected => ("failure", Some("non_success_status")),
        BackChannelLogoutDelivery::TransportFailed => ("failure", Some("transport_error")),
    };

    let mut event = BusinessEvent::audit("logout.backchannel.result")
        .outcome(outcome)
        .attribute(
            "client_oid",
            EventValue::Text(notification.client_id.to_string()),
        );
    if let Some(reason) = reason {
        event = event.reason(reason);
    }
    events.emit(event);
}

impl LogoutService {
    pub fn new(deps: LogoutServiceDependencies) -> Self {
        Self {
            client_repo: deps.client_repo,
            provider_service: deps.provider_service,
            key_repo: deps.key_repo,
            key_jwk_repo: deps.key_jwk_repo,
            signing_algorithm_detector: deps.signing_algorithm_detector,
            backchannel_sender: deps.backchannel_sender,
            session_repo: None,
            events: Arc::new(NoopEventSink),
        }
    }

    /// Attach the key event and audit sink.
    #[must_use]
    pub fn with_events(mut self, events: Arc<dyn EventSink>) -> Self {
        self.events = events;
        self
    }

    #[must_use]
    pub fn with_session_repo(mut self, session_repo: Arc<dyn SessionRepository>) -> Self {
        self.session_repo = Some(session_repo);
        self
    }

    #[tracing::instrument(skip_all, name = "logout.rp_initiated")]
    /// The protected browser session id (`sid`) a verified `id_token_hint` was
    /// issued for. A browser may remember several accounts; logout ends only
    /// the session this hint names, never another remembered account.
    pub async fn id_token_hint_session_id(&self, raw: &str) -> Result<Option<String>, AppError> {
        Ok(self.verify_id_token_hint(raw).await?.session_id)
    }

    pub async fn rp_initiated_logout(
        &self,
        request: RpInitiatedLogoutRequest,
    ) -> Result<RpInitiatedLogout, AppError> {
        let session_oid = request.session_oid;
        let result = self.rp_initiated_logout_inner(request).await;
        let mut event = BusinessEvent::audit("logout.local.result");
        match &result {
            Ok(RpInitiatedLogout { outcome, .. }) => {
                event = event.outcome("success").attribute(
                    "logout_kind",
                    EventValue::Text(
                        match outcome {
                            LogoutOutcome::LoggedOut => "logged_out",
                            LogoutOutcome::Redirect { .. } => "redirect",
                            LogoutOutcome::FrontChannel { .. } => "frontchannel",
                        }
                        .to_owned(),
                    ),
                );
            }
            Err(error) => {
                let (outcome, reason) = error_outcome(error);
                event = event
                    .outcome(outcome)
                    .reason(reason)
                    .attribute("error_code", EventValue::Integer(i64::from(error.code())));
            }
        }
        if let Some(session_oid) = session_oid {
            event = event.attribute(
                "session_oid",
                EventValue::Pseudonymized {
                    purpose: "session_oid",
                    value: session_oid.0.to_string(),
                },
            );
        }
        self.events.emit(event);
        result
    }

    async fn rp_initiated_logout_inner(
        &self,
        request: RpInitiatedLogoutRequest,
    ) -> Result<RpInitiatedLogout, AppError> {
        let id_token_hint = match request.id_token_hint.as_deref() {
            Some(raw) => Some(self.verify_id_token_hint(raw).await?),
            None => None,
        };
        // A verified hint names its client; an unverified `client_id` does not.
        let hinted_client = audience_client_id(id_token_hint.as_ref())
            .and_then(|client_id| identifier::parse_client_id(&client_id).ok());

        let mut post_logout_redirect_uri = None;
        let client_oid = if let Some(raw_redirect_uri) = request.post_logout_redirect_uri.as_deref()
        {
            let redirect_uri = Url::parse(raw_redirect_uri)
                .map_err(openid_connect::error::PostLogoutRedirectUriInvalid::map_source())?;

            let client_id = request
                .client_id
                .as_deref()
                .map(str::to_owned)
                .or_else(|| audience_client_id(id_token_hint.as_ref()))
                .ok_or_else(|| openid_connect::error::IdTokenHintRequired.into_error())?;
            let client_oid = identifier::parse_client_id(&client_id)
                .map_err(openid_connect::error::LogoutClientInvalid::map_source())?;

            if id_token_hint.as_ref().is_some_and(|claims| {
                !claims
                    .audience
                    .iter()
                    .any(|audience| audience == &client_id)
                    || claims
                        .authorized_party
                        .as_ref()
                        .is_some_and(|authorized_party| authorized_party != &client_id)
            }) {
                return Err(openid_connect::error::IdTokenHintInvalid.into_error());
            }

            let client = self
                .client_repo
                .find_by_oid(client_oid)
                .await
                .map_err(openid_connect::error::LogoutClientLookupFailed::map_source())?
                .ok_or_else(|| openid_connect::error::LogoutClientNotFound.into_error())?;

            validate_registered_post_logout_redirect_uri(&client, &redirect_uri)?;

            let mut redirect_uri = redirect_uri;
            if let Some(state) = request.state.as_deref() {
                redirect_uri.query_pairs_mut().append_pair("state", state);
            }
            post_logout_redirect_uri = Some(redirect_uri);
            Some(client_oid)
        } else {
            hinted_client
        };

        let backchannel_notifications = self
            .backchannel_logout_notifications(
                request.session_oid,
                request.protected_session_id.as_deref(),
            )
            .await?;
        let frontchannel_notifications = self
            .frontchannel_logout_notifications(
                request.session_oid,
                request.protected_session_id.as_deref(),
            )
            .await?;

        if let (Some(session_oid), Some(session_repo)) = (request.session_oid, &self.session_repo)
            && let Some(session) = session_repo
                .revoke_by_oid(session_oid, chrono::Utc::now(), client_oid)
                .await
                .map_err(AppError::from)?
        {
            self.events.emit(
                BusinessEvent::audit("session.revoked")
                    .outcome("success")
                    .attribute(
                        "session_oid",
                        EventValue::Pseudonymized {
                            purpose: "session_oid",
                            value: session.oid.0.to_string(),
                        },
                    )
                    .attribute(
                        "user_oid",
                        EventValue::Pseudonymized {
                            purpose: "user_oid",
                            value: session.user_oid.to_string(),
                        },
                    ),
            );
        }

        self.deliver_backchannel_notifications(backchannel_notifications)
            .await?;

        let outcome = if !frontchannel_notifications.is_empty() {
            LogoutOutcome::FrontChannel {
                notifications: frontchannel_notifications,
                post_logout_redirect_uri,
            }
        } else {
            match post_logout_redirect_uri {
                Some(redirect_uri) => LogoutOutcome::Redirect { redirect_uri },
                None => LogoutOutcome::LoggedOut,
            }
        };

        Ok(RpInitiatedLogout {
            outcome,
            client_oid,
        })
    }

    async fn frontchannel_logout_notifications(
        &self,
        session_oid: Option<SessionOid>,
        protected_session_id: Option<&str>,
    ) -> Result<Vec<FrontChannelLogoutNotification>, AppError> {
        let Some(session_oid) = session_oid else {
            return Ok(Vec::new());
        };

        let issuer = self.provider_service.issuer()?;
        let clients = self
            .client_repo
            .find_frontchannel_logout_clients_by_session_oid(session_oid)
            .await
            .map_err(openid_connect::error::LogoutClientLookupFailed::map_source())?;

        Ok(clients
            .into_iter()
            .filter_map(|client| {
                let mut logout_uri = client.metadata().frontchannel_logout_uri.clone()?;
                if client.metadata().frontchannel_logout_session_required == Some(true)
                    && protected_session_id.is_none()
                {
                    return None;
                }
                if let Some(sid) = protected_session_id {
                    logout_uri
                        .query_pairs_mut()
                        .append_pair("iss", issuer.as_str())
                        .append_pair("sid", sid);
                }
                Some(FrontChannelLogoutNotification {
                    client_id: client.client().oid,
                    logout_uri,
                })
            })
            .collect())
    }

    pub(super) async fn backchannel_logout_notifications(
        &self,
        session_oid: Option<SessionOid>,
        protected_session_id: Option<&str>,
    ) -> Result<Vec<BackChannelLogoutNotification>, AppError> {
        let Some(session_oid) = session_oid else {
            return Ok(Vec::new());
        };

        let user_oid = if protected_session_id.is_none() {
            let Some(session_repo) = &self.session_repo else {
                return Ok(Vec::new());
            };
            session_repo
                .find_by_oid(session_oid)
                .await
                .map_err(AppError::internal)?
                .map(|session| session.user_oid)
        } else {
            None
        };
        if protected_session_id.is_none() && user_oid.is_none() {
            return Ok(Vec::new());
        }

        let issuer = self.provider_service.issuer()?;
        let clients = self
            .client_repo
            .find_backchannel_logout_clients_by_session_oid(session_oid)
            .await
            .map_err(openid_connect::error::LogoutClientLookupFailed::map_source())?;
        let candidates = clients
            .into_iter()
            .filter_map(|client| {
                if client.metadata().backchannel_logout_session_required == Some(true)
                    && protected_session_id.is_none()
                {
                    return None;
                }
                client
                    .metadata()
                    .backchannel_logout_uri
                    .clone()
                    .map(|logout_uri| (client, logout_uri))
            })
            .collect::<Vec<_>>();
        if candidates.is_empty() {
            return Ok(Vec::new());
        }

        let (key_id, private_key, alg) = self.load_signing_key().await?;

        candidates
            .into_iter()
            .map(|(client, logout_uri)| {
                let subject = user_oid.map(|oid| client.subject_identifier(oid, &issuer));
                let logout_token = Self::sign_logout_token(
                    &key_id,
                    &private_key,
                    alg,
                    &issuer,
                    client.client().oid,
                    protected_session_id,
                    subject.as_deref(),
                )?;
                Ok(BackChannelLogoutNotification {
                    client_id: client.client().oid,
                    logout_uri,
                    logout_token,
                })
            })
            .collect()
    }

    async fn deliver_backchannel_notifications(
        &self,
        notifications: Vec<BackChannelLogoutNotification>,
    ) -> Result<(), AppError> {
        const MAX_CONCURRENT_BACKCHANNEL_LOGOUTS: usize = 8;

        if notifications.is_empty() {
            return Ok(());
        }

        let semaphore = Arc::new(tokio::sync::Semaphore::new(
            MAX_CONCURRENT_BACKCHANNEL_LOGOUTS,
        ));
        let mut tasks = tokio::task::JoinSet::new();
        for notification in notifications {
            let permit = semaphore
                .clone()
                .acquire_owned()
                .await
                .map_err(AppError::internal)?;
            let sender = Arc::clone(&self.backchannel_sender);
            let events = Arc::clone(&self.events);
            tasks.spawn(async move {
                let _permit = permit;
                deliver_backchannel_logout(sender.as_ref(), events.as_ref(), &notification).await;
            });
        }
        while let Some(joined) = tasks.join_next().await {
            if let Err(error) = joined {
                tracing::warn!(error = %error, "back-channel logout task failed");
            }
        }

        Ok(())
    }

    /// One span and one result event per back-channel target. A failing target
    /// is reported as an observed notification result; it never claims that the
    /// remote session was actually revoked.
    #[cfg(test)]
    pub(super) async fn notify_backchannel_logout(
        &self,
        notification: &BackChannelLogoutNotification,
    ) {
        deliver_backchannel_logout(
            self.backchannel_sender.as_ref(),
            self.events.as_ref(),
            notification,
        )
        .await;
    }

    async fn load_signing_key(&self) -> Result<(String, String, JwaSigningAlgorithm), AppError> {
        let keys = self
            .key_repo
            .list_active_asymmetric()
            .await
            .map_err(AppError::internal)?;

        for key in keys {
            if let KeyData::Asymmetric(data) = &key.data {
                // A key signs only with the algorithms it publishes a binding for.
                let mut found = None;
                for alg in self.signing_algorithm_detector.detect(&key) {
                    if let Some(binding) = self
                        .key_jwk_repo
                        .find_active_by_key_oid_and_algorithm(key.oid, alg)
                        .await
                        .map_err(AppError::internal)?
                    {
                        found = Some((alg, binding));
                        break;
                    }
                }
                let Some((alg, binding)) = found else {
                    continue;
                };

                return Ok((
                    identity_domain::openid_connect::identifier::key_id(binding.oid),
                    data.private_key.clone(),
                    alg,
                ));
            }
        }

        Err(common::error::InternalError.into_error())
    }

    fn sign_logout_token(
        key_id: &str,
        private_key_pem: &str,
        alg: JwaSigningAlgorithm,
        issuer: &Url,
        audience: Uuid,
        protected_session_id: Option<&str>,
        subject: Option<&str>,
    ) -> Result<String, AppError> {
        let mut header = JwsHeader::new();
        header.set_token_type("logout+jwt");
        header.set_key_id(key_id);

        let now = SystemTime::now();
        let mut payload = JwtPayload::new();
        payload.set_issuer(issuer.as_str());
        payload.set_audience(vec![
            identity_domain::openid_connect::identifier::client_id(audience),
        ]);
        payload.set_issued_at(&now);
        payload.set_jwt_id(
            identity_domain::openid_connect::identifier::logout_token_id(Uuid::new_v4()),
        );
        if let Some(protected_session_id) = protected_session_id {
            payload
                .set_claim("sid", Some(json!(protected_session_id)))
                .map_err(AppError::internal)?;
        }
        if let Some(subject) = subject {
            payload.set_subject(subject);
        }
        payload
            .set_claim(
                "events",
                Some(json!({
                    "http://schemas.openid.net/event/backchannel-logout": {}
                })),
            )
            .map_err(AppError::internal)?;

        let signer = build_logout_token_signer(private_key_pem, alg)?;
        jwt::encode_with_signer(&payload, &header, &*signer).map_err(AppError::internal)
    }

    async fn verify_id_token_hint(&self, raw: &str) -> Result<IdTokenHintClaims, AppError> {
        let invalid = || openid_connect::error::IdTokenHintInvalid.into_error();
        let header = jwt::decode_header(raw).map_err(|_| invalid())?;
        let alg = header
            .claim("alg")
            .and_then(|value| value.as_str())
            .filter(|alg| !alg.eq_ignore_ascii_case("none"))
            .ok_or_else(invalid)?;
        if header
            .claim("typ")
            .and_then(|value| value.as_str())
            .is_some_and(|typ| typ != "JWT")
        {
            return Err(invalid());
        }

        let keys = self
            .key_repo
            .list_active_asymmetric()
            .await
            .map_err(AppError::internal)?;
        let mut verified_payload = None;
        for key in keys {
            let KeyData::Asymmetric(data) = key.data else {
                continue;
            };
            let Ok(verifier) = asymmetric_verifier_from_pem(alg, data.public_key.as_bytes()) else {
                continue;
            };
            if let Ok((payload, _)) = jwt::decode_with_verifier(raw, verifier.as_ref()) {
                verified_payload = Some(payload);
                break;
            }
        }
        let payload = verified_payload.ok_or_else(invalid)?;
        if payload.subject().is_none() || payload.issued_at().is_none() {
            return Err(invalid());
        }

        let issuer = self.provider_service.issuer()?;
        if payload.issuer() != Some(issuer.as_str()) {
            return Err(openid_connect::error::IdTokenHintIssuerInvalid.into_error());
        }

        let audience = payload
            .audience()
            .filter(|audience| !audience.is_empty())
            .ok_or_else(invalid)?
            .into_iter()
            .map(str::to_owned)
            .collect();
        let authorized_party = payload
            .claim("azp")
            .and_then(|value| value.as_str())
            .map(str::to_owned);

        let session_id = payload
            .claim("sid")
            .and_then(|value| value.as_str())
            .filter(|sid| !sid.is_empty())
            .map(str::to_owned);

        Ok(IdTokenHintClaims {
            audience,
            authorized_party,
            session_id,
        })
    }
}

fn validate_registered_post_logout_redirect_uri(
    client: &OpenIdConnectClient,
    redirect_uri: &Url,
) -> Result<(), AppError> {
    let registered = client
        .metadata()
        .post_logout_redirect_uris
        .as_ref()
        .is_some_and(|uris| uris.iter().any(|registered| registered == redirect_uri));

    if registered {
        Ok(())
    } else {
        Err(openid_connect::error::PostLogoutRedirectUriNotRegistered.into_error())
    }
}

fn audience_client_id(claims: Option<&IdTokenHintClaims>) -> Option<String> {
    claims.and_then(|claims| {
        claims
            .authorized_party
            .clone()
            .or_else(|| (claims.audience.len() == 1).then(|| claims.audience[0].clone()))
    })
}

fn build_logout_token_signer(
    private_key_pem: &str,
    alg: JwaSigningAlgorithm,
) -> Result<Box<dyn JwsSigner>, AppError> {
    let pem = private_key_pem.as_bytes();
    let err = common::error::InternalError::map_source();
    match alg {
        JwaSigningAlgorithm::Rs256 => Ok(Box::new(RS256.signer_from_pem(pem).map_err(err)?)),
        JwaSigningAlgorithm::Rs384 => Ok(Box::new(RS384.signer_from_pem(pem).map_err(err)?)),
        JwaSigningAlgorithm::Rs512 => Ok(Box::new(RS512.signer_from_pem(pem).map_err(err)?)),
        JwaSigningAlgorithm::Ps256 => Ok(Box::new(PS256.signer_from_pem(pem).map_err(err)?)),
        JwaSigningAlgorithm::Ps384 => Ok(Box::new(PS384.signer_from_pem(pem).map_err(err)?)),
        JwaSigningAlgorithm::Ps512 => Ok(Box::new(PS512.signer_from_pem(pem).map_err(err)?)),
        JwaSigningAlgorithm::Es256 => Ok(Box::new(ES256.signer_from_pem(pem).map_err(err)?)),
        JwaSigningAlgorithm::Es384 => Ok(Box::new(ES384.signer_from_pem(pem).map_err(err)?)),
        JwaSigningAlgorithm::Es512 => Ok(Box::new(ES512.signer_from_pem(pem).map_err(err)?)),
        JwaSigningAlgorithm::Es256k => Ok(Box::new(ES256K.signer_from_pem(pem).map_err(err)?)),
        JwaSigningAlgorithm::EdDsa => Ok(Box::new(EdDSA.signer_from_pem(pem).map_err(err)?)),
    }
}
