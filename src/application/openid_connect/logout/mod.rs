use std::sync::Arc;

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use url::Url;
use uuid::Uuid;

use crate::{
    application::{
        error::{AppError, codes::openid_connect::OpenIdConnectErrorCode},
        openid_connect::provider::OpenIdProviderService,
    },
    domain::openid_connect::{OpenIdConnectClient, OpenIdConnectClientRepository},
};

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RpInitiatedLogoutRequest {
    pub id_token_hint: Option<String>,
    pub logout_hint: Option<String>,
    pub client_id: Option<String>,
    pub post_logout_redirect_uri: Option<String>,
    pub state: Option<String>,
    pub ui_locales: Option<String>,
    pub session_oid: Option<Uuid>,
    pub protected_session_id: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FrontChannelLogoutNotification {
    pub client_id: Uuid,
    pub logout_uri: Url,
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

#[derive(Debug, Clone, PartialEq, Eq)]
struct IdTokenHintClaims {
    issuer: Option<String>,
    audience: Vec<String>,
}

pub struct LogoutService {
    client_repo: Arc<dyn OpenIdConnectClientRepository>,
    provider_service: Arc<OpenIdProviderService>,
}

impl LogoutService {
    pub fn new(
        client_repo: Arc<dyn OpenIdConnectClientRepository>,
        provider_service: Arc<OpenIdProviderService>,
    ) -> Self {
        Self {
            client_repo,
            provider_service,
        }
    }

    pub async fn rp_initiated_logout(
        &self,
        request: RpInitiatedLogoutRequest,
    ) -> Result<LogoutOutcome, AppError> {
        let Some(raw_redirect_uri) = request.post_logout_redirect_uri.as_deref() else {
            return self
                .outcome_with_frontchannel_notifications(
                    request.session_oid,
                    request.protected_session_id.as_deref(),
                    None,
                )
                .await;
        };

        let redirect_uri = Url::parse(raw_redirect_uri).map_err(|error| {
            AppError::from_code(OpenIdConnectErrorCode::PostLogoutRedirectUriInvalid)
                .with_source(error)
        })?;

        let id_token_hint = request
            .id_token_hint
            .as_deref()
            .map(parse_id_token_hint_claims)
            .transpose()?;
        if let Some(claims) = id_token_hint.as_ref() {
            self.validate_id_token_hint_issuer(claims)?;
        }

        let client_id = request
            .client_id
            .as_deref()
            .map(str::to_owned)
            .or_else(|| audience_client_id(id_token_hint.as_ref()));

        let client_id = client_id
            .ok_or_else(|| AppError::from_code(OpenIdConnectErrorCode::IdTokenHintRequired))?;
        let client_oid = Uuid::parse_str(&client_id).map_err(|error| {
            AppError::from_code(OpenIdConnectErrorCode::LogoutClientInvalid).with_source(error)
        })?;

        let client = self
            .client_repo
            .find_by_oid(client_oid)
            .await
            .map_err(|error| {
                AppError::from_code(OpenIdConnectErrorCode::LogoutClientLookupFailed)
                    .with_source(error)
            })?
            .ok_or_else(|| AppError::from_code(OpenIdConnectErrorCode::LogoutClientNotFound))?;

        validate_registered_post_logout_redirect_uri(&client, &redirect_uri)?;

        let mut redirect_uri = redirect_uri;
        if let Some(state) = request.state.as_deref() {
            redirect_uri.query_pairs_mut().append_pair("state", state);
        }

        self.outcome_with_frontchannel_notifications(
            request.session_oid,
            request.protected_session_id.as_deref(),
            Some(redirect_uri),
        )
        .await
    }

    async fn outcome_with_frontchannel_notifications(
        &self,
        session_oid: Option<Uuid>,
        protected_session_id: Option<&str>,
        post_logout_redirect_uri: Option<Url>,
    ) -> Result<LogoutOutcome, AppError> {
        let notifications = self
            .frontchannel_logout_notifications(session_oid, protected_session_id)
            .await?;

        if !notifications.is_empty() {
            return Ok(LogoutOutcome::FrontChannel {
                notifications,
                post_logout_redirect_uri,
            });
        }

        match post_logout_redirect_uri {
            Some(redirect_uri) => Ok(LogoutOutcome::Redirect { redirect_uri }),
            None => Ok(LogoutOutcome::LoggedOut),
        }
    }

    async fn frontchannel_logout_notifications(
        &self,
        session_oid: Option<Uuid>,
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
            .map_err(|error| {
                AppError::from_code(OpenIdConnectErrorCode::LogoutClientLookupFailed)
                    .with_source(error)
            })?;

        Ok(clients
            .into_iter()
            .filter_map(|client| {
                let mut logout_uri = client.metadata().frontchannel_logout_uri.clone()?;
                logout_uri
                    .query_pairs_mut()
                    .append_pair("iss", issuer.as_str())
                    .append_pair("sid", protected_session_id.unwrap_or_default());
                Some(FrontChannelLogoutNotification {
                    client_id: client.client().oid,
                    logout_uri,
                })
            })
            .collect())
    }

    fn validate_id_token_hint_issuer(&self, claims: &IdTokenHintClaims) -> Result<(), AppError> {
        let issuer = self.provider_service.issuer()?;
        if claims
            .issuer
            .as_deref()
            .is_some_and(|value| value == issuer.as_str())
        {
            return Ok(());
        }

        Err(AppError::from_code(
            OpenIdConnectErrorCode::IdTokenHintIssuerInvalid,
        ))
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
        Err(AppError::from_code(
            OpenIdConnectErrorCode::PostLogoutRedirectUriNotRegistered,
        ))
    }
}

fn audience_client_id(claims: Option<&IdTokenHintClaims>) -> Option<String> {
    claims.and_then(|claims| claims.audience.first().cloned())
}

fn parse_id_token_hint_claims(raw: &str) -> Result<IdTokenHintClaims, AppError> {
    let header_segment = raw
        .split('.')
        .next()
        .ok_or_else(|| AppError::from_code(OpenIdConnectErrorCode::IdTokenHintInvalid))?;
    let header = URL_SAFE_NO_PAD.decode(header_segment).map_err(|error| {
        AppError::from_code(OpenIdConnectErrorCode::IdTokenHintInvalid).with_source(error)
    })?;
    let header = serde_json::from_slice::<serde_json::Value>(&header).map_err(|error| {
        AppError::from_code(OpenIdConnectErrorCode::IdTokenHintInvalid).with_source(error)
    })?;
    if header
        .get("alg")
        .and_then(|value| value.as_str())
        .is_none_or(|alg| alg.eq_ignore_ascii_case("none"))
    {
        return Err(AppError::from_code(
            OpenIdConnectErrorCode::IdTokenHintInvalid,
        ));
    }

    let payload_segment = raw
        .split('.')
        .nth(1)
        .ok_or_else(|| AppError::from_code(OpenIdConnectErrorCode::IdTokenHintInvalid))?;
    let payload = URL_SAFE_NO_PAD.decode(payload_segment).map_err(|error| {
        AppError::from_code(OpenIdConnectErrorCode::IdTokenHintInvalid).with_source(error)
    })?;
    let payload = serde_json::from_slice::<serde_json::Value>(&payload).map_err(|error| {
        AppError::from_code(OpenIdConnectErrorCode::IdTokenHintInvalid).with_source(error)
    })?;

    let issuer = payload
        .get("iss")
        .and_then(|value| value.as_str())
        .map(str::to_owned);
    let audience = match payload.get("aud") {
        Some(value) if value.is_string() => value
            .as_str()
            .map(|value| vec![value.to_owned()])
            .unwrap_or_default(),
        Some(value) if value.is_array() => value
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(|value| value.as_str().map(str::to_owned))
            .collect(),
        _ => Vec::new(),
    };

    Ok(IdTokenHintClaims { issuer, audience })
}

#[cfg(test)]
fn signed_like_id_token_hint_for_test(issuer: &str, audience: Uuid) -> String {
    let payload = serde_json::json!({
        "iss": issuer,
        "aud": audience.to_string()
    });
    let header = URL_SAFE_NO_PAD.encode(r#"{"alg":"RS256"}"#);
    let payload = URL_SAFE_NO_PAD.encode(payload.to_string());
    format!("{header}.{payload}.signature")
}

#[cfg(test)]
fn unsigned_id_token_hint_for_test(issuer: &str, audience: Uuid) -> String {
    let payload = serde_json::json!({
        "iss": issuer,
        "aud": audience.to_string()
    });
    let header = URL_SAFE_NO_PAD.encode(r#"{"alg":"none"}"#);
    let payload = URL_SAFE_NO_PAD.encode(payload.to_string());
    format!("{header}.{payload}.")
}

#[cfg(test)]
mod tests {
    use super::{
        LogoutOutcome, LogoutService, RpInitiatedLogoutRequest, signed_like_id_token_hint_for_test,
        unsigned_id_token_hint_for_test,
    };
    use crate::{
        domain::{
            client::model::{Client, ClientProtocol},
            openid_connect::{
                OpenIdConnectClient, OpenIdConnectClientMetadata, OpenIdConnectClientPlatform,
                OpenIdConnectClientPlatformType, OpenIdConnectClientRepository,
                OpenIdConnectClientRepositoryError, OpenIdConnectClientSettings,
            },
            setting::installation::{InstallationSetting, InstallationState},
        },
        openid_connect::provider::OpenIdProviderService,
    };
    use async_trait::async_trait;
    use chrono::Utc;
    use std::{collections::HashMap, sync::Arc};
    use url::Url;
    use uuid::Uuid;

    #[derive(Clone)]
    struct FakeClientRepository {
        clients: HashMap<Uuid, OpenIdConnectClient>,
    }

    struct TestInstallationSetting(Arc<InstallationState>);

    impl crate::application::setting::runtime::SettingProvider<InstallationSetting>
        for TestInstallationSetting
    {
        fn current_value(&self) -> Arc<InstallationState> {
            Arc::clone(&self.0)
        }
    }

    #[async_trait]
    impl OpenIdConnectClientRepository for FakeClientRepository {
        async fn find_by_oid(
            &self,
            oid: Uuid,
        ) -> Result<Option<OpenIdConnectClient>, OpenIdConnectClientRepositoryError> {
            Ok(self.clients.get(&oid).cloned())
        }

        async fn find_frontchannel_logout_clients_by_session_oid(
            &self,
            _session_oid: Uuid,
        ) -> Result<Vec<OpenIdConnectClient>, OpenIdConnectClientRepositoryError> {
            Ok(self.clients.values().cloned().collect())
        }
    }

    fn test_client(
        client_oid: Uuid,
        post_logout_redirect_uri: Option<&str>,
        frontchannel_logout_uri: Option<&str>,
    ) -> OpenIdConnectClient {
        OpenIdConnectClient::new(
            Client {
                oid: client_oid,
                protocol: ClientProtocol::OpenIdConnect,
                name: "Conformance RP".to_owned(),
                names: vec![],
                description: None,
                created_at: Utc::now(),
                updated_at: None,
            },
            OpenIdConnectClientMetadata {
                post_logout_redirect_uris: post_logout_redirect_uri
                    .map(|uri| vec![Url::parse(uri).unwrap()]),
                frontchannel_logout_uri: frontchannel_logout_uri
                    .map(|uri| Url::parse(uri).unwrap()),
                frontchannel_logout_session_required: Some(true),
                response_types: Some(vec!["code".to_owned()]),
                grant_types: Some(vec!["authorization_code".to_owned()]),
                contacts: None,
                logo_uri: None,
                client_uri: None,
                policy_uri: None,
                tos_uri: None,
                sector_identifier_uri: None,
                subject_type: None,
                id_token_signed_response_alg: None,
                id_token_encrypted_response_alg: None,
                id_token_encrypted_response_enc: None,
                userinfo_signed_response_alg: None,
                userinfo_encrypted_response_alg: None,
                userinfo_encrypted_response_enc: None,
                request_object_signing_alg: None,
                request_object_encryption_alg: None,
                request_object_encryption_enc: None,
                token_endpoint_auth_method: None,
                token_endpoint_auth_signing_alg: None,
                default_max_age: None,
                require_auth_time: None,
                default_acr_values: None,
                initiate_login_uri: None,
                request_uris: None,
                settings: OpenIdConnectClientSettings::default(),
            },
            vec![OpenIdConnectClientPlatform {
                platform: OpenIdConnectClientPlatformType::Web,
                redirect_uris: vec![Url::parse("https://rp.example.com/callback").unwrap()],
            }],
            vec!["openid".to_owned()],
        )
        .unwrap()
    }

    fn service_with_clients(clients: Vec<OpenIdConnectClient>) -> LogoutService {
        let mut client_map = HashMap::new();
        for client in clients {
            client_map.insert(client.client().oid, client);
        }

        LogoutService::new(
            Arc::new(FakeClientRepository {
                clients: client_map,
            }),
            Arc::new(OpenIdProviderService::new(Arc::new(
                TestInstallationSetting(Arc::new(InstallationState {
                    initialized: true,
                    domain: Some("https://identity.example.com".to_owned()),
                    first_user_oid: None,
                    first_key_oid: None,
                    initialized_at: None,
                })),
            ))),
        )
    }

    fn service_with_client(
        client_oid: Uuid,
        post_logout_redirect_uri: Option<&str>,
    ) -> LogoutService {
        service_with_clients(vec![test_client(
            client_oid,
            post_logout_redirect_uri,
            None,
        )])
    }

    #[tokio::test]
    async fn validates_registered_post_logout_redirect_uri_and_preserves_state() {
        let client_oid = Uuid::new_v4();
        let service =
            service_with_client(client_oid, Some("https://rp.example.com/logout/callback"));

        let outcome = service
            .rp_initiated_logout(RpInitiatedLogoutRequest {
                id_token_hint: Some(signed_like_id_token_hint_for_test(
                    "https://identity.example.com/",
                    client_oid,
                )),
                client_id: None,
                logout_hint: None,
                post_logout_redirect_uri: Some("https://rp.example.com/logout/callback".to_owned()),
                state: Some("state-123".to_owned()),
                ui_locales: None,
                session_oid: None,
                protected_session_id: Some("protected-session".to_string()),
            })
            .await
            .unwrap();

        let LogoutOutcome::Redirect { redirect_uri } = outcome else {
            panic!("expected redirect outcome");
        };
        assert_eq!(
            redirect_uri.as_str(),
            "https://rp.example.com/logout/callback?state=state-123"
        );
    }

    #[tokio::test]
    async fn rejects_unregistered_post_logout_redirect_uri() {
        let client_oid = Uuid::new_v4();
        let service =
            service_with_client(client_oid, Some("https://rp.example.com/logout/callback"));

        let error = service
            .rp_initiated_logout(RpInitiatedLogoutRequest {
                id_token_hint: Some(signed_like_id_token_hint_for_test(
                    "https://identity.example.com/",
                    client_oid,
                )),
                client_id: None,
                logout_hint: None,
                post_logout_redirect_uri: Some("https://evil.example.com/logout".to_owned()),
                state: None,
                ui_locales: None,
                session_oid: None,
                protected_session_id: None,
            })
            .await
            .unwrap_err();

        assert_eq!(error.code(), 21003);
    }

    #[tokio::test]
    async fn returns_logged_out_page_when_no_redirect_is_requested() {
        let client_oid = Uuid::new_v4();
        let service = service_with_client(client_oid, None);

        let outcome = service
            .rp_initiated_logout(RpInitiatedLogoutRequest {
                id_token_hint: None,
                client_id: None,
                logout_hint: None,
                post_logout_redirect_uri: None,
                state: None,
                ui_locales: None,
                session_oid: None,
                protected_session_id: None,
            })
            .await
            .unwrap();

        assert_eq!(outcome, LogoutOutcome::LoggedOut);
    }

    #[tokio::test]
    async fn returns_frontchannel_logout_notifications_for_session_clients() {
        let client_oid = Uuid::new_v4();
        let session_oid = Uuid::new_v4();
        let service = service_with_clients(vec![test_client(
            client_oid,
            None,
            Some("https://rp.example.com/frontchannel_logout?existing=1"),
        )]);

        let outcome = service
            .rp_initiated_logout(RpInitiatedLogoutRequest {
                id_token_hint: None,
                client_id: None,
                logout_hint: None,
                post_logout_redirect_uri: None,
                state: None,
                ui_locales: None,
                session_oid: Some(session_oid),
                protected_session_id: Some("protected-session".to_string()),
            })
            .await
            .unwrap();

        let LogoutOutcome::FrontChannel {
            notifications,
            post_logout_redirect_uri,
        } = outcome
        else {
            panic!("expected front-channel logout outcome");
        };

        assert!(post_logout_redirect_uri.is_none());
        assert_eq!(notifications.len(), 1);
        assert_eq!(notifications[0].client_id, client_oid);
        assert_eq!(
            notifications[0].logout_uri.as_str(),
            "https://rp.example.com/frontchannel_logout?existing=1&iss=https%3A%2F%2Fidentity.example.com%2F&sid=protected-session"
        );
        assert!(
            !notifications[0]
                .logout_uri
                .as_str()
                .contains(&session_oid.to_string())
        );
    }

    #[tokio::test]
    async fn frontchannel_logout_preserves_post_logout_redirect_uri() {
        let client_oid = Uuid::new_v4();
        let session_oid = Uuid::new_v4();
        let service = service_with_clients(vec![test_client(
            client_oid,
            Some("https://rp.example.com/logout/callback"),
            Some("https://rp.example.com/frontchannel_logout"),
        )]);

        let outcome = service
            .rp_initiated_logout(RpInitiatedLogoutRequest {
                id_token_hint: Some(signed_like_id_token_hint_for_test(
                    "https://identity.example.com/",
                    client_oid,
                )),
                client_id: None,
                logout_hint: None,
                post_logout_redirect_uri: Some("https://rp.example.com/logout/callback".to_owned()),
                state: Some("state-123".to_owned()),
                ui_locales: None,
                session_oid: Some(session_oid),
                protected_session_id: Some("protected-session".to_string()),
            })
            .await
            .unwrap();

        let LogoutOutcome::FrontChannel {
            notifications,
            post_logout_redirect_uri,
        } = outcome
        else {
            panic!("expected front-channel logout outcome");
        };

        assert_eq!(notifications.len(), 1);
        assert_eq!(
            post_logout_redirect_uri.unwrap().as_str(),
            "https://rp.example.com/logout/callback?state=state-123"
        );
    }

    #[tokio::test]
    async fn rejects_missing_id_token_hint_when_redirecting_without_client_id() {
        let client_oid = Uuid::new_v4();
        let service =
            service_with_client(client_oid, Some("https://rp.example.com/logout/callback"));

        let error = service
            .rp_initiated_logout(RpInitiatedLogoutRequest {
                id_token_hint: None,
                client_id: None,
                logout_hint: None,
                post_logout_redirect_uri: Some("https://rp.example.com/logout/callback".to_owned()),
                state: None,
                ui_locales: None,
                session_oid: None,
                protected_session_id: None,
            })
            .await
            .unwrap_err();

        assert_eq!(error.code(), 21011);
    }

    #[tokio::test]
    async fn rejects_unsigned_id_token_hint_when_redirecting() {
        let client_oid = Uuid::new_v4();
        let service =
            service_with_client(client_oid, Some("https://rp.example.com/logout/callback"));

        let error = service
            .rp_initiated_logout(RpInitiatedLogoutRequest {
                id_token_hint: Some(unsigned_id_token_hint_for_test(
                    "https://identity.example.com/",
                    client_oid,
                )),
                client_id: None,
                logout_hint: None,
                post_logout_redirect_uri: Some("https://rp.example.com/logout/callback".to_owned()),
                state: None,
                ui_locales: None,
                session_oid: None,
                protected_session_id: None,
            })
            .await
            .unwrap_err();

        assert_eq!(error.code(), 21010);
    }

    #[tokio::test]
    async fn rejects_id_token_hint_from_another_issuer_when_redirecting() {
        let client_oid = Uuid::new_v4();
        let service =
            service_with_client(client_oid, Some("https://rp.example.com/logout/callback"));

        let error = service
            .rp_initiated_logout(RpInitiatedLogoutRequest {
                id_token_hint: Some(signed_like_id_token_hint_for_test(
                    "https://other.example.com/",
                    client_oid,
                )),
                client_id: None,
                logout_hint: None,
                post_logout_redirect_uri: Some("https://rp.example.com/logout/callback".to_owned()),
                state: None,
                ui_locales: None,
                session_oid: None,
                protected_session_id: None,
            })
            .await
            .unwrap_err();

        assert_eq!(error.code(), 21004);
    }
}
