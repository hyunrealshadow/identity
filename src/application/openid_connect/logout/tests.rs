use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
    time::{Duration, SystemTime},
};

use async_trait::async_trait;
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::Utc;
use identity_domain::auth::{SessionOid, SessionStatus, model::Session};
use josekit::{
    jws::{JwsHeader, RS256},
    jwt,
    jwt::JwtPayload,
};
use openssl::rsa::Rsa;
use serde_json::{Map, json};
use url::Url;
use uuid::Uuid;

use super::{
    BackChannelLogoutDelivery, BackChannelLogoutNotification, BackChannelLogoutSender,
    LogoutOutcome, LogoutService, LogoutServiceDependencies, RpInitiatedLogoutRequest,
};
use crate::{
    domain::{
        client::model::{Client, ClientProtocol},
        key::{
            AsymmetricKeyData, JwaSigningAlgorithm, Key, KeyData, KeyJwk, KeyJwkOid, KeyOid,
            KeyType, PublicJwk,
        },
        openid_connect::{
            OpenIdConnectClient, OpenIdConnectClientMetadata, OpenIdConnectClientPlatform,
            OpenIdConnectClientPlatformType, OpenIdConnectClientRepository,
            OpenIdConnectClientRepositoryError, OpenIdConnectClientSettings,
        },
    },
    observability::{BusinessEvent, EventSink},
    openid_connect::{
        provider::{OpenIdProviderService, SigningAlgorithmDetector},
        tests::fixtures::mocks::{
            MockKeyJwkRepository, MockKeyRepository, session::MockSessionRepository,
        },
    },
    setting::{AppSettings, InstallationSettings, SettingsSnapshot, SettingsSource},
};

struct NoopBackChannelLogoutSender;

#[async_trait]
impl BackChannelLogoutSender for NoopBackChannelLogoutSender {
    async fn send(
        &self,
        _notification: &BackChannelLogoutNotification,
    ) -> BackChannelLogoutDelivery {
        BackChannelLogoutDelivery::Delivered
    }
}

struct RecordingBackChannelLogoutSender {
    delivery: BackChannelLogoutDelivery,
    notifications: Mutex<Vec<BackChannelLogoutNotification>>,
}

#[async_trait]
impl BackChannelLogoutSender for RecordingBackChannelLogoutSender {
    async fn send(
        &self,
        notification: &BackChannelLogoutNotification,
    ) -> BackChannelLogoutDelivery {
        self.notifications
            .lock()
            .unwrap()
            .push(notification.clone());
        self.delivery
    }
}

#[derive(Default)]
struct RecordingEventSink(Mutex<Vec<BusinessEvent>>);

impl EventSink for RecordingEventSink {
    fn emit(&self, event: BusinessEvent) {
        self.0.lock().unwrap().push(event);
    }
}

#[derive(Clone)]
struct FakeClientRepository {
    clients: HashMap<Uuid, OpenIdConnectClient>,
}

#[derive(Clone)]
struct SigningMaterial {
    key: Key,
    binding: KeyJwk,
    public_key: String,
}

struct TestSigningAlgorithmDetector;

struct TestInstallationSetting(Arc<SettingsSnapshot>);

impl SettingsSource for TestInstallationSetting {
    fn snapshot(&self) -> Arc<SettingsSnapshot> {
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
        _session_oid: SessionOid,
    ) -> Result<Vec<OpenIdConnectClient>, OpenIdConnectClientRepositoryError> {
        Ok(self.clients.values().cloned().collect())
    }

    async fn find_backchannel_logout_clients_by_session_oid(
        &self,
        _session_oid: SessionOid,
    ) -> Result<Vec<OpenIdConnectClient>, OpenIdConnectClientRepositoryError> {
        Ok(self.clients.values().cloned().collect())
    }
}

impl SigningAlgorithmDetector for TestSigningAlgorithmDetector {
    fn detect(&self, _key: &Key) -> Vec<JwaSigningAlgorithm> {
        vec![JwaSigningAlgorithm::Rs256]
    }
}

fn test_client(
    client_oid: Uuid,
    post_logout_redirect_uri: Option<&str>,
    frontchannel_logout_uri: Option<&str>,
    backchannel_logout_uri: Option<&str>,
) -> OpenIdConnectClient {
    OpenIdConnectClient::new(
        Client {
            oid: client_oid,
            protocol: ClientProtocol::OpenIdConnect,
            name: "Conformance RP".to_owned(),
            names: vec![],
            description: None,
            built_in: false,
            created_at: Utc::now(),
            updated_at: None,
        },
        OpenIdConnectClientMetadata {
            post_logout_redirect_uris: post_logout_redirect_uri
                .map(|uri| vec![Url::parse(uri).unwrap()]),
            frontchannel_logout_uri: frontchannel_logout_uri.map(|uri| Url::parse(uri).unwrap()),
            frontchannel_logout_session_required: Some(true),
            backchannel_logout_uri: backchannel_logout_uri.map(|uri| Url::parse(uri).unwrap()),
            backchannel_logout_session_required: Some(true),
            response_types: Some(vec!["code".parse().unwrap()]),
            grant_types: Some(vec!["authorization_code".parse().unwrap()]),
            contacts: None,
            logo_uri: None,
            client_uri: None,
            policy_uri: None,
            tos_uri: None,
            sector_identifier_uri: None,
            subject_type: None,
            id_token_signed_response_algs: None,
            id_token_encrypted_response_algs: None,
            id_token_encrypted_response_encs: None,
            userinfo_signed_response_algs: None,
            userinfo_encrypted_response_algs: None,
            userinfo_encrypted_response_encs: None,
            request_object_signing_algs: None,
            request_object_encryption_algs: None,
            request_object_encryption_encs: None,
            token_endpoint_auth_methods: None,
            token_endpoint_auth_signing_algs: None,
            default_max_age: None,
            require_auth_time: None,
            default_acr_values: None,
            initiate_login_uri: None,
            request_uris: None,
            settings: OpenIdConnectClientSettings::default(),
        },
        vec![OpenIdConnectClientPlatform {
            platform: OpenIdConnectClientPlatformType::Web,
            redirect_uris: vec!["https://rp.example.com/callback".to_owned()],
        }],
        vec!["openid".to_owned()],
    )
    .unwrap()
}

fn signing_material() -> SigningMaterial {
    let rsa = Rsa::generate(2048).unwrap();
    let private_key = String::from_utf8(rsa.private_key_to_pem().unwrap()).unwrap();
    let public_key = String::from_utf8(rsa.public_key_to_pem().unwrap()).unwrap();
    let key_oid = KeyOid(Uuid::new_v4());
    let key = Key {
        oid: key_oid,
        r#type: KeyType::Asymmetric,
        data: KeyData::Asymmetric(AsymmetricKeyData {
            public_key: public_key.clone(),
            private_key,
            certificate: None,
        }),
        expires_at: None,
        revoked_at: None,
        created_at: Utc::now(),
        updated_at: None,
    };
    let binding = KeyJwk {
        oid: KeyJwkOid(Uuid::new_v4()),
        key_oid,
        algorithm: "RS256".parse().unwrap(),
        jwk: PublicJwk::Rsa {
            key_use: None,
            alg: Some("RS256".to_owned()),
            kid: None,
            n: "n".to_owned(),
            e: "e".to_owned(),
            x5c: None,
            x5t: None,
            x5t_s256: None,
        },
        created_at: Utc::now(),
    };

    SigningMaterial {
        key,
        binding,
        public_key,
    }
}

fn signed_id_token_hint_for_test(
    signing: &SigningMaterial,
    issuer: &str,
    audience: Uuid,
) -> String {
    let KeyData::Asymmetric(key) = &signing.key.data else {
        panic!("expected asymmetric signing key");
    };
    let mut header = JwsHeader::new();
    header.set_token_type("JWT");
    header.set_key_id(Uuid::from(signing.binding.oid).to_string());
    let now = SystemTime::now();
    let mut payload = JwtPayload::new();
    payload.set_issuer(issuer);
    payload.set_subject(Uuid::new_v4().to_string());
    payload.set_audience(vec![audience.to_string()]);
    payload.set_issued_at(&now);
    payload.set_expires_at(&(now - Duration::from_secs(60)));
    payload
        .set_claim("azp", Some(json!(audience.to_string())))
        .unwrap();
    let signer = RS256.signer_from_pem(key.private_key.as_bytes()).unwrap();
    jwt::encode_with_signer(&payload, &header, &signer).unwrap()
}

fn service_with_client_and_signing(
    client_oid: Uuid,
    post_logout_redirect_uri: Option<&str>,
) -> (LogoutService, SigningMaterial) {
    service_with_clients_and_signing(vec![test_client(
        client_oid,
        post_logout_redirect_uri,
        None,
        None,
    )])
}

fn service_with_clients_and_signing(
    clients: Vec<OpenIdConnectClient>,
) -> (LogoutService, SigningMaterial) {
    let mut client_map = HashMap::new();
    for client in clients {
        client_map.insert(client.client().oid, client);
    }
    let signing = signing_material();

    let mut key_repo = MockKeyRepository::new();
    let k = signing.key.clone();
    key_repo
        .expect_find_by_oid()
        .returning(move |oid| Ok((oid == k.oid).then(|| k.clone())));
    let k = signing.key.clone();
    key_repo
        .expect_list_active_asymmetric()
        .returning(move || Ok(vec![k.clone()]));
    key_repo
        .expect_list_decryptable_symmetric()
        .returning(|| Ok(vec![]));

    let mut jwk_repo = MockKeyJwkRepository::new();
    let b = vec![signing.binding.clone()];
    let b2 = b.clone();
    jwk_repo
        .expect_list_active()
        .returning(move || Ok(b.clone()));
    jwk_repo
        .expect_find_active_by_key_oid_and_algorithm()
        .returning(move |oid, alg| {
            Ok(b2
                .iter()
                .find(|b| b.key_oid == oid && b.algorithm.as_str() == alg.as_str())
                .cloned())
        });

    let service = LogoutService::new(LogoutServiceDependencies {
        client_repo: Arc::new(FakeClientRepository {
            clients: client_map,
        }),
        provider_service: Arc::new(OpenIdProviderService::new(Arc::new(
            TestInstallationSetting(Arc::new(
                SettingsSnapshot::default()
                    .with_section(&AppSettings {
                        domain: Some("https://identity.example.com".to_owned()),
                        login_domain: None,
                        login_client_id: None,
                    })
                    .with_section(&InstallationSettings {
                        initialized: true,
                        initialized_at: None,
                    }),
            )),
        ))),
        key_repo: Arc::new(key_repo),
        key_jwk_repo: Arc::new(jwk_repo),
        signing_algorithm_detector: Arc::new(TestSigningAlgorithmDetector),
        backchannel_sender: Arc::new(NoopBackChannelLogoutSender),
    });
    (service, signing)
}

fn service_with_clients(clients: Vec<OpenIdConnectClient>) -> LogoutService {
    service_with_clients_and_signing(clients).0
}

fn service_with_client(client_oid: Uuid, post_logout_redirect_uri: Option<&str>) -> LogoutService {
    service_with_clients(vec![test_client(
        client_oid,
        post_logout_redirect_uri,
        None,
        None,
    )])
}

#[tokio::test]
async fn backchannel_delivery_outcomes_emit_audit_results() {
    for (delivery, outcome, reason) in [
        (BackChannelLogoutDelivery::Delivered, "success", None),
        (
            BackChannelLogoutDelivery::Rejected,
            "failure",
            Some("non_success_status"),
        ),
        (
            BackChannelLogoutDelivery::TransportFailed,
            "failure",
            Some("transport_error"),
        ),
    ] {
        let sender = Arc::new(RecordingBackChannelLogoutSender {
            delivery,
            notifications: Mutex::new(Vec::new()),
        });
        let events = Arc::new(RecordingEventSink::default());
        let mut service = service_with_clients(Vec::new());
        service.backchannel_sender = sender.clone();
        service.events = events.clone();
        let notification = BackChannelLogoutNotification {
            client_id: Uuid::new_v4(),
            logout_uri: Url::parse("https://rp.example.com/backchannel_logout").unwrap(),
            logout_token: "token".to_owned(),
        };

        service.notify_backchannel_logout(&notification).await;

        assert_eq!(
            sender.notifications.lock().unwrap().as_slice(),
            &[notification]
        );
        let events = events.0.lock().unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].name, "logout.backchannel.result");
        assert_eq!(events[0].outcome, Some(outcome));
        assert_eq!(events[0].reason, reason);
    }
}

#[tokio::test]
async fn validates_registered_post_logout_redirect_uri_and_preserves_state() {
    let client_oid = Uuid::new_v4();
    let (service, signing) =
        service_with_client_and_signing(client_oid, Some("https://rp.example.com/logout/callback"));

    let outcome = service
        .rp_initiated_logout(RpInitiatedLogoutRequest {
            id_token_hint: Some(signed_id_token_hint_for_test(
                &signing,
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
    let (service, signing) =
        service_with_client_and_signing(client_oid, Some("https://rp.example.com/logout/callback"));

    let error = service
        .rp_initiated_logout(RpInitiatedLogoutRequest {
            id_token_hint: Some(signed_id_token_hint_for_test(
                &signing,
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
    let session_oid = SessionOid(Uuid::new_v4());
    let service = service_with_clients(vec![test_client(
        client_oid,
        None,
        Some("https://rp.example.com/frontchannel_logout?existing=1"),
        None,
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
            .contains(&session_oid.0.to_string())
    );
}

#[tokio::test]
async fn frontchannel_logout_preserves_post_logout_redirect_uri() {
    let client_oid = Uuid::new_v4();
    let session_oid = SessionOid(Uuid::new_v4());
    let (service, signing) = service_with_clients_and_signing(vec![test_client(
        client_oid,
        Some("https://rp.example.com/logout/callback"),
        Some("https://rp.example.com/frontchannel_logout"),
        None,
    )]);

    let outcome = service
        .rp_initiated_logout(RpInitiatedLogoutRequest {
            id_token_hint: Some(signed_id_token_hint_for_test(
                &signing,
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
async fn builds_backchannel_logout_token_with_protected_sid() {
    let client_oid = Uuid::new_v4();
    let session_oid = SessionOid(Uuid::new_v4());
    let (service, signing) = service_with_clients_and_signing(vec![test_client(
        client_oid,
        None,
        None,
        Some("https://rp.example.com/backchannel_logout"),
    )]);

    let notifications = service
        .backchannel_logout_notifications(Some(session_oid), Some("protected-session"))
        .await
        .unwrap();

    assert_eq!(notifications.len(), 1);
    assert_eq!(notifications[0].client_id, client_oid);
    assert_eq!(
        notifications[0].logout_uri.as_str(),
        "https://rp.example.com/backchannel_logout"
    );
    assert!(
        !notifications[0]
            .logout_token
            .contains(&session_oid.0.to_string())
    );

    let payload = jwt::decode_with_verifier(
        &notifications[0].logout_token,
        &*RS256
            .verifier_from_pem(signing.public_key.as_bytes())
            .unwrap(),
    )
    .unwrap()
    .0;
    assert_eq!(
        payload.claim("iss").and_then(|value| value.as_str()),
        Some("https://identity.example.com/")
    );
    assert_eq!(
        payload.claim("aud").and_then(|value| {
            value.as_str().or_else(|| {
                value
                    .as_array()
                    .and_then(|audiences| audiences.first())
                    .and_then(|audience| audience.as_str())
            })
        }),
        Some(client_oid.to_string().as_str())
    );
    assert_eq!(
        payload.claim("sid").and_then(|value| value.as_str()),
        Some("protected-session")
    );
    assert!(payload.claim("iat").is_some());
    assert!(payload.claim("jti").is_some());
    assert!(payload.claim("nonce").is_none());
    assert_eq!(
        payload
            .claim("events")
            .and_then(|value| value.as_object())
            .and_then(|events| events.get("http://schemas.openid.net/event/backchannel-logout"))
            .and_then(|value| value.as_object())
            .map(Map::is_empty),
        Some(true)
    );
}

#[tokio::test]
async fn backchannel_logout_uses_subject_when_sid_is_unavailable_and_client_allows_it() {
    let session_oid = SessionOid(Uuid::new_v4());
    let user_oid = Uuid::new_v4();
    let client_without_sid = test_client(
        Uuid::new_v4(),
        None,
        None,
        Some("https://rp.example.com/backchannel_logout"),
    );
    let mut metadata = client_without_sid.metadata().clone();
    metadata.backchannel_logout_session_required = Some(false);
    let client_without_sid = OpenIdConnectClient::new(
        client_without_sid.client().clone(),
        metadata,
        client_without_sid.platforms().to_vec(),
        client_without_sid.assigned_scopes().to_vec(),
    )
    .unwrap();
    let client_requiring_sid = test_client(
        Uuid::new_v4(),
        None,
        None,
        Some("https://required.example.com/backchannel_logout"),
    );
    let expected_client_oid = client_without_sid.client().oid;
    let (service, signing) =
        service_with_clients_and_signing(vec![client_without_sid, client_requiring_sid]);
    let session = Session {
        oid: session_oid,
        user_oid,
        status: SessionStatus::Active,
        device_name: None,
        device_type: None,
        os_name: None,
        os_version: None,
        browser_name: None,
        browser_version: None,
        user_agent: None,
        ip_address: None,
        last_active_at: None,
        expires_at: None,
        revoked_at: None,
        created_at: Utc::now(),
        acr: None,
        acr_expires_at: None,
        amr: Vec::new(),
    };
    let mut session_repo = MockSessionRepository::new();
    session_repo
        .expect_find_by_oid()
        .returning(move |oid| Ok((oid == session_oid).then(|| session.clone())));
    let service = service.with_session_repo(Arc::new(session_repo));

    let notifications = service
        .backchannel_logout_notifications(Some(session_oid), None)
        .await
        .unwrap();
    assert_eq!(notifications.len(), 1);
    assert_eq!(notifications[0].client_id, expected_client_oid);
    let payload = jwt::decode_with_verifier(
        &notifications[0].logout_token,
        &*RS256
            .verifier_from_pem(signing.public_key.as_bytes())
            .unwrap(),
    )
    .unwrap()
    .0;
    assert_eq!(payload.subject(), Some(user_oid.to_string().as_str()));
    assert!(payload.claim("sid").is_none());
}

#[tokio::test]
async fn rejects_missing_id_token_hint_when_redirecting_without_client_id() {
    let client_oid = Uuid::new_v4();
    let service = service_with_client(client_oid, Some("https://rp.example.com/logout/callback"));

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
    let service = service_with_client(client_oid, Some("https://rp.example.com/logout/callback"));

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
    let (service, signing) =
        service_with_client_and_signing(client_oid, Some("https://rp.example.com/logout/callback"));

    let error = service
        .rp_initiated_logout(RpInitiatedLogoutRequest {
            id_token_hint: Some(signed_id_token_hint_for_test(
                &signing,
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

#[tokio::test]
async fn rejects_id_token_hint_with_untrusted_signature() {
    let client_oid = Uuid::new_v4();
    let (service, _) =
        service_with_client_and_signing(client_oid, Some("https://rp.example.com/logout/callback"));
    let untrusted_signing = signing_material();

    let error = service
        .rp_initiated_logout(RpInitiatedLogoutRequest {
            id_token_hint: Some(signed_id_token_hint_for_test(
                &untrusted_signing,
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
async fn rejects_client_id_that_does_not_match_id_token_hint() {
    let hinted_client_oid = Uuid::new_v4();
    let requested_client_oid = Uuid::new_v4();
    let (service, signing) = service_with_clients_and_signing(vec![
        test_client(
            hinted_client_oid,
            Some("https://rp.example.com/logout/callback"),
            None,
            None,
        ),
        test_client(
            requested_client_oid,
            Some("https://rp.example.com/logout/callback"),
            None,
            None,
        ),
    ]);

    let error = service
        .rp_initiated_logout(RpInitiatedLogoutRequest {
            id_token_hint: Some(signed_id_token_hint_for_test(
                &signing,
                "https://identity.example.com/",
                hinted_client_oid,
            )),
            client_id: Some(requested_client_oid.to_string()),
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

fn unsigned_id_token_hint_for_test(issuer: &str, audience: Uuid) -> String {
    let payload = json!({
        "iss": issuer,
        "aud": audience.to_string()
    });
    let header = URL_SAFE_NO_PAD.encode(r#"{"alg":"none"}"#);
    let payload = URL_SAFE_NO_PAD.encode(payload.to_string());
    format!("{header}.{payload}.")
}
