use std::iter;

use chrono::{DateTime, Duration};
use identity_domain::{
    client::model::ClientOid,
    client_authorization::{
        ClientAuthorization, ClientAuthorizationData, ClientAuthorizationType,
        DeviceAuthorizationApproval, DeviceAuthorizationData, DeviceAuthorizationRequestData,
        DeviceConsumeOutcome, DevicePollOutcome, DeviceRequestStatus, PreparedAuthorizationRecord,
        device_code_digest,
    },
    key::JwsAlgorithm,
    openid_connect::{API_RESOURCE, GrantType},
};
use tokio::sync::mpsc::{UnboundedReceiver, unbounded_channel};

use super::{RecordingSink, decode_unverified_payload};
use crate::{
    domain::openid_connect::{OpenIdConnectClientRepository, OpenIdConnectClientRepositoryError},
    observability::EventValue,
    openid_connect::tests::fixtures::{
        client::{test_client, test_metadata, test_platforms, test_scopes},
        mocks::MockDeviceAuthorizationRepository,
    },
};

use crate::openid_connect::token::tests::fixtures::*;
use crate::openid_connect::token::tests::*;

const DEVICE_CODE: &str = "device-code-for-tests";

fn request_record(status: DeviceRequestStatus, expires_at: DateTime<Utc>) -> ClientAuthorization {
    request_record_with_scope(status, expires_at, "openid offline_access")
}

fn request_record_with_scope(
    status: DeviceRequestStatus,
    expires_at: DateTime<Utc>,
    scope: &str,
) -> ClientAuthorization {
    let approval =
        matches!(status, DeviceRequestStatus::Approved).then(|| DeviceAuthorizationApproval {
            user_oid: Uuid::nil().to_string(),
            approved_scope: scope.to_owned(),
            auth_time: Some(1_700_000_000),
            acr: Some("urn:identity:acr:aal1".to_owned()),
            amr: vec!["pwd".to_owned()],
            device_authorization_oid: Uuid::parse_str("33333333-3333-3333-3333-333333333333")
                .unwrap(),
        });

    ClientAuthorization {
        oid: Uuid::parse_str("11111111-1111-1111-1111-111111111111").unwrap(),
        client_oid: Uuid::nil(),
        type_: ClientAuthorizationType::DeviceAuthorizationRequest,
        data: ClientAuthorizationData::DeviceAuthorizationRequest(DeviceAuthorizationRequestData {
            resources: Vec::new(),
            scope: scope.to_owned(),
            device_code_digest: device_code_digest(DEVICE_CODE),
            claimed_login_oid: None,
            user_code: "WDJBMJHT".to_owned(),
            user_code_display: "WDJB-MJHT".to_owned(),
            interval_seconds: 5,
            slow_down_seconds: 0,
            last_polled_at: None,
            status,
            device_authorization_oid: approval
                .as_ref()
                .map(|approval| approval.device_authorization_oid),
            approval,
            denied_by_user_oid: None,
            decided_at: None,
            client_authentication_mode: None,
        }),
        expires_at,
        completed_at: None,
        revoked_at: None,
        created_at: Utc::now(),
        updated_at: None,
    }
}

fn relation_record(revoked: bool) -> ClientAuthorization {
    relation_record_with_scope(revoked, "openid offline_access")
}

fn relation_record_with_scope(revoked: bool, scope: &str) -> ClientAuthorization {
    ClientAuthorization {
        oid: Uuid::parse_str("33333333-3333-3333-3333-333333333333").unwrap(),
        client_oid: Uuid::nil(),
        type_: ClientAuthorizationType::DeviceAuthorization,
        data: ClientAuthorizationData::DeviceAuthorization(DeviceAuthorizationData {
            resources: Vec::new(),
            scope: scope.to_owned(),
            user_oid: Uuid::nil().to_string(),
            auth_time: Some(1_700_000_000),
            acr: Some("urn:identity:acr:aal1".to_owned()),
            amr: vec!["pwd".to_owned()],
            request_oid: Uuid::parse_str("11111111-1111-1111-1111-111111111111").unwrap(),
            approved_at: Utc::now(),
        }),
        expires_at: Utc::now() + Duration::days(365),
        completed_at: None,
        revoked_at: revoked.then(Utc::now),
        created_at: Utc::now(),
        updated_at: None,
    }
}

fn device_client(grant_types: Vec<GrantType>) -> OpenIdConnectClient {
    device_client_with_id_token_algorithm(grant_types, None)
}

fn public_device_client() -> OpenIdConnectClient {
    let mut metadata = test_metadata(None, Some("none"));
    metadata.grant_types = Some(vec![GrantType::DeviceCode]);
    OpenIdConnectClient::new(
        test_client(Uuid::nil()),
        metadata,
        test_platforms(),
        test_scopes(),
    )
    .unwrap()
}

fn device_client_with_id_token_algorithm(
    grant_types: Vec<GrantType>,
    algorithm: Option<JwaSigningAlgorithm>,
) -> OpenIdConnectClient {
    let mut metadata = test_metadata(None, Some("client_secret_basic"));
    metadata.grant_types = Some(grant_types);
    metadata.id_token_signed_response_algs =
        algorithm.map(|value| vec![JwsAlgorithm::Asymmetric(value)]);

    OpenIdConnectClient::new(
        test_client(Uuid::nil()),
        metadata,
        test_platforms(),
        test_scopes(),
    )
    .unwrap()
}

#[tokio::test]
async fn device_grant_uses_client_algorithm_for_access_token() {
    for scope in ["openid offline_access", "profile"] {
        let (repo, _records) = device_repo(
            request_record_with_scope(
                DeviceRequestStatus::Approved,
                Utc::now() + Duration::minutes(10),
                scope,
            ),
            Some(relation_record_with_scope(false, scope)),
            DeviceRepoOptions::default(),
        );
        let mut service = build_service(
            device_client_with_id_token_algorithm(
                vec![GrantType::DeviceCode],
                Some(JwaSigningAlgorithm::Rs256),
            ),
            repo,
        );
        let default_ec_key = key_for_algorithm("ES256");
        let requested_rsa_key = key_for_algorithm("RS256");
        let ec_binding = key_jwk_binding(&default_ec_key, "ES256", Uuid::new_v4());
        let rsa_binding = key_jwk_binding(&requested_rsa_key, "RS256", Uuid::new_v4());
        service.key_repo = Arc::new(key_repo_with_keys(vec![default_ec_key, requested_rsa_key]));
        service.key_jwk_repo = Arc::new(jwk_repo_with_bindings(vec![
            ec_binding,
            rsa_binding.clone(),
        ]));

        let response = service.exchange_device_code(params()).await.unwrap();
        assert_eq!(response.id_token.is_some(), scope.contains("openid"));
        let expected_kid = Uuid::from(rsa_binding.oid).to_string();
        for token in iter::once(&response.access_token).chain(response.id_token.iter()) {
            let header = jwt::decode_header(token).unwrap();
            assert_eq!(
                header.claim(JwtClaimNames::ALG).and_then(|v| v.as_str()),
                Some("RS256")
            );
            assert_eq!(
                header.claim(JwtClaimNames::KID).and_then(|v| v.as_str()),
                Some(expected_kid.as_str())
            );
        }
    }
}

#[tokio::test]
async fn device_grant_includes_scoped_user_claims_in_access_token_when_enabled() {
    let scope = "openid profile email";
    let (repo, _records) = device_repo(
        request_record_with_scope(
            DeviceRequestStatus::Approved,
            Utc::now() + Duration::minutes(10),
            scope,
        ),
        Some(relation_record_with_scope(false, scope)),
        DeviceRepoOptions::default(),
    );
    let mut metadata = test_metadata(None, Some("client_secret_basic"));
    metadata.grant_types = Some(vec![GrantType::DeviceCode]);
    metadata.settings.include_scoped_claims_in_access_token = true;
    let client = OpenIdConnectClient::new(
        test_client(Uuid::nil()),
        metadata,
        test_platforms(),
        test_scopes(),
    )
    .unwrap();
    let service = build_service(client, repo);

    let response = service.exchange_device_code(params()).await.unwrap();
    let access_claims = decode_unverified_payload(&response.access_token);
    assert_eq!(access_claims["name"], "A");
    assert_eq!(access_claims["email"], "a@example.com");
    let id_claims = decode_unverified_payload(response.id_token.as_ref().unwrap());
    assert!(id_claims.get("name").is_none());
    assert!(id_claims.get("email").is_none());
}

#[derive(Default)]
struct DeviceRepoOptions {
    poll: Option<DevicePollOutcome>,
    consume: Option<DeviceConsumeOutcome>,
    client_oid: Option<Uuid>,
}

/// Builds a device repository mock around one request record.
fn device_repo(
    record: ClientAuthorization,
    relation: Option<ClientAuthorization>,
    options: DeviceRepoOptions,
) -> (
    Arc<MockDeviceAuthorizationRepository>,
    UnboundedReceiver<Vec<PreparedAuthorizationRecord>>,
) {
    let mut repo = MockDeviceAuthorizationRepository::new();
    let client_oid = options.client_oid.unwrap_or(record.client_oid);
    let record_for_lookup = record.clone();
    repo.expect_find_device_request_by_device_code_digest()
        .returning(move |_| {
            let mut record = record_for_lookup.clone();
            record.client_oid = client_oid;

            Ok(Some(record))
        });
    let record_for_oid = record.clone();
    repo.expect_find_device_request_by_oid()
        .returning(move |_| Ok(Some(record_for_oid.clone())));
    if let Some(relation) = relation {
        repo.expect_find_device_authorization_by_oid()
            .returning(move |_| Ok(Some(relation.clone())));
    }
    let poll = options.poll.unwrap_or(DevicePollOutcome::Accepted);
    repo.expect_record_device_poll()
        .returning(move |_, _| Ok(poll));
    let (sender, receiver) = unbounded_channel();
    let consume = options.consume.unwrap_or(DeviceConsumeOutcome::Consumed);
    repo.expect_consume_device_request_with_tokens()
        .returning(move |_, records, _| {
            let _ = sender.send(records);
            Ok(consume)
        });

    (Arc::new(repo), receiver)
}

fn params() -> DeviceCodeGrantParams {
    DeviceCodeGrantParams {
        resources: Vec::new(),
        device_code: DEVICE_CODE.to_owned(),
        client_id: Some(Uuid::nil().to_string()),
        client_secret: Some("secret-123".to_owned()),
        client_secret_basic: true,
        client_assertion_type: None,
        client_assertion: None,
    }
}

fn build_service(
    client: OpenIdConnectClient,
    repo: Arc<MockDeviceAuthorizationRepository>,
) -> TokenService {
    build_token_service_with_device_repo(
        Arc::new(mock_client_auth_repo()),
        Uuid::nil(),
        Arc::new(DeviceClientRepository { client }),
        repo,
    )
}

struct DeviceClientRepository {
    client: OpenIdConnectClient,
}

#[async_trait::async_trait]
impl OpenIdConnectClientRepository for DeviceClientRepository {
    async fn find_by_oid(
        &self,
        _oid: ClientOid,
    ) -> Result<Option<OpenIdConnectClient>, OpenIdConnectClientRepositoryError> {
        Ok(Some(self.client.clone()))
    }
}

#[tokio::test]
async fn unknown_device_code_is_invalid_grant() {
    let mut repo = MockDeviceAuthorizationRepository::new();
    repo.expect_find_device_request_by_device_code_digest()
        .returning(|_| Ok(None));
    let service = build_service(device_client(vec![GrantType::DeviceCode]), Arc::new(repo));

    let error = service.exchange_device_code(params()).await.unwrap_err();

    assert_eq!(error.code(), 24062);
}

#[tokio::test]
async fn device_codes_of_other_clients_are_rejected() {
    let (repo, _records) = device_repo(
        request_record(
            DeviceRequestStatus::Pending,
            Utc::now() + Duration::minutes(10),
        ),
        None,
        DeviceRepoOptions {
            client_oid: Some(Uuid::new_v4()),
            ..DeviceRepoOptions::default()
        },
    );
    let service = build_service(device_client(vec![GrantType::DeviceCode]), repo);

    let error = service.exchange_device_code(params()).await.unwrap_err();

    assert_eq!(error.code(), 24063);
}

#[tokio::test]
async fn expired_requests_report_expired_token() {
    let (repo, _records) = device_repo(
        request_record(
            DeviceRequestStatus::Pending,
            Utc::now() - Duration::seconds(1),
        ),
        None,
        DeviceRepoOptions::default(),
    );
    let service = build_service(device_client(vec![GrantType::DeviceCode]), repo);

    let error = service.exchange_device_code(params()).await.unwrap_err();

    assert_eq!(error.code(), 24067);
}

#[tokio::test]
async fn pending_requests_report_authorization_pending() {
    let (repo, _records) = device_repo(
        request_record(
            DeviceRequestStatus::Pending,
            Utc::now() + Duration::minutes(10),
        ),
        None,
        DeviceRepoOptions::default(),
    );
    let sink = Arc::new(RecordingSink::default());
    let service =
        build_service(device_client(vec![GrantType::DeviceCode]), repo).with_events(sink.clone());

    let error = service.exchange_device_code(params()).await.unwrap_err();

    assert_eq!(error.code(), 24064);
    sink.assert_attribute(
        "token.device_code.result",
        "rejected",
        "request_oid",
        EventValue::Text("11111111-1111-1111-1111-111111111111".to_owned()),
    );
}

#[tokio::test]
async fn too_frequent_polling_reports_slow_down() {
    let (repo, _records) = device_repo(
        request_record(
            DeviceRequestStatus::Pending,
            Utc::now() + Duration::minutes(10),
        ),
        None,
        DeviceRepoOptions {
            poll: Some(DevicePollOutcome::TooFrequent),
            ..DeviceRepoOptions::default()
        },
    );
    let service = build_service(device_client(vec![GrantType::DeviceCode]), repo);

    let error = service.exchange_device_code(params()).await.unwrap_err();

    assert_eq!(error.code(), 24065);
}

#[tokio::test]
async fn denied_requests_report_access_denied() {
    let (repo, _records) = device_repo(
        request_record(
            DeviceRequestStatus::Denied,
            Utc::now() + Duration::minutes(10),
        ),
        None,
        DeviceRepoOptions::default(),
    );
    let service = build_service(device_client(vec![GrantType::DeviceCode]), repo);

    let error = service.exchange_device_code(params()).await.unwrap_err();

    assert_eq!(error.code(), 24066);
}

#[tokio::test]
async fn consumed_requests_report_invalid_grant() {
    let (repo, _records) = device_repo(
        request_record(
            DeviceRequestStatus::Consumed,
            Utc::now() + Duration::minutes(10),
        ),
        None,
        DeviceRepoOptions::default(),
    );
    let service = build_service(device_client(vec![GrantType::DeviceCode]), repo);

    let error = service.exchange_device_code(params()).await.unwrap_err();

    assert_eq!(error.code(), 24062);
}

#[tokio::test]
async fn an_approved_request_issues_its_token_set_once() {
    let sink = Arc::new(RecordingSink::default());
    let (repo, mut records) = device_repo(
        request_record(
            DeviceRequestStatus::Approved,
            Utc::now() + Duration::minutes(10),
        ),
        Some(relation_record(false)),
        DeviceRepoOptions::default(),
    );
    let service = build_service(
        device_client(vec![GrantType::DeviceCode, GrantType::RefreshToken]),
        repo,
    )
    .with_events(sink.clone());

    let mut request = params();
    request.resources = vec![API_RESOURCE.to_owned()];
    let response = service.exchange_device_code(request).await.unwrap();

    assert_eq!(response.scope, "openid offline_access");
    let access_token = decode_unverified_payload(&response.access_token);
    assert_eq!(access_token["aud"], API_RESOURCE);
    assert_eq!(access_token["sub"], Uuid::nil().to_string());
    assert_eq!(access_token["client_id"], Uuid::nil().to_string());
    assert_eq!(access_token["auth_time"], 1_700_000_000);
    assert!(
        access_token.get("sid").is_none(),
        "device tokens must not carry a forged browser session"
    );

    let id_token = response.id_token.as_ref().unwrap();
    let id_claims = decode_unverified_payload(id_token);
    assert_eq!(id_claims["aud"], Uuid::nil().to_string());
    assert!(id_claims.get("sid").is_none());

    let stored = records.try_recv().unwrap();
    for record in &stored {
        let field = match record.data {
            ClientAuthorizationData::AccessToken(_) => "access_token_oid",
            ClientAuthorizationData::RefreshToken(_) => "refresh_token_oid",
            _ => panic!("unexpected token record"),
        };
        sink.assert_attribute(
            "token.device_code.issued",
            "success",
            field,
            EventValue::Text(record.oid.to_string()),
        );
    }
    sink.assert_attribute(
        "token.device_code.issued",
        "success",
        "request_oid",
        EventValue::Text("11111111-1111-1111-1111-111111111111".to_owned()),
    );
    assert_eq!(
        stored.len(),
        2,
        "access and refresh records are committed together"
    );
    let mut found_access = false;
    let mut found_refresh = false;
    for record in &stored {
        match &record.data {
            ClientAuthorizationData::AccessToken(data) => {
                found_access = true;
                assert!(data.session_oid.is_none());
                assert_eq!(
                    data.device_authorization_oid.as_deref(),
                    Some("33333333-3333-3333-3333-333333333333")
                );
            }
            ClientAuthorizationData::RefreshToken(data) => {
                found_refresh = true;
                assert_eq!(data.resources, [API_RESOURCE]);
                assert!(data.session_oid.is_none());
                assert_eq!(
                    data.device_authorization_oid.as_deref(),
                    Some("33333333-3333-3333-3333-333333333333")
                );
            }
            other => panic!("unexpected record {other:?}"),
        }
    }
    assert!(found_access && found_refresh);
    assert!(response.refresh_token.is_some());
}

#[tokio::test]
async fn offline_access_without_the_refresh_grant_issues_no_refresh_token() {
    let (repo, mut records) = device_repo(
        request_record(
            DeviceRequestStatus::Approved,
            Utc::now() + Duration::minutes(10),
        ),
        Some(relation_record(false)),
        DeviceRepoOptions::default(),
    );
    let service = build_service(device_client(vec![GrantType::DeviceCode]), repo);

    let response = service.exchange_device_code(params()).await.unwrap();

    assert!(response.refresh_token.is_none());
    let stored = records.try_recv().unwrap();
    assert_eq!(stored.len(), 1);
}

#[tokio::test]
async fn revoked_authorizations_report_access_denied() {
    let (repo, _records) = device_repo(
        request_record(
            DeviceRequestStatus::Approved,
            Utc::now() + Duration::minutes(10),
        ),
        Some(relation_record(true)),
        DeviceRepoOptions::default(),
    );
    let service = build_service(device_client(vec![GrantType::DeviceCode]), repo);

    let error = service.exchange_device_code(params()).await.unwrap_err();

    assert_eq!(error.code(), 24068);
}

#[tokio::test]
async fn a_lost_redemption_race_reports_invalid_grant_without_tokens() {
    let (repo, _records) = device_repo(
        request_record(
            DeviceRequestStatus::Approved,
            Utc::now() + Duration::minutes(10),
        ),
        Some(relation_record(false)),
        DeviceRepoOptions {
            consume: Some(DeviceConsumeOutcome::NotRedeemable),
            ..DeviceRepoOptions::default()
        },
    );
    let service = build_service(device_client(vec![GrantType::DeviceCode]), repo);

    let error = service.exchange_device_code(params()).await.unwrap_err();

    assert_eq!(error.code(), 24062);
}

#[tokio::test]
async fn a_revocation_racing_the_redemption_reports_access_denied() {
    let (repo, _records) = device_repo(
        request_record(
            DeviceRequestStatus::Approved,
            Utc::now() + Duration::minutes(10),
        ),
        Some(relation_record(false)),
        DeviceRepoOptions {
            consume: Some(DeviceConsumeOutcome::AuthorizationRevoked),
            ..DeviceRepoOptions::default()
        },
    );
    let service = build_service(device_client(vec![GrantType::DeviceCode]), repo);

    let error = service.exchange_device_code(params()).await.unwrap_err();

    assert_eq!(error.code(), 24068);
}

#[tokio::test]
async fn clients_without_the_device_grant_cannot_redeem() {
    let mut repo = MockDeviceAuthorizationRepository::new();
    repo.expect_find_device_request_by_device_code_digest()
        .returning(|_| Ok(None));
    let service = build_service(
        device_client(vec![GrantType::AuthorizationCode]),
        Arc::new(repo),
    );

    let error = service.exchange_device_code(params()).await.unwrap_err();

    assert_eq!(error.code(), 24061);
}

#[tokio::test]
async fn redemption_requires_client_authentication() {
    let mut repo = MockDeviceAuthorizationRepository::new();
    repo.expect_find_device_request_by_device_code_digest()
        .returning(|_| Ok(None));
    let service = build_service(device_client(vec![GrantType::DeviceCode]), Arc::new(repo));

    let error = service
        .exchange_device_code(DeviceCodeGrantParams {
            resources: Vec::new(),
            client_secret: None,
            client_secret_basic: false,
            ..params()
        })
        .await
        .unwrap_err();

    assert_eq!(error.code(), 24031);
}

#[tokio::test]
async fn registered_public_client_redeems_device_code_without_secret() {
    let mut repo = MockDeviceAuthorizationRepository::new();
    repo.expect_find_device_request_by_device_code_digest()
        .returning(|_| Ok(None));
    let service = build_service(public_device_client(), Arc::new(repo));

    let error = service
        .exchange_device_code(DeviceCodeGrantParams {
            resources: Vec::new(),
            client_secret: None,
            client_secret_basic: false,
            ..params()
        })
        .await
        .unwrap_err();

    assert_eq!(error.code(), 24062);
}

/// Builds a device refresh token whose original authorization had `scope`.
async fn device_refresh_token(repo: &Arc<MockClientAuthorizationRepository>, scope: &str) -> Uuid {
    let refresh_data = RefreshTokenData {
        resources: Vec::new(),
        scope: scope.to_owned(),
        user_oid: Uuid::nil().to_string(),
        session_oid: None,
        protected_session_id: None,
        auth_time: Some(1_700_000_000),
        acr: None,
        amr: vec!["pwd".to_owned()],
        rotated_from: None,
        authorization_code_oid: None,
        device_authorization_oid: Some("33333333-3333-3333-3333-333333333333".to_owned()),
        client_authentication_mode: None,
    };
    let record = repo
        .create(
            Uuid::nil(),
            ClientAuthorizationData::RefreshToken(refresh_data),
            Utc::now() + Duration::days(30),
        )
        .await
        .unwrap();

    record.oid
}

#[tokio::test]
async fn a_device_grant_without_openid_stays_plain_oauth_through_refresh() {
    let repo = Arc::new(mock_client_auth_repo());
    let oid = device_refresh_token(&repo, "offline_access").await;
    let mut device_repo = MockDeviceAuthorizationRepository::new();
    let live = relation_record(false);
    device_repo
        .expect_find_device_authorization_by_oid()
        .returning(move |_| Ok(Some(live.clone())));
    let service = build_token_service_with_device_repo(
        repo,
        Uuid::nil(),
        Arc::new(DeviceClientRepository {
            client: device_client(vec![GrantType::DeviceCode, GrantType::RefreshToken]),
        }),
        Arc::new(device_repo),
    );

    let refreshed = service
        .exchange_refresh_token(RefreshTokenGrantParams {
            resources: Vec::new(),
            scope: None,
            refresh_token: STANDARD.encode(oid.as_bytes()),
            client_id: Some(Uuid::nil().to_string()),
            client_secret: Some("secret-123".to_owned()),
            client_secret_basic: true,
            client_assertion_type: None,
            client_assertion: None,
        })
        .await
        .unwrap();

    assert_eq!(refreshed.scope, "offline_access");
    assert!(
        refreshed.id_token.is_none(),
        "an authorization that never requested openid may not gain an ID token by refreshing"
    );
}

#[tokio::test]
async fn refresh_cannot_add_openid_the_device_grant_never_requested() {
    let repo = Arc::new(mock_client_auth_repo());
    let oid = device_refresh_token(&repo, "offline_access").await;
    let mut device_repo = MockDeviceAuthorizationRepository::new();
    let live = relation_record(false);
    device_repo
        .expect_find_device_authorization_by_oid()
        .returning(move |_| Ok(Some(live.clone())));
    let service = build_token_service_with_device_repo(
        repo,
        Uuid::nil(),
        Arc::new(DeviceClientRepository {
            client: device_client(vec![GrantType::DeviceCode, GrantType::RefreshToken]),
        }),
        Arc::new(device_repo),
    );

    let error = service
        .exchange_refresh_token(RefreshTokenGrantParams {
            resources: Vec::new(),
            scope: Some("openid offline_access".to_owned()),
            refresh_token: STANDARD.encode(oid.as_bytes()),
            client_id: Some(Uuid::nil().to_string()),
            client_secret: Some("secret-123".to_owned()),
            client_secret_basic: true,
            client_assertion_type: None,
            client_assertion: None,
        })
        .await
        .unwrap_err();

    assert_eq!(
        error.code(),
        24074,
        "invalid_scope: a refresh may narrow, never widen"
    );
}

#[tokio::test]
async fn refresh_may_narrow_the_granted_scope() {
    let repo = Arc::new(mock_client_auth_repo());
    let oid = device_refresh_token(&repo, "openid offline_access").await;
    let mut device_repo = MockDeviceAuthorizationRepository::new();
    let live = relation_record(false);
    device_repo
        .expect_find_device_authorization_by_oid()
        .returning(move |_| Ok(Some(live.clone())));
    let service = build_token_service_with_device_repo(
        repo,
        Uuid::nil(),
        Arc::new(DeviceClientRepository {
            client: device_client(vec![GrantType::DeviceCode, GrantType::RefreshToken]),
        }),
        Arc::new(device_repo),
    );

    let refreshed = service
        .exchange_refresh_token(RefreshTokenGrantParams {
            resources: Vec::new(),
            scope: Some("openid".to_owned()),
            refresh_token: STANDARD.encode(oid.as_bytes()),
            client_id: Some(Uuid::nil().to_string()),
            client_secret: Some("secret-123".to_owned()),
            client_secret_basic: true,
            client_assertion_type: None,
            client_assertion: None,
        })
        .await
        .unwrap();

    assert_eq!(refreshed.scope, "openid");
    assert!(
        refreshed.id_token.is_some(),
        "dropping offline_access keeps the OIDC behavior"
    );
}

#[tokio::test]
async fn refreshing_a_device_token_requires_a_live_relation() {
    let refresh_data = RefreshTokenData {
        resources: Vec::new(),
        scope: "openid offline_access".to_owned(),
        user_oid: Uuid::nil().to_string(),
        session_oid: None,
        protected_session_id: None,
        auth_time: Some(1_700_000_000),
        acr: None,
        amr: vec!["pwd".to_owned()],
        rotated_from: None,
        authorization_code_oid: None,
        device_authorization_oid: Some("33333333-3333-3333-3333-333333333333".to_owned()),
        client_authentication_mode: None,
    };
    let repo = Arc::new(mock_client_auth_repo());
    let record = repo
        .create(
            Uuid::nil(),
            ClientAuthorizationData::RefreshToken(refresh_data),
            Utc::now() + Duration::days(30),
        )
        .await
        .unwrap();

    let mut device_repo = MockDeviceAuthorizationRepository::new();
    let revoked = relation_record(true);
    device_repo
        .expect_find_device_authorization_by_oid()
        .returning(move |_| Ok(Some(revoked.clone())));
    let service = build_token_service_with_device_repo(
        repo.clone(),
        Uuid::nil(),
        Arc::new(DeviceClientRepository {
            client: device_client(vec![GrantType::DeviceCode, GrantType::RefreshToken]),
        }),
        Arc::new(device_repo),
    );

    let error = service
        .exchange_refresh_token(RefreshTokenGrantParams {
            resources: Vec::new(),
            scope: None,
            refresh_token: STANDARD.encode(record.oid.as_bytes()),
            client_id: Some(Uuid::nil().to_string()),
            client_secret: Some("secret-123".to_owned()),
            client_secret_basic: true,
            client_assertion_type: None,
            client_assertion: None,
        })
        .await
        .unwrap_err();

    assert_eq!(error.code(), 24015, "invalid_grant for a revoked relation");
    let stored = repo.find_by_oid(record.oid).await.unwrap().unwrap();
    assert!(
        stored.revoked_at.is_none(),
        "a rejected refresh must not consume the token"
    );
}

#[tokio::test]
async fn a_live_relation_allows_refreshing_a_device_token() {
    let refresh_data = RefreshTokenData {
        resources: Vec::new(),
        scope: "openid offline_access".to_owned(),
        user_oid: Uuid::nil().to_string(),
        session_oid: None,
        protected_session_id: None,
        auth_time: Some(1_700_000_000),
        acr: Some("urn:identity:acr:aal1".to_owned()),
        amr: vec!["pwd".to_owned()],
        rotated_from: None,
        authorization_code_oid: None,
        device_authorization_oid: Some("33333333-3333-3333-3333-333333333333".to_owned()),
        client_authentication_mode: None,
    };
    let repo = Arc::new(mock_client_auth_repo());
    let record = repo
        .create(
            Uuid::nil(),
            ClientAuthorizationData::RefreshToken(refresh_data),
            Utc::now() + Duration::days(30),
        )
        .await
        .unwrap();

    let mut device_repo = MockDeviceAuthorizationRepository::new();
    let live = relation_record(false);
    device_repo
        .expect_find_device_authorization_by_oid()
        .returning(move |_| Ok(Some(live.clone())));
    let service = build_token_service_with_device_repo(
        repo.clone(),
        Uuid::nil(),
        Arc::new(DeviceClientRepository {
            client: device_client(vec![GrantType::DeviceCode, GrantType::RefreshToken]),
        }),
        Arc::new(device_repo),
    );

    let refreshed = service
        .exchange_refresh_token(RefreshTokenGrantParams {
            resources: Vec::new(),
            scope: None,
            refresh_token: STANDARD.encode(record.oid.as_bytes()),
            client_id: Some(Uuid::nil().to_string()),
            client_secret: Some("secret-123".to_owned()),
            client_secret_basic: true,
            client_assertion_type: None,
            client_assertion: None,
        })
        .await
        .unwrap();

    assert!(refreshed.id_token.is_some());
    let rotated_oid = Uuid::from_slice(
        &STANDARD
            .decode(refreshed.refresh_token.as_ref().unwrap())
            .unwrap(),
    )
    .unwrap();
    let rotated = repo.find_by_oid(rotated_oid).await.unwrap().unwrap();
    let ClientAuthorizationData::RefreshToken(rotated) = rotated.data else {
        panic!("expected a refresh token");
    };
    assert!(rotated.session_oid.is_none());
    assert_eq!(
        rotated.device_authorization_oid.as_deref(),
        Some("33333333-3333-3333-3333-333333333333"),
        "the rotated token stays bound to the device relation"
    );
    let refreshed_access_claims = decode_unverified_payload(&refreshed.access_token);
    assert!(
        refreshed_access_claims.get("sid").is_none(),
        "refreshed device tokens carry no browser session either"
    );
}
