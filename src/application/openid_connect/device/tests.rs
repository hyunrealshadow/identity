use std::sync::Arc;

use chrono::{DateTime, Utc};
use uuid::Uuid;

use crate::application::error::{
    code::AppErrorCode, codes::device::DeviceAuthorizationErrorCode, codes::token::TokenErrorCode,
};
use crate::application::setting::runtime::SettingProvider;
use crate::domain::client::model::ClientOid;
use crate::domain::client_authorization::{
    ClientAuthorization, ClientAuthorizationData, ClientAuthorizationRepositoryError,
    ClientAuthorizationType, DeviceAuthorizationRepositoryError, DeviceAuthorizationRequestData,
    device_code_digest,
};
use crate::domain::openid_connect::{
    ClientAssertionType, GrantType, OpenIdConnectClient, OpenIdConnectClientRepository,
    OpenIdConnectClientRepositoryError, OpenIdConnectCredential, OpenIdConnectCredentialData,
    OpenIdConnectCredentialType, TokenEndpointAuthMethod,
};
use crate::domain::setting::installation::{InstallationSetting, InstallationState};
use crate::domain::setting::{
    DeviceAuthorizationSetting, DeviceAuthorizationSettings, LoginDomainSetting,
};
use crate::openid_connect::device::{
    DEVICE_VERIFICATION_PATH, DeviceAuthorizationParams, DeviceAuthorizationService,
    DeviceAuthorizationServiceDependencies, DeviceVerificationDecision, DeviceVerificationStatus,
    DeviceVerificationUser,
};
use crate::openid_connect::tests::fixtures::client::{
    test_client, test_metadata, test_platforms, test_scopes,
};
use crate::openid_connect::tests::fixtures::mocks::{
    MockDeviceAuthorizationRepository, MockOpenIdConnectCredentialRepository,
};
use crate::openid_connect::{
    client_authentication::{ClientAuthenticator, ClientAuthenticatorDependencies},
    provider::OpenIdProviderService,
};

const CLIENT_ID: Uuid = Uuid::nil();

struct StaticInstallationProvider {
    value: Arc<InstallationState>,
}

impl SettingProvider<InstallationSetting> for StaticInstallationProvider {
    fn current_value(&self) -> Arc<InstallationState> {
        self.value.clone()
    }
}

struct StaticLoginDomainProvider {
    value: Option<String>,
}

impl SettingProvider<LoginDomainSetting> for StaticLoginDomainProvider {
    fn current_value(&self) -> Arc<Option<String>> {
        Arc::new(self.value.clone())
    }
}

struct StaticDeviceAuthorizationProvider {
    value: Arc<DeviceAuthorizationSettings>,
}

impl SettingProvider<DeviceAuthorizationSetting> for StaticDeviceAuthorizationProvider {
    fn current_value(&self) -> Arc<DeviceAuthorizationSettings> {
        self.value.clone()
    }
}

fn provider_service() -> Arc<OpenIdProviderService> {
    Arc::new(OpenIdProviderService::new(Arc::new(
        StaticInstallationProvider {
            value: Arc::new(InstallationState {
                initialized: true,
                domain: Some("https://identity.example.com".to_owned()),
                first_user_oid: Some(Uuid::new_v4()),
                first_key_oid: Some(Uuid::new_v4()),
                initialized_at: Some(Utc::now()),
            }),
        },
    )))
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

fn device_client(grant_types: Vec<GrantType>, public: bool) -> OpenIdConnectClient {
    let mut metadata = test_metadata(None, public.then_some("none"));
    metadata.grant_types = Some(grant_types);
    if public {
        metadata.token_endpoint_auth_method = Some(TokenEndpointAuthMethod::None);
    }

    OpenIdConnectClient::new(
        test_client(CLIENT_ID),
        metadata,
        test_platforms(),
        test_scopes(),
    )
    .unwrap()
}

fn client_secret_credential() -> OpenIdConnectCredential {
    OpenIdConnectCredential {
        oid: Uuid::new_v4(),
        client_oid: CLIENT_ID,
        r#type: OpenIdConnectCredentialType::ClientSecret,
        hint: "token".to_owned(),
        data: OpenIdConnectCredentialData::ClientSecret {
            secret: "secret-123".to_owned(),
        },
        expires_at: Utc::now() + chrono::Duration::days(1),
        revoked_at: None,
        created_at: Utc::now(),
        updated_at: None,
    }
}

/// Builds the service under test around the caller's repository mocks.
fn build_service(
    client: OpenIdConnectClient,
    device_repo: Arc<MockDeviceAuthorizationRepository>,
) -> DeviceAuthorizationService {
    build_service_with_login_domain(client, device_repo, None)
}

/// Builds the service with the login application domain recorded at install
/// time.
fn build_service_with_login_domain(
    client: OpenIdConnectClient,
    device_repo: Arc<MockDeviceAuthorizationRepository>,
    login_domain: Option<&str>,
) -> DeviceAuthorizationService {
    build_service_with_credential(
        client,
        device_repo,
        DeviceAuthorizationSettings::default(),
        client_secret_credential(),
        login_domain,
    )
}

fn build_service_with_settings(
    client: OpenIdConnectClient,
    device_repo: Arc<MockDeviceAuthorizationRepository>,
    settings: DeviceAuthorizationSettings,
) -> DeviceAuthorizationService {
    build_service_with_credential(
        client,
        device_repo,
        settings,
        client_secret_credential(),
        None,
    )
}

fn build_service_with_credential(
    client: OpenIdConnectClient,
    device_repo: Arc<MockDeviceAuthorizationRepository>,
    settings: DeviceAuthorizationSettings,
    credential: OpenIdConnectCredential,
    login_domain: Option<&str>,
) -> DeviceAuthorizationService {
    let mut credential_repo = MockOpenIdConnectCredentialRepository::new();
    credential_repo
        .expect_find_active_by_client_oid_and_type()
        .returning(move |_, _| Ok(vec![credential.clone()]));

    let client_repo: Arc<dyn OpenIdConnectClientRepository> =
        Arc::new(DeviceClientRepository { client });
    let authenticator = Arc::new(ClientAuthenticator::new(ClientAuthenticatorDependencies {
        client_repo: Arc::clone(&client_repo),
        credential_repo: Arc::new(credential_repo),
        provider_service: provider_service(),
    }));

    DeviceAuthorizationService::new(DeviceAuthorizationServiceDependencies {
        client_authentication: authenticator,
        client_repo,
        device_repo,
        provider_service: provider_service(),
        login_domain: Arc::new(StaticLoginDomainProvider {
            value: login_domain.map(str::to_owned),
        }),
        settings: Arc::new(StaticDeviceAuthorizationProvider {
            value: Arc::new(settings),
        }),
    })
}

fn request_record(
    client_oid: ClientOid,
    data: DeviceAuthorizationRequestData,
    expires_at: DateTime<Utc>,
) -> ClientAuthorization {
    ClientAuthorization {
        oid: Uuid::new_v4(),
        client_oid,
        type_: ClientAuthorizationType::DeviceAuthorizationRequest,
        data: ClientAuthorizationData::DeviceAuthorizationRequest(data),
        expires_at,
        completed_at: None,
        revoked_at: None,
        created_at: Utc::now(),
        updated_at: None,
    }
}

/// Device repository mock that accepts one request and reports it back.
fn accepting_device_repo() -> (
    Arc<MockDeviceAuthorizationRepository>,
    tokio::sync::mpsc::UnboundedReceiver<DeviceAuthorizationRequestData>,
) {
    let (sender, receiver) = tokio::sync::mpsc::unbounded_channel();
    let mut repo = MockDeviceAuthorizationRepository::new();
    repo.expect_create_device_request()
        .returning(move |client_oid, data, expires_at| {
            let _ = sender.send(data.clone());
            Ok(request_record(client_oid, data, expires_at))
        });

    (Arc::new(repo), receiver)
}

fn params(client_secret: Option<&str>, scope: Option<&str>) -> DeviceAuthorizationParams {
    DeviceAuthorizationParams {
        client_id: Some(CLIENT_ID.to_string()),
        client_secret: client_secret.map(str::to_owned),
        client_assertion_type: None,
        client_assertion: None,
        scope: scope.map(str::to_owned),
    }
}

fn device_grant() -> Vec<GrantType> {
    vec![GrantType::DeviceCode]
}

#[tokio::test]
async fn request_returns_rfc_8628_fields_and_stores_only_the_digest() {
    let (device_repo, mut created) = accepting_device_repo();
    let service = build_service(device_client(device_grant(), false), device_repo);

    let response = service
        .authorize(params(Some("secret-123"), Some("openid offline_access")))
        .await
        .unwrap();

    assert_eq!(response.expires_in, 600);
    assert_eq!(response.interval, 5);
    assert_eq!(
        response.verification_uri,
        format!("https://identity.example.com/{DEVICE_VERIFICATION_PATH}"),
        "without an application URL the issuer host serves the page"
    );
    assert_eq!(
        response.verification_uri_complete,
        format!(
            "https://identity.example.com/{DEVICE_VERIFICATION_PATH}?user_code={}",
            response.user_code
        )
    );
    assert_eq!(response.user_code.len(), 9, "grouped as four and four");
    assert_eq!(response.user_code.chars().filter(|c| *c == '-').count(), 1);
    assert!(response.device_code.len() >= 43, "256 bits of base64url");

    let stored = created.try_recv().unwrap();
    assert_eq!(
        stored.status,
        crate::domain::client_authorization::DeviceRequestStatus::Pending
    );
    assert_eq!(stored.scope, "openid offline_access");
    assert_eq!(
        stored.device_code_digest,
        device_code_digest(&response.device_code)
    );
    assert!(
        !stored.device_code_digest.contains(&response.device_code),
        "the raw device code is never stored"
    );
    assert_eq!(
        stored.user_code,
        response.user_code.replace('-', ""),
        "the stored code is the normalized lookup form"
    );
}

#[tokio::test]
async fn request_scopes_and_lifetime_come_from_settings() {
    let (device_repo, mut created) = accepting_device_repo();
    let service = build_service_with_settings(
        device_client(device_grant(), false),
        device_repo,
        DeviceAuthorizationSettings {
            request_ttl_seconds: 120,
            polling_interval_seconds: 10,
        },
    );

    let response = service
        .authorize(params(Some("secret-123"), Some("openid")))
        .await
        .unwrap();

    assert_eq!(response.expires_in, 120);
    assert_eq!(response.interval, 10);

    let stored = created.try_recv().unwrap();
    assert_eq!(stored.interval_seconds, 10);
    assert!(stored.last_polled_at.is_none());
}

/// Client registered for `private_key_jwt` and the matching credential.
fn private_key_jwt_client(public_key: String) -> (OpenIdConnectClient, OpenIdConnectCredential) {
    let mut metadata = test_metadata(None, Some("private_key_jwt"));
    metadata.grant_types = Some(vec![GrantType::DeviceCode]);
    let client = OpenIdConnectClient::new(
        test_client(CLIENT_ID),
        metadata,
        test_platforms(),
        test_scopes(),
    )
    .unwrap();
    let credential = OpenIdConnectCredential {
        oid: Uuid::new_v4(),
        client_oid: CLIENT_ID,
        r#type: OpenIdConnectCredentialType::ClientPublicKey,
        hint: "private_key_jwt".to_owned(),
        data: OpenIdConnectCredentialData::ClientPublicKey {
            public_key,
            jwk: None,
        },
        expires_at: Utc::now() + chrono::Duration::days(1),
        revoked_at: None,
        created_at: Utc::now(),
        updated_at: None,
    };

    (client, credential)
}

/// An assertion as a confidential client library signs it.
fn sign_assertion(private_key: &str, client_id: Uuid) -> String {
    sign_assertion_with_audience(
        private_key,
        client_id,
        "https://identity.example.com/oauth2/token",
    )
}

fn sign_assertion_with_audience(private_key: &str, client_id: Uuid, audience: &str) -> String {
    use josekit::jws::{JwsHeader, RS256};
    use josekit::jwt::{self, JwtPayload};

    let mut header = JwsHeader::new();
    header.set_token_type("JWT");
    let mut payload = JwtPayload::new();
    let now = std::time::SystemTime::now();
    payload.set_issuer(client_id.to_string());
    payload.set_subject(client_id.to_string());
    payload.set_audience(vec![audience]);
    payload.set_issued_at(&now);
    payload.set_expires_at(&(now + std::time::Duration::from_secs(300)));
    payload.set_jwt_id(Uuid::new_v4().to_string());

    jwt::encode_with_signer(
        &payload,
        &header,
        &*RS256.signer_from_pem(private_key.as_bytes()).unwrap(),
    )
    .unwrap()
}

fn key_pair() -> (String, String) {
    let rsa = openssl::rsa::Rsa::generate(2048).unwrap();
    let private_key = String::from_utf8(rsa.private_key_to_pem().unwrap()).unwrap();
    let public_key = String::from_utf8(rsa.public_key_to_pem().unwrap()).unwrap();

    (private_key, public_key)
}

#[tokio::test]
async fn request_authenticates_a_jwt_client_without_a_separate_client_id() {
    let (private_key, public_key) = key_pair();
    let (client, credential) = private_key_jwt_client(public_key);
    let (device_repo, _created) = accepting_device_repo();
    let service = build_service_with_credential(
        client,
        device_repo,
        DeviceAuthorizationSettings::default(),
        credential,
        None,
    );

    let response = service
        .authorize(DeviceAuthorizationParams {
            // RFC 7523 §2.2: the assertion identifies the client on its own.
            client_assertion_type: Some(ClientAssertionType::JwtBearer),
            client_assertion: Some(sign_assertion(&private_key, CLIENT_ID)),
            ..DeviceAuthorizationParams::default()
        })
        .await
        .unwrap();

    assert_eq!(response.expires_in, 600);
    assert!(response.verification_uri.ends_with("/device"));
}

#[tokio::test]
async fn request_rejects_an_assertion_signed_by_another_key() {
    let (_, public_key) = key_pair();
    let (other_private_key, _) = key_pair();
    let (client, credential) = private_key_jwt_client(public_key);
    let service = build_service_with_credential(
        client,
        Arc::new(MockDeviceAuthorizationRepository::new()),
        DeviceAuthorizationSettings::default(),
        credential,
        None,
    );

    let error = service
        .authorize(DeviceAuthorizationParams {
            client_assertion_type: Some(ClientAssertionType::JwtBearer),
            client_assertion: Some(sign_assertion(&other_private_key, CLIENT_ID)),
            ..DeviceAuthorizationParams::default()
        })
        .await
        .unwrap_err();

    assert_eq!(
        error.code(),
        TokenErrorCode::AssertionVerifyFailed.code(),
        "an assertion signed by a foreign key authenticates nothing"
    );
}

#[tokio::test]
async fn request_rejects_an_assertion_for_another_audience() {
    let (private_key, public_key) = key_pair();
    let (client, credential) = private_key_jwt_client(public_key);
    let service = build_service_with_credential(
        client,
        Arc::new(MockDeviceAuthorizationRepository::new()),
        DeviceAuthorizationSettings::default(),
        credential,
        None,
    );
    let foreign_audience = sign_assertion_with_audience(
        &private_key,
        CLIENT_ID,
        "https://other.example.com/oauth2/token",
    );

    let error = service
        .authorize(DeviceAuthorizationParams {
            client_assertion_type: Some(ClientAssertionType::JwtBearer),
            client_assertion: Some(foreign_audience),
            ..DeviceAuthorizationParams::default()
        })
        .await
        .unwrap_err();

    assert_eq!(error.code(), TokenErrorCode::AssertionAudMismatch.code());
}

#[tokio::test]
async fn request_requires_client_id() {
    let service = build_service(
        device_client(device_grant(), false),
        Arc::new(MockDeviceAuthorizationRepository::new()),
    );

    let error = service
        .authorize(DeviceAuthorizationParams::default())
        .await
        .unwrap_err();

    assert_eq!(
        error.code(),
        24001,
        "client identification without an assertion is missing a client_id"
    );
}

#[tokio::test]
async fn confidential_client_without_credentials_is_rejected() {
    let service = build_service(
        device_client(device_grant(), false),
        Arc::new(MockDeviceAuthorizationRepository::new()),
    );

    let error = service.authorize(params(None, None)).await.unwrap_err();

    assert_eq!(error.code(), 24031, "client authentication is required");
}

#[tokio::test]
async fn confidential_client_with_wrong_secret_is_rejected() {
    let service = build_service(
        device_client(device_grant(), false),
        Arc::new(MockDeviceAuthorizationRepository::new()),
    );

    let error = service
        .authorize(params(Some("wrong-secret"), None))
        .await
        .unwrap_err();

    assert_eq!(error.code(), 24030);
}

#[tokio::test]
async fn registered_public_client_authenticates_with_client_id_only() {
    let (device_repo, _created) = accepting_device_repo();
    let service = build_service(device_client(device_grant(), true), device_repo);

    let response = service.authorize(params(None, None)).await.unwrap();

    assert!(!response.device_code.is_empty());
}

#[tokio::test]
async fn client_without_device_grant_is_rejected() {
    let service = build_service(
        device_client(vec![GrantType::AuthorizationCode], false),
        Arc::new(MockDeviceAuthorizationRepository::new()),
    );

    let error = service
        .authorize(params(Some("secret-123"), None))
        .await
        .unwrap_err();

    assert_eq!(
        error.code(),
        DeviceAuthorizationErrorCode::GrantNotAllowed.code()
    );
}

#[tokio::test]
async fn scope_must_be_assigned_to_the_client() {
    let service = build_service(
        device_client(device_grant(), false),
        Arc::new(MockDeviceAuthorizationRepository::new()),
    );

    let error = service
        .authorize(params(Some("secret-123"), Some("openid account.update")))
        .await
        .unwrap_err();

    assert_eq!(
        error.code(),
        DeviceAuthorizationErrorCode::ScopeNotAssignedToClient.code()
    );
}

#[tokio::test]
async fn unparsable_scope_is_rejected() {
    let service = build_service(
        device_client(device_grant(), false),
        Arc::new(MockDeviceAuthorizationRepository::new()),
    );

    let error = service
        .authorize(params(Some("secret-123"), Some("openid unknown_scope")))
        .await
        .unwrap_err();

    assert_eq!(
        error.code(),
        DeviceAuthorizationErrorCode::ScopeInvalid.code()
    );
}

#[tokio::test]
async fn user_code_collision_is_retried() {
    let (sender, mut receiver) = tokio::sync::mpsc::unbounded_channel();
    let mut device_repo = MockDeviceAuthorizationRepository::new();
    device_repo
        .expect_create_device_request()
        .times(1)
        .returning(|_, _, _| Err(DeviceAuthorizationRepositoryError::UserCodeConflict));
    device_repo
        .expect_create_device_request()
        .returning(move |client_oid, data, expires_at| {
            let _ = sender.send(data.clone());
            Ok(request_record(client_oid, data, expires_at))
        });
    let service = build_service(device_client(device_grant(), false), Arc::new(device_repo));

    let response = service
        .authorize(params(Some("secret-123"), None))
        .await
        .unwrap();

    assert!(receiver.try_recv().is_ok(), "the request was retried");
    assert!(!response.user_code.is_empty());
}

#[tokio::test]
async fn storage_failures_surface_as_server_errors() {
    let mut device_repo = MockDeviceAuthorizationRepository::new();
    device_repo
        .expect_create_device_request()
        .returning(|_, _, _| {
            Err(DeviceAuthorizationRepositoryError::QueryFailed(Box::new(
                ClientAuthorizationRepositoryError::QueryFailed(Box::new(std::io::Error::other(
                    "database unavailable",
                ))),
            )))
        });
    let service = build_service(device_client(device_grant(), false), Arc::new(device_repo));

    let error = service
        .authorize(params(Some("secret-123"), None))
        .await
        .unwrap_err();

    assert_eq!(
        error.code(),
        DeviceAuthorizationErrorCode::StoreRequestFailed.code()
    );
    assert!(matches!(
        error.kind(),
        crate::application::error::kind::ErrorKind::Internal
    ));
}

fn skip_consent_device_client() -> OpenIdConnectClient {
    let mut metadata = test_metadata(None, Some("client_secret_basic"));
    metadata.grant_types = Some(vec![GrantType::DeviceCode]);
    metadata.settings.skip_consent = true;
    metadata.client_uri = Some(url::Url::parse("https://client.example.com").unwrap());
    metadata.logo_uri = Some(url::Url::parse("https://client.example.com/logo.png").unwrap());

    OpenIdConnectClient::new(
        test_client(CLIENT_ID),
        metadata,
        test_platforms(),
        test_scopes(),
    )
    .unwrap()
}

fn pending_record(user_code: &str, scope: &str, expires_at: DateTime<Utc>) -> ClientAuthorization {
    request_record(
        CLIENT_ID,
        DeviceAuthorizationRequestData {
            scope: scope.to_owned(),
            device_code_digest: device_code_digest("device-code"),
            user_code: user_code.to_owned(),
            user_code_display: crate::domain::client_authorization::format_user_code(user_code),
            interval_seconds: 5,
            slow_down_seconds: 0,
            last_polled_at: None,
            status: crate::domain::client_authorization::DeviceRequestStatus::Pending,
            approval: None,
            denied_by_user_oid: None,
            decided_at: None,
            device_authorization_oid: None,
        },
        expires_at,
    )
}

fn device_repo_with(record: ClientAuthorization) -> Arc<MockDeviceAuthorizationRepository> {
    let mut repo = MockDeviceAuthorizationRepository::new();
    repo.expect_find_active_device_request_by_user_code()
        .returning(move |_| Ok(Some(record.clone())));

    Arc::new(repo)
}

fn verification_user() -> DeviceVerificationUser {
    DeviceVerificationUser {
        user_oid: Uuid::parse_str("22222222-2222-2222-2222-222222222222").unwrap(),
        auth_time: Some(1_700_000_000),
        acr: Some("urn:identity:acr:aal1".to_owned()),
        amr: vec!["pwd".to_owned()],
    }
}

#[tokio::test]
async fn describe_reports_the_pending_request_to_the_user() {
    let record = pending_record(
        "WDJBMJHT",
        "openid profile",
        Utc::now() + chrono::Duration::minutes(10),
    );
    let service = build_service(
        device_client(device_grant(), false),
        device_repo_with(record),
    );

    let description = service.describe_verification("wdjb-mjht").await.unwrap();

    assert_eq!(description.status, DeviceVerificationStatus::Pending);
    assert_eq!(description.user_code, "WDJB-MJHT");
    assert_eq!(description.client_name, "Example RP");
    assert_eq!(description.scopes, vec!["openid", "profile"]);
    assert!(
        description.consent_required,
        "a normal client needs a per-request consent"
    );
}

#[tokio::test]
async fn describe_never_changes_authorization_state() {
    let record = pending_record(
        "WDJBMJHT",
        "openid",
        Utc::now() + chrono::Duration::minutes(10),
    );
    // A trusted client would be auto approved by an eager implementation; the
    // mock panics if the read path calls the approve transition at all.
    let service = build_service(skip_consent_device_client(), device_repo_with(record));

    let description = service.describe_verification("WDJBMJHT").await.unwrap();

    assert_eq!(
        description.status,
        DeviceVerificationStatus::Pending,
        "a GET style lookup must not approve the request"
    );
    assert!(
        !description.consent_required,
        "the UI may approve a trusted client without asking the user"
    );
    assert_eq!(
        description.client_uri.as_deref(),
        Some("https://client.example.com/")
    );
}

#[tokio::test]
async fn trusted_clients_still_approve_through_the_decision_path() {
    let record = pending_record(
        "WDJBMJHT",
        "openid",
        Utc::now() + chrono::Duration::minutes(10),
    );
    let mut device_repo = MockDeviceAuthorizationRepository::new();
    let record_for_lookup = record.clone();
    device_repo
        .expect_find_active_device_request_by_user_code()
        .returning(move |_| Ok(Some(record_for_lookup.clone())));
    let (sender, mut approvals) = tokio::sync::mpsc::unbounded_channel();
    device_repo
        .expect_approve_device_request()
        .returning(move |_, approval, _| {
            let _ = sender.send(approval.clone());
            Ok(Some(approval.device_authorization_oid))
        });

    let service = build_service(skip_consent_device_client(), Arc::new(device_repo));

    let outcome = service
        .decide_verification(
            "WDJBMJHT",
            &verification_user(),
            DeviceVerificationDecision::Approve,
        )
        .await
        .unwrap();

    assert_eq!(outcome.status, DeviceVerificationStatus::Approved);
    let approval = approvals.try_recv().unwrap();
    assert_eq!(approval.user_oid, verification_user().user_oid.to_string());
    assert_eq!(approval.approved_scope, "openid");
}

#[tokio::test]
async fn decide_approves_with_the_session_authentication_context() {
    let record = pending_record(
        "WDJBMJHT",
        "openid profile",
        Utc::now() + chrono::Duration::minutes(10),
    );
    let mut device_repo = MockDeviceAuthorizationRepository::new();
    let record_for_lookup = record.clone();
    device_repo
        .expect_find_active_device_request_by_user_code()
        .returning(move |code| {
            assert_eq!(code, "WDJBMJHT", "lookup uses the normalized code");

            Ok(Some(record_for_lookup.clone()))
        });
    let (sender, mut approvals) = tokio::sync::mpsc::unbounded_channel();
    device_repo
        .expect_approve_device_request()
        .returning(move |_, approval, _| {
            let _ = sender.send(approval.clone());
            Ok(Some(approval.device_authorization_oid))
        });

    let service = build_service(device_client(device_grant(), false), Arc::new(device_repo));

    let outcome = service
        .decide_verification(
            "WDJB-MJHT",
            &verification_user(),
            DeviceVerificationDecision::Approve,
        )
        .await
        .unwrap();

    assert_eq!(outcome.status, DeviceVerificationStatus::Approved);
    let approval = approvals.try_recv().unwrap();
    assert_eq!(approval.user_oid, verification_user().user_oid.to_string());
    assert_eq!(approval.auth_time, Some(1_700_000_000));
    assert_eq!(approval.acr.as_deref(), Some("urn:identity:acr:aal1"));
    assert_eq!(approval.amr, vec!["pwd".to_owned()]);
    assert_eq!(approval.approved_scope, "openid profile");
}

#[tokio::test]
async fn decide_denies_the_request() {
    let record = pending_record(
        "WDJBMJHT",
        "openid",
        Utc::now() + chrono::Duration::minutes(10),
    );
    let mut device_repo = MockDeviceAuthorizationRepository::new();
    device_repo
        .expect_find_active_device_request_by_user_code()
        .returning(move |_| Ok(Some(record.clone())));
    let (sender, mut denials) = tokio::sync::mpsc::unbounded_channel();
    device_repo
        .expect_deny_device_request()
        .returning(move |_, user_oid, _| {
            let _ = sender.send(user_oid);
            Ok(true)
        });

    let service = build_service(device_client(device_grant(), false), Arc::new(device_repo));

    let outcome = service
        .decide_verification(
            "WDJBMJHT",
            &verification_user(),
            DeviceVerificationDecision::Deny,
        )
        .await
        .unwrap();

    assert_eq!(outcome.status, DeviceVerificationStatus::Denied);
    assert_eq!(denials.try_recv().unwrap(), verification_user().user_oid);
}

#[tokio::test]
async fn decide_is_rejected_when_another_decision_won_the_race() {
    let record = pending_record(
        "WDJBMJHT",
        "openid",
        Utc::now() + chrono::Duration::minutes(10),
    );
    let mut device_repo = MockDeviceAuthorizationRepository::new();
    device_repo
        .expect_find_active_device_request_by_user_code()
        .returning(move |_| Ok(Some(record.clone())));
    device_repo
        .expect_approve_device_request()
        .returning(|_, _, _| Ok(None));

    let service = build_service(device_client(device_grant(), false), Arc::new(device_repo));

    let error = service
        .decide_verification(
            "WDJBMJHT",
            &verification_user(),
            DeviceVerificationDecision::Approve,
        )
        .await
        .unwrap_err();

    assert_eq!(
        error.code(),
        DeviceAuthorizationErrorCode::RequestAlreadyDecided.code()
    );
}

#[tokio::test]
async fn expired_requests_cannot_be_decided() {
    let record = pending_record(
        "WDJBMJHT",
        "openid",
        Utc::now() - chrono::Duration::seconds(1),
    );
    let service = build_service(
        device_client(device_grant(), false),
        device_repo_with(record),
    );

    let error = service
        .decide_verification(
            "WDJBMJHT",
            &verification_user(),
            DeviceVerificationDecision::Approve,
        )
        .await
        .unwrap_err();

    assert_eq!(
        error.code(),
        DeviceAuthorizationErrorCode::RequestExpired.code()
    );

    let description = service.describe_verification("WDJBMJHT").await.unwrap();
    assert_eq!(description.status, DeviceVerificationStatus::Expired);
}

#[tokio::test]
async fn unknown_and_malformed_user_codes_are_rejected() {
    let mut device_repo = MockDeviceAuthorizationRepository::new();
    device_repo
        .expect_find_active_device_request_by_user_code()
        .returning(|_| Ok(None));
    let service = build_service(device_client(device_grant(), false), Arc::new(device_repo));

    let unknown = service.describe_verification("WDJBMJHT").await.unwrap_err();
    assert_eq!(
        unknown.code(),
        DeviceAuthorizationErrorCode::UserCodeNotFound.code()
    );

    // "WDJ" normalizes to fewer characters than a code can have; the lookup
    // never reaches the database.
    let malformed = service.describe_verification("WDJ").await.unwrap_err();
    assert_eq!(
        malformed.code(),
        DeviceAuthorizationErrorCode::UserCodeNotFound.code()
    );
}

#[tokio::test]
async fn verification_uri_points_at_the_login_application() {
    let (device_repo, _created) = accepting_device_repo();
    let service = build_service_with_login_domain(
        device_client(device_grant(), false),
        device_repo,
        Some("https://login.example.com"),
    );

    let response = service
        .authorize(params(Some("secret-123"), Some("openid")))
        .await
        .unwrap();

    assert_eq!(
        response.verification_uri, "https://login.example.com/device",
        "the login application renders the verification page, wherever it runs"
    );
    assert_eq!(
        response.verification_uri_complete,
        format!(
            "https://login.example.com/device?user_code={}",
            response.user_code
        )
    );
}

#[tokio::test]
async fn verification_uri_falls_back_to_the_issuer_host() {
    let (device_repo, _created) = accepting_device_repo();
    let service = build_service(device_client(device_grant(), false), device_repo);

    let response = service
        .authorize(params(Some("secret-123"), Some("openid")))
        .await
        .unwrap();

    assert_eq!(
        response.verification_uri, "https://identity.example.com/device",
        "an installation without a login domain still answers with a URI"
    );
}

#[tokio::test]
async fn a_malformed_login_domain_fails_the_request() {
    let (device_repo, _created) = accepting_device_repo();
    let service = build_service_with_login_domain(
        device_client(device_grant(), false),
        device_repo,
        Some("not a url"),
    );

    let error = service
        .authorize(params(Some("secret-123"), Some("openid")))
        .await
        .unwrap_err();

    assert_eq!(error.code(), 26023);
}
