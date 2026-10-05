use super::{fixtures::*, *};
use crate::error::code::AppErrorCode;
use crate::error::codes::token::TokenErrorCode;
use crate::openid_connect::tests::fixtures::client::test_client;
use crate::openid_connect::tests::fixtures::client::test_metadata;
use crate::openid_connect::tests::fixtures::client::test_platforms;
use crate::openid_connect::tests::fixtures::client::test_scopes;
use crate::openid_connect::tests::fixtures::mocks::MockClientAuthorizationRepository;
use crate::openid_connect::{
    client_authentication::{ClientAuthenticator, ClientAuthenticatorDependencies},
    par::{PushedAuthorizationParams, PushedAuthorizationService, request_uri_digest},
};
use chrono::DateTime;
use chrono::Duration;
use identity_domain::client_authorization::{
    ClientAuthorization, ClientAuthorizationData, ClientAuthorizationRepositoryError,
    PushedAuthorizationRequestData,
};
use identity_domain::openid_connect::API_RESOURCE;
use identity_domain::openid_connect::ClientAssertionType;
use identity_domain::openid_connect::par::PAR_REQUEST_URI_PREFIX;
use std::sync::Mutex;

#[derive(Default)]
struct MemoryPar(Mutex<HashMap<String, (Uuid, AuthorizationRequestParams, DateTime<Utc>)>>);
struct ClientRepo(OpenIdConnectClient);
#[async_trait]
impl OpenIdConnectClientRepository for ClientRepo {
    async fn find_by_oid(
        &self,
        _: Uuid,
    ) -> Result<Option<OpenIdConnectClient>, OpenIdConnectClientRepositoryError> {
        Ok(Some(self.0.clone()))
    }
}
impl MemoryPar {
    async fn insert(
        &self,
        digest: &str,
        client: Uuid,
        params: AuthorizationRequestParams,
        expires: DateTime<Utc>,
    ) -> Result<(), ClientAuthorizationRepositoryError> {
        self.0
            .lock()
            .unwrap()
            .insert(digest.to_owned(), (client, params, expires));
        Ok(())
    }
}
fn front(uri: &str) -> AuthorizationRequestParams {
    AuthorizationRequestParams {
        client_id: TEST_CLIENT_ID.to_string(),
        request_uri: Some(uri.to_owned()),
        ..Default::default()
    }
}
fn public_push(authorization: AuthorizationRequestParams) -> PushedAuthorizationParams {
    PushedAuthorizationParams {
        authorization,
        client_secret: None,
        client_secret_basic: false,
        client_assertion: None,
        client_assertion_type: None,
    }
}
fn setup() -> (PushedAuthorizationService, AuthorizeService, Arc<MemoryPar>) {
    let repository = Arc::new(MemoryPar::default());
    let mut client = test_metadata(None, Some("none"));
    client.settings.allow_public_client_flow = true;
    let client = OpenIdConnectClient::new(
        test_client(TEST_CLIENT_ID),
        client,
        test_platforms(),
        test_scopes(),
    )
    .unwrap();
    let client_repo = Arc::new(ClientRepo(client));
    let mut authorize = build_test_service(
        client_repo.clone(),
        Arc::new(empty_cred_repo()),
        Arc::new(mock_login_repo()),
    );
    let mut auth_repo = MockClientAuthorizationRepository::new();
    let records = repository.clone();
    auth_repo
        .expect_create()
        .returning(move |client_oid, data, expires_at| {
            let ClientAuthorizationData::PushedAuthorizationRequest(pushed) = &data else {
                panic!("expected PAR")
            };
            records.0.lock().unwrap().insert(
                pushed.request_uri_digest.clone(),
                (client_oid, pushed.parameters.clone(), expires_at),
            );
            Ok(ClientAuthorization {
                oid: Uuid::new_v4(),
                client_oid,
                type_: data.authorization_type(),
                data,
                expires_at,
                completed_at: None,
                revoked_at: None,
                created_at: Utc::now(),
                updated_at: None,
            })
        });
    let records = repository.clone();
    auth_repo
        .expect_consume_pushed_authorization_request()
        .returning(move |digest, client, now| {
            let mut records = records.0.lock().unwrap();
            if !records
                .get(digest)
                .is_some_and(|(owner, _, expiry)| *owner == client && *expiry > now)
            {
                return Ok(None);
            }
            Ok(records
                .remove(digest)
                .map(|(_, parameters, _)| PushedAuthorizationRequestData {
                    request_uri_digest: digest.to_owned(),
                    parameters,
                }))
        });
    let auth_repo = Arc::new(auth_repo);
    authorize.client_authorization_repo = auth_repo.clone();
    let auth = ClientAuthenticator::new(ClientAuthenticatorDependencies {
        client_repo,
        credential_repo: Arc::new(empty_cred_repo()),
        provider_service: provider_service(),
    });
    let push = PushedAuthorizationService::new(
        Arc::new(auth),
        authorize.clone(),
        auth_repo,
        provider_service(),
    );
    (push, authorize, repository)
}

#[tokio::test]
async fn pushed_requests_preserve_resources_and_are_client_bound_expiring_and_single_use() {
    let (push, authorize, repository) = setup();
    let mut original = params("openid profile");
    original.resources = vec![API_RESOURCE.to_owned()];
    let response = push.push(public_push(original)).await.unwrap();
    assert!(response.request_uri.starts_with(PAR_REQUEST_URI_PREFIX));
    assert_eq!(response.expires_in, 90);
    let mut other = front(&response.request_uri);
    other.client_id = Uuid::new_v4().to_string();
    assert!(authorize.validate_request(other).await.is_err());
    let mut tampered = front(&response.request_uri);
    tampered.scope = "openid email".to_owned();
    assert_eq!(
        authorize
            .validate_request(tampered)
            .await
            .unwrap_err()
            .code(),
        10000
    );
    let (first, second) = tokio::join!(
        authorize.validate_request(front(&response.request_uri)),
        authorize.validate_request(front(&response.request_uri))
    );
    assert_eq!(first.is_ok() as usize + second.is_ok() as usize, 1);
    let (request, _) = first.or(second).unwrap();
    assert_eq!(request.resources, [API_RESOURCE]);
    assert_eq!(request.scope.to_scope_string(), "openid profile");
    assert_eq!(request.state, "state123");
    assert!(
        authorize
            .validate_request(front(&response.request_uri))
            .await
            .is_err()
    );
    let expired = push.push(public_push(params("openid"))).await.unwrap();
    repository
        .0
        .lock()
        .unwrap()
        .get_mut(&request_uri_digest(&expired.request_uri))
        .unwrap()
        .2 = Utc::now() - Duration::seconds(1);
    assert!(
        authorize
            .validate_request(front(&expired.request_uri))
            .await
            .is_err()
    );
}

#[tokio::test]
async fn par_reuses_pkce_validation_and_rejects_nested_request_uris_before_storage() {
    let (push, _, repository) = setup();
    let mut unidentified = public_push(params("openid"));
    unidentified.authorization.client_id.clear();
    unidentified.client_assertion_type = Some(ClientAssertionType::JwtBearer);
    unidentified.client_assertion = Some("assertion".to_owned());
    assert_eq!(
        push.push(unidentified).await.unwrap_err().code(),
        TokenErrorCode::ClientIdRequired.code()
    );
    let mut missing = params("openid");
    missing.code_challenge = None;
    missing.code_challenge_method = None;
    assert_eq!(
        push.push(public_push(missing)).await.unwrap_err().code(),
        23013
    );
    let mut nested = params("openid");
    nested.request_uri = Some("https://client.example.com/object.jwt".to_owned());
    assert_eq!(
        push.push(public_push(nested)).await.unwrap_err().code(),
        10000
    );
    assert!(repository.0.lock().unwrap().is_empty());
}

#[tokio::test]
async fn required_par_policy_accepts_pushed_requests_and_revalidates_client_scopes() {
    let (_, mut authorize, repository) = setup();
    let old = params("openid profile");
    let uri = format!("{PAR_REQUEST_URI_PREFIX}original");
    repository
        .insert(
            &request_uri_digest(&uri),
            TEST_CLIENT_ID,
            old.clone(),
            Utc::now() + Duration::seconds(90),
        )
        .await
        .unwrap();
    let mut client = authorize
        .client_repo
        .find_by_oid(TEST_CLIENT_ID)
        .await
        .unwrap()
        .unwrap();
    let mut metadata = client.metadata().clone();
    metadata.settings.require_pushed_authorization_requests = true;
    client = OpenIdConnectClient::new(
        client.client().clone(),
        metadata,
        client.platforms().to_vec(),
        vec!["openid".to_owned()],
    )
    .unwrap();
    authorize.client_repo = Arc::new(ClientRepo(client));
    assert_eq!(
        authorize.validate_request(old).await.unwrap_err().code(),
        10000
    );
    assert_eq!(
        authorize
            .validate_request(front(&uri))
            .await
            .unwrap_err()
            .code(),
        23056
    );
    assert!(
        authorize
            .validate_pushed_request(params("openid"))
            .await
            .is_ok()
    );
}

#[tokio::test]
async fn par_signed_request_objects_must_identify_the_authenticated_client() {
    let (private, public) = signing_keypair();
    let authorize = authorize_service_with_public_key(public);
    let fields = [
        ("client_id", json!(TEST_CLIENT_ID)),
        ("response_type", json!("code")),
        ("scope", json!("openid")),
        ("state", json!("signed-state")),
        ("redirect_uri", json!("https://client.example.com/callback")),
        ("code_challenge", json!("challenge")),
        ("code_challenge_method", json!("S256")),
    ];
    let signed = signed_request_object(&private, fields.clone());
    let request = AuthorizationRequestParams {
        client_id: TEST_CLIENT_ID.to_string(),
        request: Some(signed),
        ..Default::default()
    };
    assert!(authorize.validate_pushed_request(request).await.is_ok());
    let mut fields = fields;
    fields[0].1 = json!(Uuid::new_v4().to_string());
    let other = signed_request_object(&private, fields);
    let request = AuthorizationRequestParams {
        client_id: TEST_CLIENT_ID.to_string(),
        request: Some(other),
        ..Default::default()
    };
    assert_eq!(
        authorize
            .validate_pushed_request(request)
            .await
            .unwrap_err()
            .code(),
        23034
    );
}
