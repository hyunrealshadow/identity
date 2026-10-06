use identity_domain::openid_connect::{API_RESOURCE, GrantType};
use serde_json::{Value, from_slice};

use super::{RecordingSink, decode_unverified_payload};
use crate::{
    application::error::{code::AppErrorCode, codes::token::TokenErrorCode},
    observability::EventValue,
};

use crate::openid_connect::token::tests::fixtures::*;
use crate::openid_connect::token::tests::*;

fn request(scope: &str) -> ClientCredentialsGrantParams {
    ClientCredentialsGrantParams {
        resources: Vec::new(),
        scope: Some(scope.to_owned()),
        client_id: Some(Uuid::nil().to_string()),
        client_secret: Some("secret-123".to_owned()),
        client_secret_basic: true,
        client_assertion_type: None,
        client_assertion: None,
    }
}

#[tokio::test]
async fn client_credentials_issues_only_access_token_for_assigned_api_scope() {
    let sink = Arc::new(RecordingSink::default());
    let repo = Arc::new(mock_client_auth_repo());
    let service = build_token_service_with_client_repo(
        repo,
        Uuid::new_v4(),
        Arc::new(MachineClientRepository),
    )
    .with_events(sink.clone());

    let mut params = request("account.read");
    params.resources = vec![API_RESOURCE.to_owned()];
    let response = service.exchange_client_credentials(params).await.unwrap();
    assert!(!response.access_token.is_empty());
    assert_eq!(response.scope, "account.read");
    assert!(response.id_token.is_none());
    assert!(response.refresh_token.is_none());
    let access = decode_unverified_payload(&response.access_token);
    sink.assert_attribute(
        "token.client_credentials.result",
        "success",
        "access_token_oid",
        EventValue::Text(access["jti"].as_str().unwrap().to_owned()),
    );
}

#[tokio::test]
async fn client_credentials_uses_client_id_token_algorithm_for_access_token() {
    let repo = Arc::new(mock_client_auth_repo());
    let mut service = build_token_service_with_client_repo(
        repo,
        Uuid::new_v4(),
        Arc::new(MachineAlgorithmClientRepository {
            algorithm: JwaSigningAlgorithm::Rs256,
            include_access_claims: true,
        }),
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

    let response = service
        .exchange_client_credentials(request("account.read"))
        .await
        .unwrap();
    assert!(response.id_token.is_none());
    let access_claims = from_slice::<Value>(
        &URL_SAFE_NO_PAD
            .decode(response.access_token.split('.').nth(1).unwrap())
            .unwrap(),
    )
    .unwrap();
    assert!(access_claims.get("name").is_none());
    assert!(access_claims.get("email").is_none());
    let header = jwt::decode_header(&response.access_token).unwrap();
    assert_eq!(
        header
            .claim(JwtClaimNames::ALG)
            .and_then(|value| value.as_str()),
        Some("RS256")
    );
    assert_eq!(
        header
            .claim(JwtClaimNames::KID)
            .and_then(|value| value.as_str()),
        Some(Uuid::from(rsa_binding.oid).to_string().as_str())
    );
}

#[tokio::test]
async fn client_credentials_rejects_user_scope_and_unassigned_scope() {
    let repo = Arc::new(mock_client_auth_repo());
    let service = build_token_service_with_client_repo(
        repo,
        Uuid::new_v4(),
        Arc::new(MachineClientRepository),
    );
    for scope in ["openid", "offline_access", "account.update"] {
        let error = service
            .exchange_client_credentials(request(scope))
            .await
            .unwrap_err();
        assert_eq!(
            error.code(),
            TokenErrorCode::ClientCredentialsScopeNotAllowed.code()
        );
    }
}

#[tokio::test]
async fn client_credentials_requires_confidential_client_and_grant_permission() {
    let repo = Arc::new(mock_client_auth_repo());
    let public_service = build_token_service_with_client_repo(
        repo.clone(),
        Uuid::new_v4(),
        Arc::new(RegisteredPublicClientRepository),
    );
    let mut public_request = request("account.read");
    public_request.client_secret = None;
    let error = public_service
        .exchange_client_credentials(public_request)
        .await
        .unwrap_err();
    assert_eq!(error.code(), TokenErrorCode::ClientAuthRequired.code());

    let restricted_service = build_token_service_with_client_repo(
        repo,
        Uuid::new_v4(),
        Arc::new(RestrictedGrantClientRepository {
            grant_types: vec![GrantType::AuthorizationCode],
        }),
    );
    let error = restricted_service
        .exchange_client_credentials(request(""))
        .await
        .unwrap_err();
    assert_eq!(error.code(), TokenErrorCode::ClientGrantNotAllowed.code());
}

#[tokio::test]
async fn client_credentials_enforces_registered_authentication_method() {
    let repo = Arc::new(mock_client_auth_repo());
    let basic_service = build_token_service_with_client_repo(
        repo.clone(),
        Uuid::new_v4(),
        Arc::new(MachineClientRepository),
    );
    let mut posted_secret = request("account.read");
    posted_secret.client_secret_basic = false;
    let error = basic_service
        .exchange_client_credentials(posted_secret)
        .await
        .unwrap_err();
    assert_eq!(error.code(), TokenErrorCode::ClientAuthRequired.code());

    let jwt_service = build_token_service_with_client_repo(
        repo,
        Uuid::new_v4(),
        Arc::new(AuthMethodClientRepository {
            method: "private_key_jwt",
            signing_alg: None,
        }),
    );
    let error = jwt_service
        .exchange_client_credentials(request(""))
        .await
        .unwrap_err();
    assert_eq!(error.code(), TokenErrorCode::ClientAuthRequired.code());
}
