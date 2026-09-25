use crate::application::error::{code::AppErrorCode, codes::token::TokenErrorCode};
use crate::openid_connect::token::tests::fixtures::*;
use crate::openid_connect::token::tests::*;
use identity_domain::openid_connect::GrantType;

fn request(scope: &str) -> ClientCredentialsGrantParams {
    ClientCredentialsGrantParams {
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
    let repo = Arc::new(mock_client_auth_repo());
    let service = build_token_service_with_client_repo(
        repo,
        Uuid::new_v4(),
        Arc::new(MachineClientRepository),
    );

    let response = service
        .exchange_client_credentials(request("account.read"))
        .await
        .unwrap();
    assert!(!response.access_token.is_empty());
    assert_eq!(response.scope, "account.read");
    assert!(response.id_token.is_none());
    assert!(response.refresh_token.is_none());
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
