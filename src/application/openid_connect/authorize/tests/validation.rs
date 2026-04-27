use super::fixtures::*;
use super::*;

#[tokio::test]
async fn validate_request_rejects_missing_openid_scope() {
    let service = AuthorizeService::new(
        Arc::new(MissingClientRepository),
        Arc::new(InMemoryCredentialRepository::default()),
        Arc::new(InMemoryClientAuthorizationRepository::default()),
        Arc::new(InMemoryLoginRepository),
        provider_service(),
        test_data_protector(),
    );

    let result = service.validate_request(params("profile email")).await;

    assert!(result.is_err());
}

#[tokio::test]
async fn validate_request_rejects_unknown_scope() {
    let service = AuthorizeService::new(
        Arc::new(MissingClientRepository),
        Arc::new(InMemoryCredentialRepository::default()),
        Arc::new(InMemoryClientAuthorizationRepository::default()),
        Arc::new(InMemoryLoginRepository),
        provider_service(),
        test_data_protector(),
    );

    let result = service
        .validate_request(params("openid custom_scope"))
        .await;

    assert!(result.is_err());
}

#[tokio::test]
async fn validate_request_reports_missing_required_fields() {
    let service = AuthorizeService::new(
        Arc::new(MissingClientRepository),
        Arc::new(InMemoryCredentialRepository::default()),
        Arc::new(InMemoryClientAuthorizationRepository::default()),
        Arc::new(InMemoryLoginRepository),
        provider_service(),
        test_data_protector(),
    );

    let params = AuthorizationRequestParams {
        response_type: String::new(),
        client_id: String::new(),
        redirect_uri: String::new(),
        scope: String::new(),
        state: String::new(),
        nonce: None,
        display: None,
        prompt: None,
        max_age: None,
        ui_locales: None,
        claims_locales: None,
        id_token_hint: None,
        login_hint: None,
        acr_values: None,
        claims: None,
        request: None,
        request_uri: None,
        code_challenge: None,
        code_challenge_method: None,
    };

    let error = service.validate_request(params).await.unwrap_err();
    let debug = format!("{error:?}");

    assert!(debug.contains("response_type"));
    assert!(debug.contains("client_id"));
    assert!(debug.contains("redirect_uri"));
    assert!(debug.contains("scope"));
}

#[tokio::test]
async fn validate_request_rejects_request_and_request_uri_together() {
    let service = AuthorizeService::new(
        Arc::new(FoundClientRepository),
        Arc::new(InMemoryCredentialRepository::default()),
        Arc::new(InMemoryClientAuthorizationRepository::default()),
        Arc::new(InMemoryLoginRepository),
        provider_service(),
        test_data_protector(),
    );
    let params = AuthorizationRequestParams {
        request: Some("header.payload.signature".to_string()),
        request_uri: Some("https://client.example.com/request.jwt".to_string()),
        ..params("openid profile")
    };

    let error = service.validate_request(params).await.unwrap_err();

    assert_eq!(error.code(), 23012); // RequestAndUriConflict
}

#[tokio::test]
async fn validate_request_accepts_registered_redirect_uri() {
    let service = AuthorizeService::new(
        Arc::new(FoundClientRepository),
        Arc::new(InMemoryCredentialRepository::default()),
        Arc::new(InMemoryClientAuthorizationRepository::default()),
        Arc::new(InMemoryLoginRepository),
        provider_service(),
        test_data_protector(),
    );

    let result = service.validate_request(params("openid profile")).await;

    assert!(result.is_ok());
}

#[tokio::test]
async fn validate_request_rejects_scope_not_assigned_to_client() {
    let service = AuthorizeService::new(
        Arc::new(ScopedClientRepository {
            assigned_scopes: vec!["openid".to_string()],
        }),
        Arc::new(InMemoryCredentialRepository::default()),
        Arc::new(InMemoryClientAuthorizationRepository::default()),
        Arc::new(InMemoryLoginRepository),
        provider_service(),
        test_data_protector(),
    );

    let error = service
        .validate_request(params("openid email"))
        .await
        .unwrap_err();

    assert_eq!(error.code(), 23056);
}

#[tokio::test]
async fn prompt_none_combined_with_other_value_rejects() {
    let service = AuthorizeService::new(
        Arc::new(FoundClientRepository),
        Arc::new(InMemoryCredentialRepository::default()),
        Arc::new(InMemoryClientAuthorizationRepository::default()),
        Arc::new(InMemoryLoginRepository),
        provider_service(),
        test_data_protector(),
    );

    let error = service
        .validate_request(AuthorizationRequestParams {
            prompt: Some("none login".to_string()),
            ..params("openid profile")
        })
        .await
        .unwrap_err();

    assert_eq!(error.code(), 23057);
}

#[tokio::test]
async fn prompt_none_alone_is_accepted() {
    let service = AuthorizeService::new(
        Arc::new(FoundClientRepository),
        Arc::new(InMemoryCredentialRepository::default()),
        Arc::new(InMemoryClientAuthorizationRepository::default()),
        Arc::new(InMemoryLoginRepository),
        provider_service(),
        test_data_protector(),
    );

    let result = service
        .validate_request(AuthorizationRequestParams {
            prompt: Some("none".to_string()),
            ..params("openid profile")
        })
        .await;

    assert!(result.is_ok());
}

#[tokio::test]
async fn validate_request_rejects_unassigned_openid_scope() {
    let service = AuthorizeService::new(
        Arc::new(ScopedClientRepository {
            assigned_scopes: vec!["profile".to_string()],
        }),
        Arc::new(InMemoryCredentialRepository::default()),
        Arc::new(InMemoryClientAuthorizationRepository::default()),
        Arc::new(InMemoryLoginRepository),
        provider_service(),
        test_data_protector(),
    );

    let error = service
        .validate_request(params("openid"))
        .await
        .unwrap_err();

    assert_eq!(error.code(), 23056);
}
