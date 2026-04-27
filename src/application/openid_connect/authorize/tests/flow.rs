use super::fixtures::*;
use super::*;

#[tokio::test]
async fn create_authorization_request_returns_oid() {
    let request_repo = Arc::new(InMemoryClientAuthorizationRepository::default());
    let service = AuthorizeService::new(
        Arc::new(FoundClientRepository),
        Arc::new(InMemoryCredentialRepository::default()),
        request_repo,
        Arc::new(InMemoryLoginRepository),
        provider_service(),
        test_data_protector(),
    );

    let (request, _) = service
        .validate_request(params("openid profile"))
        .await
        .unwrap();
    let oid = service
        .create_authorization_request(&request)
        .await
        .unwrap();

    assert_ne!(oid, Uuid::nil());
}

#[tokio::test]
async fn create_login_flow_returns_protected_id() {
    let request_repo = Arc::new(InMemoryClientAuthorizationRepository::default());
    let service = AuthorizeService::new(
        Arc::new(FoundClientRepository),
        Arc::new(InMemoryCredentialRepository::default()),
        request_repo.clone(),
        Arc::new(InMemoryLoginRepository),
        provider_service(),
        test_data_protector(),
    );

    let (request, _) = service
        .validate_request(params("openid profile"))
        .await
        .unwrap();
    let authorization_request_id = service
        .create_authorization_request(&request)
        .await
        .unwrap();
    let login_id = service
        .create_login_flow(request.client_id, authorization_request_id, None)
        .await
        .unwrap();

    assert!(!login_id.is_empty());
}

#[tokio::test]
async fn load_authorization_request_returns_stored_data() {
    let request_repo = Arc::new(InMemoryClientAuthorizationRepository::default());
    let service = AuthorizeService::new(
        Arc::new(FoundClientRepository),
        Arc::new(InMemoryCredentialRepository::default()),
        request_repo.clone(),
        Arc::new(InMemoryLoginRepository),
        provider_service(),
        test_data_protector(),
    );

    let (request, _) = service
        .validate_request(params("openid profile"))
        .await
        .unwrap();
    let oid = service
        .create_authorization_request(&request)
        .await
        .unwrap();
    let loaded = service.load_authorization_request(oid).await.unwrap();

    assert_eq!(loaded.state, "state123");
    assert_eq!(loaded.scope, "openid profile");
}

#[tokio::test]
async fn approve_authorization_request_returns_redirect_with_code_and_state() {
    let request_repo = Arc::new(InMemoryClientAuthorizationRepository::default());
    let service = AuthorizeService::new(
        Arc::new(FoundClientRepository),
        Arc::new(InMemoryCredentialRepository::default()),
        request_repo.clone(),
        Arc::new(InMemoryLoginRepository),
        provider_service(),
        test_data_protector(),
    );

    let (request, _) = service
        .validate_request(params("openid profile"))
        .await
        .unwrap();
    let oid = service
        .create_authorization_request(&request)
        .await
        .unwrap();
    let redirect = service
        .approve_authorization_request(oid, Uuid::new_v4(), Uuid::new_v4(), None)
        .await
        .unwrap();

    let query = redirect.query().unwrap();
    assert!(query.contains("code="));
    assert!(query.contains("state=state123"));
}

#[tokio::test]
async fn create_authorization_request_persists_login_hint() {
    let request_repo = Arc::new(InMemoryClientAuthorizationRepository::default());
    let service = AuthorizeService::new(
        Arc::new(FoundClientRepository),
        Arc::new(InMemoryCredentialRepository::default()),
        request_repo.clone(),
        Arc::new(InMemoryLoginRepository),
        provider_service(),
        test_data_protector(),
    );

    let mut request_params = params("openid profile");
    request_params.login_hint = Some("alice@example.com".to_string());

    let (request, _) = service.validate_request(request_params).await.unwrap();
    let oid = service
        .create_authorization_request(&request)
        .await
        .unwrap();
    let loaded = service.load_authorization_request(oid).await.unwrap();

    assert_eq!(loaded.login_hint.as_deref(), Some("alice@example.com"));
}

#[tokio::test]
async fn deny_authorization_request_returns_access_denied_redirect() {
    let request_repo = Arc::new(InMemoryClientAuthorizationRepository::default());
    let service = AuthorizeService::new(
        Arc::new(FoundClientRepository),
        Arc::new(InMemoryCredentialRepository::default()),
        request_repo.clone(),
        Arc::new(InMemoryLoginRepository),
        provider_service(),
        test_data_protector(),
    );

    let (request, _) = service
        .validate_request(params("openid profile"))
        .await
        .unwrap();
    let oid = service
        .create_authorization_request(&request)
        .await
        .unwrap();
    let redirect = service.deny_authorization_request(oid).await.unwrap();

    let query = redirect.query().unwrap();
    assert!(query.contains("error=access_denied"));
    assert!(query.contains("state=state123"));
}
