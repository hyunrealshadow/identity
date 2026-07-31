use super::fixtures::*;
use super::*;

#[tokio::test]
async fn validate_request_rejects_missing_openid_scope() {
    let service = build_test_service(
        Arc::new(MissingClientRepository),
        Arc::new(empty_cred_repo()),
        Arc::new(mock_login_repo()),
    );

    let result = service.validate_request(params("profile email")).await;

    assert!(result.is_err());
}

#[tokio::test]
async fn validate_request_rejects_unknown_scope() {
    let service = build_test_service(
        Arc::new(MissingClientRepository),
        Arc::new(empty_cred_repo()),
        Arc::new(mock_login_repo()),
    );

    let result = service
        .validate_request(params("openid custom_scope"))
        .await;

    assert!(result.is_err());
}

#[tokio::test]
async fn public_client_requires_pkce_s256() {
    let service = build_test_service(
        Arc::new(PublicClientRepository),
        Arc::new(empty_cred_repo()),
        Arc::new(mock_login_repo()),
    );

    let missing = service
        .validate_request(params("openid profile"))
        .await
        .unwrap_err();
    assert_eq!(missing.code(), 23013);

    let mut plain = params("openid profile");
    plain.code_challenge = Some("challenge".to_owned());
    plain.code_challenge_method = Some("plain".to_owned());
    let plain = service.validate_request(plain).await.unwrap_err();
    assert_eq!(plain.code(), 23011);

    let mut s256 = params("openid profile");
    s256.code_challenge = Some("challenge".to_owned());
    s256.code_challenge_method = Some("S256".to_owned());
    assert!(service.validate_request(s256).await.is_ok());
}

#[tokio::test]
async fn public_client_rejects_implicit_response_type() {
    let service = build_test_service(
        Arc::new(PublicClientRepository),
        Arc::new(empty_cred_repo()),
        Arc::new(mock_login_repo()),
    );
    let mut request = params("openid profile");
    request.response_type = "id_token".to_owned();
    request.nonce = Some("nonce".to_owned());
    request.code_challenge = Some("challenge".to_owned());
    request.code_challenge_method = Some("S256".to_owned());

    let error = service.validate_request(request).await.unwrap_err();

    assert_eq!(error.code(), 23003);
}

#[tokio::test]
async fn validate_request_reports_missing_required_fields() {
    let service = build_test_service(
        Arc::new(MissingClientRepository),
        Arc::new(empty_cred_repo()),
        Arc::new(mock_login_repo()),
    );

    let params = AuthorizationRequestParams {
        response_type: String::new(),
        response_mode: None,
        client_id: String::new(),
        redirect_uri: String::new(),
        scope: String::new(),
        resource: None,
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
async fn validate_request_rejects_id_token_hint_from_other_issuer() {
    let mut params = params("openid profile");
    params.id_token_hint = Some(unsigned_id_token_hint("https://other.example.com/"));
    let service = build_test_service(
        Arc::new(FoundClientRepository),
        Arc::new(empty_cred_repo()),
        Arc::new(mock_login_repo()),
    );

    let result = service.validate_request(params).await;

    assert!(result.is_err());
    assert_eq!(result.unwrap_err().code(), 23060);
}

#[cfg(not(feature = "allow-none-alg"))]
#[tokio::test]
async fn validate_request_rejects_none_algorithm_id_token_hint() {
    let mut params = params("openid profile");
    params.id_token_hint = Some(unsigned_id_token_hint("https://identity.example.com/"));
    let service = build_test_service(
        Arc::new(FoundClientRepository),
        Arc::new(empty_cred_repo()),
        Arc::new(mock_login_repo()),
    );

    let error = service.validate_request(params).await.unwrap_err();

    assert_eq!(error.code(), 23060);
}

fn unsigned_id_token_hint(issuer: &str) -> String {
    let mut header = JwsHeader::new();
    header.set_token_type("JWT");
    let mut payload = JwtPayload::new();
    payload
        .set_claim("iss", Some(serde_json::json!(issuer)))
        .unwrap();
    jwt::encode_unsecured(&payload, &header).unwrap()
}

#[tokio::test]
async fn validate_request_rejects_request_and_request_uri_together() {
    let service = build_test_service(
        Arc::new(FoundClientRepository),
        Arc::new(empty_cred_repo()),
        Arc::new(mock_login_repo()),
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
    let service = build_test_service(
        Arc::new(FoundClientRepository),
        Arc::new(empty_cred_repo()),
        Arc::new(mock_login_repo()),
    );

    let result = service.validate_request(params("openid profile")).await;

    assert!(result.is_ok());
}

#[tokio::test]
async fn validate_request_rejects_scope_not_assigned_to_client() {
    let service = build_test_service(
        Arc::new(ScopedClientRepository {
            assigned_scopes: vec!["openid".to_string()],
        }),
        Arc::new(empty_cred_repo()),
        Arc::new(mock_login_repo()),
    );

    let error = service
        .validate_request(params("openid email"))
        .await
        .unwrap_err();

    assert_eq!(error.code(), 23056);
}

#[tokio::test]
async fn prompt_none_combined_with_other_value_rejects() {
    let service = build_test_service(
        Arc::new(FoundClientRepository),
        Arc::new(empty_cred_repo()),
        Arc::new(mock_login_repo()),
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
    let service = build_test_service(
        Arc::new(FoundClientRepository),
        Arc::new(empty_cred_repo()),
        Arc::new(mock_login_repo()),
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
    let service = build_test_service(
        Arc::new(ScopedClientRepository {
            assigned_scopes: vec!["profile".to_string()],
        }),
        Arc::new(empty_cred_repo()),
        Arc::new(mock_login_repo()),
    );

    let error = service
        .validate_request(params("openid"))
        .await
        .unwrap_err();

    assert_eq!(error.code(), 23056);
}

#[tokio::test]
async fn api_scopes_require_graphql_resource() {
    let service = build_test_service(
        Arc::new(ScopedClientRepository {
            assigned_scopes: vec!["openid".to_string(), "account".to_string()],
        }),
        Arc::new(empty_cred_repo()),
        Arc::new(mock_login_repo()),
    );

    let error = service
        .validate_request(params("openid account"))
        .await
        .unwrap_err();

    assert_eq!(error.code(), 23005);
}

#[tokio::test]
async fn api_scopes_accept_graphql_resource() {
    let service = build_test_service(
        Arc::new(ScopedClientRepository {
            assigned_scopes: vec!["openid".to_string(), "account".to_string()],
        }),
        Arc::new(empty_cred_repo()),
        Arc::new(mock_login_repo()),
    );
    let mut request = params("openid account");
    request.resource = Some(identity_domain::openid_connect::API_RESOURCE.to_string());

    assert!(service.validate_request(request).await.is_ok());
}
