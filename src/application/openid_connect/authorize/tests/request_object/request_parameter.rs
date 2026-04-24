use super::super::fixtures::*;
use super::super::*;

#[tokio::test]
async fn validate_request_supports_request_parameter() {
    let (private_key, public_key) = signing_keypair();
    let service = authorize_service_with_public_key(public_key);

    let request = signed_request_object(
        &private_key,
        [
            ("response_type", json!("code")),
            ("client_id", json!(TEST_CLIENT_ID)),
            ("redirect_uri", json!("https://client.example.com/callback")),
            ("scope", json!("openid profile")),
            ("state", json!("state-123")),
            ("login_hint", json!("alice@example.com")),
        ],
    );

    let params = AuthorizationRequestParams {
        client_id: TEST_CLIENT_ID.to_string(),
        response_type: String::new(),
        redirect_uri: String::new(),
        scope: String::new(),
        state: String::new(),
        request: Some(request),
        request_uri: None,
        ..empty_optional_params()
    };

    let (request, _) = service.validate_request(params).await.unwrap();
    assert_eq!(request.response_type.to_string(), "code");
    assert_eq!(
        request.redirect_uri.as_str(),
        "https://client.example.com/callback"
    );
    assert_eq!(request.scope.to_scope_string(), "openid profile");
    assert_eq!(request.state, "state-123");
    assert_eq!(request.login_hint.as_deref(), Some("alice@example.com"));
}

#[tokio::test]
async fn validate_request_supports_request_parameter_without_outer_client_id() {
    let (private_key, public_key) = signing_keypair();
    let service = authorize_service_with_public_key(public_key);

    let request = signed_request_object(
        &private_key,
        [
            ("response_type", json!("code")),
            ("client_id", json!(TEST_CLIENT_ID)),
            ("redirect_uri", json!("https://client.example.com/callback")),
            ("scope", json!("openid profile")),
            ("state", json!("state-456")),
        ],
    );

    let params = AuthorizationRequestParams {
        client_id: String::new(),
        response_type: String::new(),
        redirect_uri: String::new(),
        scope: String::new(),
        state: String::new(),
        request: Some(request),
        request_uri: None,
        ..empty_optional_params()
    };

    let (request, _) = service.validate_request(params).await.unwrap();
    assert_eq!(request.client_id, TEST_CLIENT_ID);
    assert_eq!(request.state, "state-456");
}

#[tokio::test]
async fn validate_request_rejects_mismatched_request_object_field() {
    let (private_key, public_key) = signing_keypair();
    let service = authorize_service_with_public_key(public_key);
    let request = signed_request_object(
        &private_key,
        [
            ("response_type", json!("code")),
            ("client_id", json!(TEST_CLIENT_ID)),
            ("redirect_uri", json!("https://client.example.com/callback")),
            ("scope", json!("openid email")),
        ],
    );

    let params = AuthorizationRequestParams {
        request: Some(request),
        ..params("openid profile")
    };

    let error = service.validate_request(params).await.unwrap_err();
    assert!(format!("{error:?}").contains("scope"));
}
