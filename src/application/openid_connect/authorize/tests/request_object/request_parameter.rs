use crate::openid_connect::authorize::tests::fixtures::*;
use crate::openid_connect::authorize::tests::*;

#[tokio::test]
async fn signed_request_object_preserves_resource_through_parsing_and_merge() {
    let (private_key, public_key) = signing_keypair();
    let service = authorize_service_with_public_key(public_key);
    let resource = identity_domain::openid_connect::API_RESOURCE;
    let raw = signed_request_object(&private_key, [("resource", json!(resource))]);
    let client = service
        .client_repo
        .find_by_oid(TEST_CLIENT_ID)
        .await
        .unwrap()
        .unwrap();

    let payload = service
        .parse_request_object_payload(&client, &raw)
        .await
        .unwrap();
    let merged =
        AuthorizeService::merge_request_object_params(params("openid profile"), &payload).unwrap();
    assert_eq!(merged.resources, vec![resource]);
    service.validate_request(merged).await.unwrap();
}

#[tokio::test]
async fn validate_request_rejects_unsupported_resource_in_signed_request_object() {
    let (private_key, public_key) = signing_keypair();
    let service = authorize_service_with_public_key(public_key);
    let request = signed_request_object(
        &private_key,
        [("resource", json!("https://unsupported.example.com/api"))],
    );
    let params = AuthorizationRequestParams {
        resources: Vec::new(),
        request: Some(request),
        ..params("openid profile")
    };

    let error = service.validate_request(params).await.unwrap_err();
    assert_eq!(error.code(), 10006); // invalid_target
}

#[tokio::test]
async fn validate_request_supports_request_parameter() {
    let (private_key, public_key) = signing_keypair();
    let service = authorize_service_with_public_key(public_key);

    let request = signed_request_object(
        &private_key,
        [
            ("response_type", json!("code")),
            ("response_mode", json!("form_post")),
            ("client_id", json!(TEST_CLIENT_ID)),
            ("redirect_uri", json!("https://client.example.com/callback")),
            ("scope", json!("openid profile")),
            ("state", json!("state-123")),
            ("login_hint", json!("alice@example.com")),
        ],
    );

    let params = AuthorizationRequestParams {
        resources: Vec::new(),
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
    assert_eq!(request.response_mode.unwrap().to_string(), "form_post");
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
        resources: Vec::new(),
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
        resources: Vec::new(),
        request: Some(request),
        ..params("openid profile")
    };

    let error = service.validate_request(params).await.unwrap_err();
    assert!(format!("{error:?}").contains("scope"));
}

#[tokio::test]
async fn signed_request_object_resources_accept_arrays_and_reject_other_claim_types() {
    let (private_key, public_key) = signing_keypair();
    let service = authorize_service_with_public_key(public_key);
    let client = service
        .client_repo
        .find_by_oid(TEST_CLIENT_ID)
        .await
        .unwrap()
        .unwrap();
    for (claim, expected) in [
        (json!(["urn:a", "urn:b"]), Some(vec!["urn:a", "urn:b"])),
        (json!([]), None),
        (json!(["urn:a", 42]), None),
        (json!(42), None),
        (json!(null), None),
    ] {
        let raw = signed_request_object(&private_key, [("resource", claim)]);
        let payload = service
            .parse_request_object_payload(&client, &raw)
            .await
            .unwrap();
        let merged = AuthorizeService::merge_request_object_params(params("openid"), &payload);
        match expected {
            Some(expected) => assert_eq!(merged.unwrap().resources, expected),
            None => assert_eq!(merged.unwrap_err().code(), 10006),
        }
    }
}
