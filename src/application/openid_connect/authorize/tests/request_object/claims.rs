use super::super::fixtures::*;
use super::super::*;

#[test]
fn validate_request_object_claims_rejects_future_issued_at() {
    let mut params = params("openid profile");
    params.state = "state-123".to_string();
    let payload = serde_json::json!({
        "response_type": "code",
        "client_id": TEST_CLIENT_ID.to_string(),
        "redirect_uri": "https://client.example.com/callback",
        "scope": "openid profile",
        "state": "state-123",
        "iat": chrono::Utc::now().timestamp() + 60,
    });

    let result = AuthorizeService::validate_request_object_claims(
        &params,
        &payload,
        &Url::parse("https://identity.example.com/").unwrap(),
    );

    assert!(result.is_err());
    assert_eq!(result.unwrap_err().code(), 6033); // RequestObjectIatFuture
}

#[test]
fn merge_request_object_overrides_scope_and_login_hint() {
    let payload = serde_json::json!({
        "scope": "openid email",
        "state": "override-state",
        "login_hint": "alice@example.com"
    });

    let params = AuthorizationRequestParams {
        response_type: "code".to_string(),
        client_id: Uuid::nil().to_string(),
        redirect_uri: "https://client.example.com/callback".to_string(),
        scope: "openid profile".to_string(),
        state: "state123".to_string(),
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

    let merged = AuthorizeService::merge_request_object_params(params, &payload).unwrap();

    assert_eq!(merged.scope, "openid email");
    assert_eq!(merged.state, "override-state");
    assert_eq!(merged.login_hint.as_deref(), Some("alice@example.com"));
}

#[test]
fn validate_request_object_claims_rejects_client_id_mismatch() {
    let params = AuthorizationRequestParams {
        response_type: "code".to_string(),
        client_id: Uuid::nil().to_string(),
        redirect_uri: "https://client.example.com/callback".to_string(),
        scope: "openid profile".to_string(),
        state: "state123".to_string(),
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
    let payload = serde_json::json!({
        "client_id": Uuid::new_v4().to_string(),
        "redirect_uri": "https://client.example.com/callback"
    });

    let result = AuthorizeService::validate_request_object_claims(
        &params,
        &payload,
        &Url::parse("https://identity.example.com/").unwrap(),
    );

    assert!(result.is_err());
}

#[test]
fn validate_request_object_claims_allows_redirect_uri_mismatch() {
    // Per OIDCC-6.1, request object values supersede query params.
    // redirect_uri mismatches are allowed; the merge step will use the
    // request object's redirect_uri.
    let params = AuthorizationRequestParams {
        response_type: "code".to_string(),
        client_id: Uuid::nil().to_string(),
        redirect_uri: "https://client.example.com/callback".to_string(),
        scope: "openid profile".to_string(),
        state: "state123".to_string(),
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
    let payload = serde_json::json!({
        "client_id": Uuid::nil().to_string(),
        "redirect_uri": "https://other.example.com/callback"
    });

    let result = AuthorizeService::validate_request_object_claims(
        &params,
        &payload,
        &Url::parse("https://identity.example.com/").unwrap(),
    );

    assert!(result.is_ok());
}

#[test]
fn validate_request_object_claims_rejects_issuer_mismatch() {
    let params = AuthorizationRequestParams {
        response_type: "code".to_string(),
        client_id: Uuid::nil().to_string(),
        redirect_uri: "https://client.example.com/callback".to_string(),
        scope: "openid profile".to_string(),
        state: "state123".to_string(),
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
    let payload = serde_json::json!({
        "iss": Uuid::new_v4().to_string(),
        "aud": "https://identity.example.com/"
    });

    let result = AuthorizeService::validate_request_object_claims(
        &params,
        &payload,
        &Url::parse("https://identity.example.com/").unwrap(),
    );

    assert!(result.is_err());
}

#[test]
fn validate_request_object_claims_rejects_audience_mismatch() {
    let params = AuthorizationRequestParams {
        response_type: "code".to_string(),
        client_id: Uuid::nil().to_string(),
        redirect_uri: "https://client.example.com/callback".to_string(),
        scope: "openid profile".to_string(),
        state: "state123".to_string(),
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
    let payload = serde_json::json!({
        "iss": Uuid::nil().to_string(),
        "aud": "https://other.example.com/"
    });

    let result = AuthorizeService::validate_request_object_claims(
        &params,
        &payload,
        &Url::parse("https://identity.example.com/").unwrap(),
    );

    assert!(result.is_err());
}

#[test]
fn validate_request_object_claims_rejects_expired_request_object() {
    let params = AuthorizationRequestParams {
        response_type: "code".to_string(),
        client_id: Uuid::nil().to_string(),
        redirect_uri: "https://client.example.com/callback".to_string(),
        scope: "openid profile".to_string(),
        state: "state123".to_string(),
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
    let payload = serde_json::json!({
        "exp": chrono::Utc::now().timestamp() - 60
    });

    let result = AuthorizeService::validate_request_object_claims(
        &params,
        &payload,
        &Url::parse("https://identity.example.com/").unwrap(),
    );

    assert!(result.is_err());
}

#[test]
fn validate_request_object_claims_rejects_future_not_before() {
    let params = AuthorizationRequestParams {
        response_type: "code".to_string(),
        client_id: Uuid::nil().to_string(),
        redirect_uri: "https://client.example.com/callback".to_string(),
        scope: "openid profile".to_string(),
        state: "state123".to_string(),
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
    let payload = serde_json::json!({
        "nbf": chrono::Utc::now().timestamp() + 60
    });

    let result = AuthorizeService::validate_request_object_claims(
        &params,
        &payload,
        &Url::parse("https://identity.example.com/").unwrap(),
    );

    assert!(result.is_err());
}
