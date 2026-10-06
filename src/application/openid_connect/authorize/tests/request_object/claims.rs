use chrono::Utc;
use identity_domain::openid_connect::ClaimsRequestSection;
use serde_json::{json, to_string};

use crate::openid_connect::authorize::tests::fixtures::*;
use crate::openid_connect::authorize::tests::*;

#[test]
fn validate_request_object_claims_rejects_future_issued_at() {
    let mut params = params("openid profile");
    params.state = "state-123".to_string();
    let payload = json!({
        "response_type": "code",
        "client_id": TEST_CLIENT_ID.to_string(),
        "redirect_uri": "https://client.example.com/callback",
        "scope": "openid profile",
        "state": "state-123",
        "iat": Utc::now().timestamp() + 60,
    });

    let result = AuthorizeService::validate_request_object_claims(
        &params,
        &payload,
        &Url::parse("https://identity.example.com/").unwrap(),
    );

    assert!(result.is_err());
    assert_eq!(result.unwrap_err().code(), 23033); // RequestObjectIatFuture
}

#[test]
fn validate_request_object_claims_rejects_client_id_mismatch() {
    let params = AuthorizationRequestParams {
        response_type: "code".to_string(),
        response_mode: None,
        client_id: Uuid::nil().to_string(),
        redirect_uri: "https://client.example.com/callback".to_string(),
        scope: "openid profile".to_string(),
        resources: Vec::new(),
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
    let payload = json!({
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
        response_mode: None,
        client_id: Uuid::nil().to_string(),
        redirect_uri: "https://client.example.com/callback".to_string(),
        scope: "openid profile".to_string(),
        resources: Vec::new(),
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
    let payload = json!({
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
        response_mode: None,
        client_id: Uuid::nil().to_string(),
        redirect_uri: "https://client.example.com/callback".to_string(),
        scope: "openid profile".to_string(),
        resources: Vec::new(),
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
    let payload = json!({
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
        response_mode: None,
        client_id: Uuid::nil().to_string(),
        redirect_uri: "https://client.example.com/callback".to_string(),
        scope: "openid profile".to_string(),
        resources: Vec::new(),
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
    let payload = json!({
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
        response_mode: None,
        client_id: Uuid::nil().to_string(),
        redirect_uri: "https://client.example.com/callback".to_string(),
        scope: "openid profile".to_string(),
        resources: Vec::new(),
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
    let payload = json!({
        "exp": Utc::now().timestamp() - 60
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
        response_mode: None,
        client_id: Uuid::nil().to_string(),
        redirect_uri: "https://client.example.com/callback".to_string(),
        scope: "openid profile".to_string(),
        resources: Vec::new(),
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
    let payload = json!({
        "nbf": Utc::now().timestamp() + 60
    });

    let result = AuthorizeService::validate_request_object_claims(
        &params,
        &payload,
        &Url::parse("https://identity.example.com/").unwrap(),
    );

    assert!(result.is_err());
}

#[test]
fn parse_claims_request_accepts_round_trip_serialization() {
    // Regression for oidcc-claims-essential: `AuthorizationRequestData`
    // stores `claims` by serializing a `ClaimsRequest`. A serialized
    // `ClaimsRequest` may carry `"id_token": null` (or omit it); re-parsing
    // such a document must not fail with ClaimsFieldNotObject.

    let parsed =
        AuthorizeService::parse_claims_request(r#"{"userinfo":{"name":{"essential":true}}}"#)
            .unwrap();
    assert_eq!(
        parsed.essential_claim_names(&[ClaimsRequestSection::UserInfo]),
        vec!["name"]
    );

    // The serialized form (the value persisted to storage) must round-trip.
    let serialized = to_string(&parsed).unwrap();
    let reparsed = AuthorizeService::parse_claims_request(&serialized).unwrap();
    assert_eq!(parsed, reparsed);

    // Explicit `null` sections (legacy serialized form) are tolerated.
    let reparsed_null = AuthorizeService::parse_claims_request(
        r#"{"id_token":null,"userinfo":{"name":{"essential":true}}}"#,
    )
    .unwrap();
    assert_eq!(parsed, reparsed_null);

    // A non-object section value is still rejected.
    let err = AuthorizeService::parse_claims_request(r#"{"userinfo":"nope"}"#).unwrap_err();
    assert_eq!(err.code(), 23038); // ClaimsFieldNotObject
}
