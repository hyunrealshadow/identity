use std::collections::HashSet;

use http::{HeaderMap, StatusCode, header};
use identity_application::error::{AppError, codes::common::CommonErrorCode};
use identity_domain::openid_connect::{
    AuthorizationRequest, OAuthErrorCode, PromptValue, ResponseType, ScopeSet,
};
use identity_infrastructure::test_app_state_with_mock_settings;
use salvo::{
    Depot, Response, Writer,
    test::{ResponseExt, TestClient},
};
use url::Url;
use uuid::Uuid;

use super::super::{
    request::RawAuthorizeRequest,
    response::{AuthorizationWebError, redirect_oauth_error_response},
};

async fn response_body_text(mut response: Response) -> String {
    response.take_string().await.unwrap()
}

#[tokio::test]
async fn action_error_boundary_never_redirects_without_a_registered_client() {
    let state = test_app_state_with_mock_settings().await;
    let mut depot = Depot::new();
    depot.insert_typed(state);
    depot.insert_typed(RawAuthorizeRequest {
        client_id: Some(identity_domain::openid_connect::identifier::client_id(
            Uuid::nil(),
        )),
        redirect_uri: Some("https://unregistered.example/callback".to_owned()),
        scope: Some("openid".to_owned()),
        ..Default::default()
    });
    let mut request = TestClient::get("http://localhost/oauth2/authorize").build();
    let mut response = Response::new();
    AuthorizationWebError(AppError::from_code(CommonErrorCode::InvalidScope))
        .write(&mut request, &mut depot, &mut response)
        .await;

    assert_eq!(response.status_code, Some(StatusCode::BAD_REQUEST));
    assert!(response.headers().get(header::LOCATION).is_none());
    assert!(response_body_text(response).await.contains("invalid_scope"));
}

#[tokio::test]
async fn authorize_redirects_oauth_error_after_redirect_uri_validation() {
    let request = AuthorizationRequest {
        resources: Vec::new(),
        response_type: ResponseType::Code,
        response_mode: None,
        client_id: Uuid::nil(),
        redirect_uri: Url::parse("https://client.example.com/callback").unwrap(),
        redirect_uri_raw: "https://client.example.com/callback".to_owned(),
        redirect_uri_was_supplied: true,
        scope: ScopeSet::parse("openid").unwrap(),
        state: "state".to_string(),
        nonce: None,
        display: None,
        prompt: Some(HashSet::from([PromptValue::None])),
        max_age: None,
        ui_locales: None,
        claims_locales: None,
        id_token_hint: None,
        login_hint: None,
        acr_values: None,
        claims: None,
        request_uri: None,
        code_challenge: None,
        code_challenge_method: None,
    };

    let response = redirect_oauth_error_response(
        &test_app_state_with_mock_settings().await,
        &HeaderMap::new(),
        &request,
        OAuthErrorCode::LoginRequired,
    );

    assert_eq!(response.status_code, Some(StatusCode::SEE_OTHER));
    let location = response.headers().get(header::LOCATION).unwrap();
    assert!(location.to_str().unwrap().contains("error=login_required"));
}

#[tokio::test]
async fn authorize_redirects_implicit_oauth_error_in_fragment() {
    let request = AuthorizationRequest {
        resources: Vec::new(),
        response_type: ResponseType::IdToken,
        response_mode: None,
        client_id: Uuid::nil(),
        redirect_uri: Url::parse("https://client.example.com/callback").unwrap(),
        redirect_uri_raw: "https://client.example.com/callback".to_owned(),
        redirect_uri_was_supplied: true,
        scope: ScopeSet::parse("openid").unwrap(),
        state: "state".to_string(),
        nonce: Some("nonce".to_string()),
        display: None,
        prompt: Some(HashSet::from([PromptValue::None])),
        max_age: None,
        ui_locales: None,
        claims_locales: None,
        id_token_hint: None,
        login_hint: None,
        acr_values: None,
        claims: None,
        request_uri: None,
        code_challenge: None,
        code_challenge_method: None,
    };

    let response = redirect_oauth_error_response(
        &test_app_state_with_mock_settings().await,
        &HeaderMap::new(),
        &request,
        OAuthErrorCode::LoginRequired,
    );

    assert_eq!(response.status_code, Some(StatusCode::SEE_OTHER));
    let location = response.headers().get(header::LOCATION).unwrap();
    let location = Url::parse(location.to_str().unwrap()).unwrap();
    assert_eq!(location.query(), None);
    assert_eq!(
        location.fragment(),
        Some(
            "error=login_required&error_description=The+user+must+sign+in+to+continue.&state=state&iss=https%3A%2F%2Fidentity.example.com%2F"
        )
    );
}

#[tokio::test]
async fn authorize_redirects_hybrid_oauth_error_in_fragment() {
    let request = AuthorizationRequest {
        resources: Vec::new(),
        response_type: ResponseType::CodeIdToken,
        response_mode: None,
        client_id: Uuid::nil(),
        redirect_uri: Url::parse("https://client.example.com/callback").unwrap(),
        redirect_uri_raw: "https://client.example.com/callback".to_owned(),
        redirect_uri_was_supplied: true,
        scope: ScopeSet::parse("openid").unwrap(),
        state: "state".to_string(),
        nonce: Some("nonce".to_string()),
        display: None,
        prompt: Some(HashSet::from([PromptValue::None])),
        max_age: None,
        ui_locales: None,
        claims_locales: None,
        id_token_hint: None,
        login_hint: None,
        acr_values: None,
        claims: None,
        request_uri: None,
        code_challenge: None,
        code_challenge_method: None,
    };

    let response = redirect_oauth_error_response(
        &test_app_state_with_mock_settings().await,
        &HeaderMap::new(),
        &request,
        OAuthErrorCode::LoginRequired,
    );

    assert_eq!(response.status_code, Some(StatusCode::SEE_OTHER));
    let location = response.headers().get(header::LOCATION).unwrap();
    let location = Url::parse(location.to_str().unwrap()).unwrap();
    assert_eq!(location.query(), None);
    assert_eq!(
        location.fragment(),
        Some(
            "error=login_required&error_description=The+user+must+sign+in+to+continue.&state=state&iss=https%3A%2F%2Fidentity.example.com%2F"
        )
    );
}
