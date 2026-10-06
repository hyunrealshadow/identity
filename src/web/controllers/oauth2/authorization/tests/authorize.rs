use std::collections::HashSet;

use http::{HeaderMap, StatusCode, header};
use identity_application::error::{AppError, codes::common::CommonErrorCode};
use identity_domain::{
    auth::SessionOid,
    openid_connect::{AuthorizationRequest, OAuthErrorCode, PromptValue, ResponseType, ScopeSet},
};
use identity_infrastructure::{AppState, test_app_state_with_mock_settings};
use salvo::{
    Depot, Response, Service, Writer,
    affix_state::inject,
    test::{ResponseExt, TestClient},
};
use url::Url;
use uuid::Uuid;

use super::super::{
    request::RawAuthorizeRequest,
    response::{AuthorizationWebError, redirect_oauth_error_response},
};
use crate::controllers::{
    oauth2::{routes, tests::interaction_fixtures::authorize_first_hop_state},
    shared::build_session_cookie,
};

async fn response_body_text(mut response: Response) -> String {
    response.take_string().await.unwrap()
}

async fn call_authorize(uri: &str) -> Response {
    let app = routes().hoop(inject(test_app_state_with_mock_settings().await));
    let service = Service::new(app);

    TestClient::get(format!("http://127.0.0.1:5800{uri}"))
        .send(&service)
        .await
}

#[tokio::test]
async fn action_error_boundary_never_redirects_without_a_registered_client() {
    let state = test_app_state_with_mock_settings().await;
    let mut depot = Depot::new();
    depot.insert_typed(state);
    depot.insert_typed(RawAuthorizeRequest {
        client_id: Some(Uuid::nil().to_string()),
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

async fn call_authorize_with_state(
    uri: &str,
    state: AppState,
    session_cookie: Option<String>,
) -> Response {
    let app = routes().hoop(inject(state));
    let service = Service::new(app);

    let request = TestClient::get(format!("http://127.0.0.1:5800{uri}"));
    let request = if let Some(cookie) = session_cookie {
        request.add_header(header::COOKIE, cookie, true)
    } else {
        request
    };

    request.send(&service).await
}

#[tokio::test]
async fn authorize_routes_accept_post_requests() {
    let app = routes().hoop(inject(test_app_state_with_mock_settings().await));
    let service = Service::new(app);

    let response = TestClient::post("http://127.0.0.1:5800/oauth2/authorize")
        .add_header(
            header::CONTENT_TYPE,
            "application/x-www-form-urlencoded",
            true,
        )
        .send(&service)
        .await;

    assert_ne!(response.status_code, Some(StatusCode::METHOD_NOT_ALLOWED));
}

#[tokio::test]
async fn authorize_renders_html_error_page_for_missing_required_fields() {
    let response = call_authorize("/oauth2/authorize?scope=openid").await;

    assert_eq!(response.status_code, Some(StatusCode::BAD_REQUEST));
    let body = response_body_text(response).await;
    assert!(body.contains("Something went wrong"), "{body}");
    assert!(body.contains("href=\"/static/css/error.css\""), "{body}");
    assert!(body.contains("E22002"), "{body}");
    assert!(body.contains("invalid_request"), "{body}");
    assert!(body.contains("Error type"), "{body}");
    assert!(!body.contains("OAuth 2.0 error"), "{body}");
    assert!(!body.contains("HTTP status"), "{body}");
    assert!(
        body.contains("Missing required parameters: client_id, redirect_uri"),
        "{body}"
    );
    assert!(
        !body.contains("Review the request parameters and try again."),
        "{body}"
    );
    assert!(!body.contains("Additional information"), "{body}");
}

#[tokio::test]
async fn authorize_with_reusable_session_redirects_to_oauth2_continue() {
    let (state, session_oid) = authorize_first_hop_state().await;
    let session_cookie = build_session_cookie(&state, &[SessionOid(session_oid)])
        .await
        .unwrap();
    let response = call_authorize_with_state(
        "/oauth2/authorize?client_id=00000000-0000-0000-0000-000000000000&response_type=code&scope=openid&redirect_uri=https%3A%2F%2Fclient.example.com%2Fcallback&state=state123&code_challenge=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA&code_challenge_method=S256",
        state,
        Some(session_cookie),
    )
    .await;

    if response.status_code != Some(StatusCode::SEE_OTHER) {
        let status = response.status_code;
        let body = response_body_text(response).await;
        panic!("expected redirect, got {status:?}: {body}");
    }
    let location = response
        .headers()
        .get(header::LOCATION)
        .unwrap()
        .to_str()
        .unwrap();
    assert!(
        location.starts_with("/oauth2/continue?login_id="),
        "{location}"
    );
}

#[tokio::test]
async fn oauth_client_with_one_redirect_can_omit_redirect_uri() {
    let (state, session_oid) = authorize_first_hop_state().await;
    let session_cookie = build_session_cookie(&state, &[SessionOid(session_oid)])
        .await
        .unwrap();
    let response = call_authorize_with_state(
        "/oauth2/authorize?client_id=00000000-0000-0000-0000-000000000000&response_type=code&scope=profile&state=state123&code_challenge=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA&code_challenge_method=S256",
        state,
        Some(session_cookie),
    )
    .await;
    if response.status_code != Some(StatusCode::SEE_OTHER) {
        let status = response.status_code;
        let body = response_body_text(response).await;
        panic!("expected redirect, got {status:?}: {body}");
    }
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
