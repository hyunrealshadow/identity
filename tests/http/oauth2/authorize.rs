use super::interaction_fixtures::authorize_first_hop_state;
use http::{StatusCode, header};
use identity_domain::auth::SessionOid;
use identity_infrastructure::{AppState, test_app_state_with_mock_settings};
use identity_web::controllers::{oauth2::routes, shared::build_session_cookie};
use salvo::{
    Response, Service,
    affix_state::inject,
    test::{ResponseExt, TestClient},
};
use url::Url;
async fn response_body_text(mut response: Response) -> String {
    response.take_string().await.unwrap()
}
async fn call_authorize(uri: &str) -> Response {
    call_authorize_with_state(uri, test_app_state_with_mock_settings().await, None).await
}
async fn call_authorize_with_state(
    uri: &str,
    state: AppState,
    session_cookie: Option<String>,
) -> Response {
    let service = Service::new(routes().hoop(inject(state)));
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
        "/oauth2/authorize?client_id=00000000-0000-0000-0000-000000000000&response_type=code&scope=openid&redirect_uri=https%3A%2F%2Fclient.example.com%2Fcallback&state=state123&code_challenge=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA&code_challenge_method=S256&ui_locales=zh-CN%20en-US",
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
    let destination = Url::parse(&format!("https://identity.example.com{location}")).unwrap();
    assert_eq!(
        destination
            .query_pairs()
            .find(|(name, _)| name == "ui_locales")
            .unwrap()
            .1,
        "zh-CN en-US"
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
