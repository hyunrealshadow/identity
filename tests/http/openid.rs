//! OpenID Connect UserInfo, logout, and session management routes.
use http::{StatusCode, header::HeaderName};
use identity_infrastructure::test_app_state_with_mock_settings;
use identity_web::controllers::openid::routes;
use salvo::{
    Service,
    affix_state::inject,
    test::{ResponseExt, TestClient},
};

#[tokio::test]
async fn check_session_iframe_renders_post_message_script() {
    let app = routes().hoop(inject(test_app_state_with_mock_settings().await));
    let service = Service::new(app);

    let mut response = TestClient::get("http://127.0.0.1:5800/openid/check_session")
        .send(&service)
        .await;

    assert_eq!(response.status_code, Some(StatusCode::OK));
    assert!(
        response
            .headers()
            .get(HeaderName::from_static("content-security-policy"))
            .and_then(|value| value.to_str().ok())
            .is_some_and(|v| v.contains("script-src 'nonce-")),
        "CSP header should use nonce-based script-src"
    );
    let body = response.take_string().await.unwrap();
    assert!(
        body.contains("window.addEventListener(\"message\""),
        "{body}"
    );
    assert!(body.contains("postMessage"), "{body}");
    assert!(body.contains("opBrowserState"), "{body}");
    assert!(body.contains("\"unchanged\""), "{body}");
    assert!(body.contains("\"changed\""), "{body}");
}
#[tokio::test]
async fn logout_route_renders_logged_out_page_without_redirect() {
    let app = routes().hoop(inject(test_app_state_with_mock_settings().await));
    let service = Service::new(app);

    let response = TestClient::get("http://127.0.0.1:5800/openid/logout")
        .send(&service)
        .await;

    assert_eq!(response.status_code, Some(StatusCode::OK));
}
