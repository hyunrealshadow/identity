mod fixtures;

use fixtures::{consent_test_config, consent_test_state};
use http::{StatusCode, header};
use salvo::{
    Service,
    test::{ResponseExt, TestClient},
};

use crate::{
    controllers::shared::build_session_cookie,
    router::app_router,
};

#[tokio::test]
async fn consent_get_returns_html_by_default() {
    let (state, protected_login_id, session_oid) = consent_test_state().await;
    let app = app_router(state, &consent_test_config());
    let service = Service::new(app);
    let session_cookie = build_session_cookie(&[session_oid], false);

    let response = TestClient::get(format!(
        "http://127.0.0.1:5800/oauth2/consent?login_id={protected_login_id}"
    ))
    .add_header(header::COOKIE, session_cookie, true)
    .send(&service)
    .await;

    assert_eq!(response.status_code, Some(StatusCode::OK));
    assert_eq!(
        response
            .headers()
            .get(header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok()),
        Some("text/html; charset=utf-8"),
    );
}

#[tokio::test]
async fn consent_get_returns_json_when_accept_requests_json() {
    let (state, protected_login_id, session_oid) = consent_test_state().await;
    let app = app_router(state, &consent_test_config());
    let service = Service::new(app);
    let session_cookie = build_session_cookie(&[session_oid], false);

    let mut response = TestClient::get(format!(
        "http://127.0.0.1:5800/oauth2/consent?login_id={protected_login_id}"
    ))
    .add_header(header::COOKIE, session_cookie, true)
    .add_header(header::ACCEPT, "application/json", true)
    .send(&service)
    .await;

    assert_eq!(response.status_code, Some(StatusCode::OK));
    let body = response.take_string().await.unwrap();
    assert!(body.contains("\"login_id\""), "{body}");
    assert!(body.contains("\"client_name\""), "{body}");
}

#[test]
fn accepts_json_rejects_zero_quality_json_media_type() {
    let result = super::accepts_json(Some("application/json;q=0"));

    assert!(!result);
}

#[test]
fn accepts_json_rejects_non_exact_json_media_type() {
    let result = super::accepts_json(Some("application/json-patch+json"));

    assert!(!result);
}

#[test]
fn consent_post_with_only_json_accept_still_uses_form_branch() {
    let result = super::expects_json_post(
        Some("application/json"),
        Some("application/x-www-form-urlencoded"),
    );

    assert!(!result);
}

#[test]
fn consent_post_with_only_json_content_type_still_uses_form_branch() {
    let result = super::expects_json_post(Some("text/html"), Some("application/json"));

    assert!(!result);
}

#[test]
fn consent_post_returns_json_only_when_accept_and_content_type_are_json() {
    let result = super::expects_json_post(Some("application/json"), Some("application/json"));

    assert!(result);
}

#[tokio::test]
async fn consent_post_redirects_back_to_oauth2_continue_after_approve() {
    let (state, protected_login_id, session_oid) = consent_test_state().await;
    let app = app_router(state, &consent_test_config());
    let service = Service::new(app);
    let session_cookie = build_session_cookie(&[session_oid], false);

    let mut csrf_page = TestClient::get(format!(
        "http://127.0.0.1:5800/oauth2/consent?login_id={protected_login_id}"
    ))
    .add_header(header::COOKIE, session_cookie.clone(), true)
    .send(&service)
    .await;
    let csrf_cookie = csrf_page
        .headers()
        .get(header::SET_COOKIE)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| {
            value
                .split(';')
                .find_map(|segment| segment.trim().strip_prefix("salvo.csrf="))
        })
        .unwrap()
        .to_owned();
    let csrf_body = csrf_page.take_string().await.unwrap();
    let csrf_token = csrf_body
        .split("name=\"csrf_token\" value=\"")
        .nth(1)
        .and_then(|tail| tail.split('"').next())
        .unwrap()
        .to_owned();

    let response = TestClient::post("http://127.0.0.1:5800/oauth2/consent")
        .add_header(
            header::COOKIE,
            format!("{session_cookie}; salvo.csrf={csrf_cookie}"),
            true,
        )
        .add_header("x-csrf-token", csrf_token.clone(), true)
        .form(&[
            ("login_id", protected_login_id.as_str()),
            ("decision", "approve"),
            ("csrf_token", csrf_token.as_str()),
        ])
        .send(&service)
        .await;

    assert_eq!(response.status_code, Some(StatusCode::SEE_OTHER));
    assert!(
        response
            .headers()
            .get(header::LOCATION)
            .unwrap()
            .to_str()
            .unwrap()
            .starts_with("/oauth2/continue?login_id=")
    );
}

#[tokio::test]
async fn consent_template_no_longer_auto_submits_for_auto_approve() {
    let template_path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join("assets/views/oauth2/consent.html");
    let body = tokio::fs::read_to_string(template_path).await.unwrap();

    assert!(!body.contains("auto_approve"), "{body}");
}

#[tokio::test]
async fn consent_page_keeps_inline_script_csp_header() {
    let (state, protected_login_id, session_oid) = consent_test_state().await;
    let app = app_router(state, &consent_test_config());
    let service = Service::new(app);
    let session_cookie = build_session_cookie(&[session_oid], false);

    let mut response = TestClient::get(format!(
        "http://127.0.0.1:5800/oauth2/consent?login_id={protected_login_id}"
    ))
    .add_header(header::COOKIE, session_cookie, true)
    .send(&service)
    .await;

    assert_eq!(response.status_code, Some(StatusCode::OK));
    let body = response.take_string().await.unwrap();
    assert!(body.contains("consent-form"), "{body}");
    assert_eq!(
        response
            .headers()
            .get("content-security-policy")
            .and_then(|value| value.to_str().ok()),
        Some("default-src 'self'; script-src 'unsafe-inline'"),
    );
}
