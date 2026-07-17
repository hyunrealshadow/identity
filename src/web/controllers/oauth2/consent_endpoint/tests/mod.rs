mod fixtures;

use fixtures::{consent_test_config, consent_test_state, consent_test_state_with_scope};
use http::{StatusCode, header};
use identity_domain::auth::SessionOid;
use salvo::{
    Service,
    test::{ResponseExt, TestClient},
};

use crate::{
    controllers::shared::{SESSION_HEADER_NAME, build_session_cookie},
    router::app_router,
};

fn session_header(cookie: &str) -> &str {
    cookie
        .strip_prefix("sessions=")
        .and_then(|value| value.split(';').next())
        .expect("test session cookie should contain a JSON session list")
}

#[tokio::test]
async fn consent_get_is_a_json_api_without_content_negotiation() {
    let (state, protected_login_id, session_oid) = consent_test_state().await;
    let session_cookie = build_session_cookie(&state, &[SessionOid(session_oid)])
        .await
        .unwrap();
    let service = Service::new(app_router(state, &consent_test_config()));

    let mut response = TestClient::get(format!(
        "http://127.0.0.1:5800/oauth2/consent?login_id={protected_login_id}"
    ))
    .add_header(SESSION_HEADER_NAME, session_header(&session_cookie), true)
    .send(&service)
    .await;

    assert_eq!(response.status_code, Some(StatusCode::OK));
    assert_eq!(
        response
            .headers()
            .get(header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok()),
        Some("application/json; charset=utf-8"),
    );
    let body = response.take_string().await.unwrap();
    assert!(body.contains("\"login_id\""), "{body}");
    assert!(body.contains("\"client_name\""), "{body}");
}

#[tokio::test]
async fn consent_get_rejects_invalid_stored_scope() {
    let (state, protected_login_id, session_oid) =
        consent_test_state_with_scope("openid unknown_scope").await;
    let session_cookie = build_session_cookie(&state, &[SessionOid(session_oid)])
        .await
        .unwrap();
    let service = Service::new(app_router(state, &consent_test_config()));

    let response = TestClient::get(format!(
        "http://127.0.0.1:5800/oauth2/consent?login_id={protected_login_id}"
    ))
    .add_header(SESSION_HEADER_NAME, session_header(&session_cookie), true)
    .send(&service)
    .await;

    assert_eq!(response.status_code, Some(StatusCode::UNPROCESSABLE_ENTITY));
}

#[tokio::test]
async fn consent_post_accepts_json_and_returns_continue_uri() {
    let (state, protected_login_id, session_oid) = consent_test_state().await;
    let session_cookie = build_session_cookie(&state, &[SessionOid(session_oid)])
        .await
        .unwrap();
    let service = Service::new(app_router(state, &consent_test_config()));

    let mut context_response = TestClient::get(format!(
        "http://127.0.0.1:5800/oauth2/consent?login_id={protected_login_id}"
    ))
    .add_header(SESSION_HEADER_NAME, session_header(&session_cookie), true)
    .send(&service)
    .await;
    assert!(context_response.headers().get(header::SET_COOKIE).is_none());
    let context: serde_json::Value =
        serde_json::from_str(&context_response.take_string().await.unwrap()).unwrap();
    let csrf_token = context["csrf_token"].as_str().unwrap();

    let mut response = TestClient::post("http://127.0.0.1:5800/oauth2/consent")
        .add_header(SESSION_HEADER_NAME, session_header(&session_cookie), true)
        .add_header("x-csrf-token", csrf_token, true)
        .raw_json(format!(
            r#"{{"login_id":"{protected_login_id}","decision":"approve"}}"#
        ))
        .send(&service)
        .await;

    assert_eq!(response.status_code, Some(StatusCode::OK));
    let body = response.take_string().await.unwrap();
    assert!(body.contains("\"status\":\"approved\""), "{body}");
    assert!(body.contains("\"continue_uri\""), "{body}");
}
