mod fixtures;

use fixtures::{consent_test_config, consent_test_state, consent_test_state_with_scope};
use http::{StatusCode, header};
use salvo::{
    Service,
    test::{ResponseExt, TestClient},
};

use crate::router::app_router;

#[tokio::test]
async fn consent_get_is_a_json_api_without_content_negotiation() {
    let (state, protected_login_id, _) = consent_test_state().await;
    let service = Service::new(app_router(state, &consent_test_config()));

    let mut response = TestClient::get(format!(
        "http://127.0.0.1:5800/oauth2/consent?login_id={protected_login_id}"
    ))
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
    let (state, protected_login_id, _) =
        consent_test_state_with_scope("openid unknown_scope").await;
    let service = Service::new(app_router(state, &consent_test_config()));

    let response = TestClient::get(format!(
        "http://127.0.0.1:5800/oauth2/consent?login_id={protected_login_id}"
    ))
    .send(&service)
    .await;

    assert_eq!(response.status_code, Some(StatusCode::UNPROCESSABLE_ENTITY));
}

#[tokio::test]
async fn consent_post_accepts_json_and_returns_continue_uri() {
    let (state, protected_login_id, _) = consent_test_state().await;
    let service = Service::new(app_router(state, &consent_test_config()));

    let mut context_response = TestClient::get(format!(
        "http://127.0.0.1:5800/oauth2/consent?login_id={protected_login_id}"
    ))
    .send(&service)
    .await;
    assert!(context_response.headers().get(header::SET_COOKIE).is_none());
    let context: serde_json::Value =
        serde_json::from_str(&context_response.take_string().await.unwrap()).unwrap();
    let csrf_token = context["csrf_token"].as_str().unwrap();

    let mut response = TestClient::post("http://127.0.0.1:5800/oauth2/consent")
        .add_header("x-csrf-token", csrf_token, true)
        .raw_json(format!(
            r#"{{"login_id":"{protected_login_id}","decision":"approve"}}"#
        ))
        .send(&service)
        .await;

    assert_eq!(response.status_code, Some(StatusCode::OK));
    let body = response.take_string().await.unwrap();
    assert!(body.contains("\"status\":\"approved\""), "{body}");
    let payload: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert!(
        payload["continue_uri"]
            .as_str()
            .is_some_and(|uri| uri.starts_with("https://identity.example.com/oauth2/continue?")),
        "{body}"
    );
}
