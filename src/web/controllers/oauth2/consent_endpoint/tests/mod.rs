mod fixtures;

use fixtures::{
    DEVICE_USER_CODE, consent_test_config, consent_test_state, consent_test_state_with_scope,
    device_decision_test_state, device_verification_test_state, unknown_user_code_test_state,
};
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
    assert!(!body.contains("\"logo_uri\""), "{body}");
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
    let db = state.resources().db().clone();
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

    let body = response.take_string().await.unwrap();
    assert_eq!(response.status_code, Some(StatusCode::OK), "{body}");
    assert!(body.contains("\"status\":\"approved\""), "{body}");
    let payload: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert!(
        payload["continue_uri"]
            .as_str()
            .is_some_and(|uri| uri.starts_with("https://identity.example.com/oauth2/continue?")),
        "{body}"
    );
    let statements = format!("{:?}", db.into_transaction_log());
    assert!(
        statements.contains("INSERT INTO \\\"user_client_consent\\\""),
        "{statements}"
    );
}

#[tokio::test]
async fn consent_post_without_a_csrf_token_is_rejected() {
    let (state, protected_login_id, _) = consent_test_state().await;
    let db = state.resources().db().clone();
    let service = Service::new(app_router(state, &consent_test_config()));

    // The device approval rides on this same route, so an unprotected POST
    // must not reach the decision handler for either interaction kind.
    let response = TestClient::post("http://127.0.0.1:5800/oauth2/consent")
        .raw_json(format!(
            r#"{{"login_id":"{protected_login_id}","decision":"approve"}}"#
        ))
        .send(&service)
        .await;

    assert_eq!(response.status_code, Some(StatusCode::FORBIDDEN));
    let statements = format!("{:?}", db.into_transaction_log());
    assert!(
        !statements.contains("user_client_consent"),
        "an unprotected POST must not write consent: {statements}"
    );
}

#[tokio::test]
async fn device_verification_reports_an_unknown_code_before_any_session_is_required() {
    let (state, _, _) = unknown_user_code_test_state().await;
    let service = Service::new(app_router(state, &consent_test_config()));

    // The entry form checks the code first, so the answer must not depend on a
    // browser session: a code that matches no request is reported as unknown
    // and the user is never sent into a sign-in for a request that does not
    // exist.
    let mut response = TestClient::get("http://127.0.0.1:5800/oauth2/consent?user_code=ZZZZ-ZZZZ")
        .send(&service)
        .await;

    assert_eq!(response.status_code, Some(StatusCode::UNPROCESSABLE_ENTITY));
    let body = response.take_string().await.unwrap();
    assert!(body.contains("\"code\":26010"), "{body}");
}

#[tokio::test]
async fn device_verification_checks_a_real_code_without_requiring_a_session() {
    let (state, _, _) = device_verification_test_state().await;
    let service = Service::new(app_router(state, &consent_test_config()));

    let response = TestClient::get(format!(
        "http://127.0.0.1:5800/oauth2/consent?user_code={DEVICE_USER_CODE}"
    ))
    .send(&service)
    .await;

    assert_eq!(response.status_code, Some(StatusCode::OK));
}

#[tokio::test]
async fn device_code_check_does_not_choose_an_account() {
    let (state, _, _) = device_verification_test_state().await;
    let service = Service::new(app_router(state, &consent_test_config()));

    // The code check answers read-only and never chooses an account: it
    // returns only what the entry form needs to start the login flow, even
    // when the browser presents sessions.
    let mut response = TestClient::get(format!(
        "http://127.0.0.1:5800/oauth2/consent?user_code={DEVICE_USER_CODE}"
    ))
    .send(&service)
    .await;

    assert_eq!(response.status_code, Some(StatusCode::OK));
    let body = response.take_string().await.unwrap();
    let payload: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(payload["user_code"], "WDJB-MJHT");
    assert_eq!(payload["status"], "pending");
    assert!(payload.get("account").is_none());
    assert!(payload.get("session_id").is_none());
}

#[tokio::test]
async fn device_decision_is_recorded_against_the_bound_login() {
    let (state, protected_login_id, session_oid) = device_decision_test_state().await;
    let db = state.resources().db().clone();
    let service = Service::new(app_router(state, &consent_test_config()));

    // The page is addressed by the login the device request was claimed with,
    // and it describes that login's account rather than picking one from the
    // browser transport.
    let mut description = TestClient::get(format!(
        "http://127.0.0.1:5800/oauth2/consent?login_id={protected_login_id}"
    ))
    .add_header("x-sessions", format!("[\"{session_oid}\"]"), true)
    .send(&service)
    .await;
    let body = description.take_string().await.unwrap();
    let payload: serde_json::Value = serde_json::from_str(&body).unwrap();
    let csrf_token = payload["csrf_token"].as_str().unwrap_or_else(|| {
        panic!(
            "expected csrf_token in {body}; queries: {:?}",
            db.clone().into_transaction_log()
        )
    });
    assert_eq!(payload["account"]["email"], "ada@example.com");

    // A browser that presents another session than the bound one cannot
    // approve: the decision is refused and nothing is written.
    let response = TestClient::post("http://127.0.0.1:5800/oauth2/consent")
        .add_header("x-csrf-token", csrf_token, true)
        .raw_json(format!(
            r#"{{"login_id":"{protected_login_id}","decision":"approve"}}"#
        ))
        .send(&service)
        .await;

    assert_eq!(response.status_code, Some(StatusCode::UNAUTHORIZED));
    let statements = format!("{:?}", db.into_transaction_log());
    assert!(
        !statements.contains("UPDATE"),
        "a refused decision must not write: {statements}"
    );
}

#[tokio::test]
async fn device_begin_preserves_unknown_code_error_for_the_entry_form() {
    let (bootstrap, _, _) = device_verification_test_state().await;
    let bootstrap = Service::new(app_router(bootstrap, &consent_test_config()));
    let mut response = TestClient::get(format!(
        "http://127.0.0.1:5800/oauth2/consent?user_code={DEVICE_USER_CODE}"
    ))
    .send(&bootstrap)
    .await;
    let body: serde_json::Value =
        serde_json::from_str(&response.take_string().await.unwrap()).unwrap();
    let (state, _, _) = unknown_user_code_test_state().await;
    let service = Service::new(app_router(state, &consent_test_config()));
    let mut response = TestClient::post("http://127.0.0.1:5800/oauth2/device/begin")
        .add_header("x-csrf-token", body["csrf_token"].as_str().unwrap(), true)
        .raw_json(r#"{"user_code":"ZZZZ-ZZZZ"}"#)
        .send(&service)
        .await;
    let body = response.take_string().await.unwrap();
    assert_eq!(
        response.status_code,
        Some(StatusCode::UNPROCESSABLE_ENTITY),
        "{body}"
    );
    assert!(body.contains("\"code\":26010"), "{body}");
}

#[tokio::test]
async fn consent_route_rejects_ambiguous_or_missing_interaction_identifiers() {
    let (state, _, _) = consent_test_state().await;
    let service = Service::new(app_router(state, &consent_test_config()));

    let both =
        TestClient::get("http://127.0.0.1:5800/oauth2/consent?login_id=abc&user_code=WDJB-MJHT")
            .send(&service)
            .await;
    assert_ne!(both.status_code, Some(StatusCode::OK));

    let neither = TestClient::get("http://127.0.0.1:5800/oauth2/consent")
        .send(&service)
        .await;
    assert_ne!(neither.status_code, Some(StatusCode::OK));
}
