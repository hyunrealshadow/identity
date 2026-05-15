mod fixtures;

use chrono::{Duration, Utc};
use fixtures::{
    ContinueFixture, continue_selected_session_state, continue_selected_session_with_consent_state,
    continue_selected_session_with_fixture, continue_selected_session_with_prompt_state,
    continue_state, continue_test_state,
};
use http::{StatusCode, header};
use identity_domain::auth::SessionOid;
use identity_domain::client_authorization::ConsentState;
use salvo::{Service, test::TestClient};

use crate::controllers::shared::build_session_cookie;

fn location(response: &salvo::Response) -> &str {
    response
        .headers()
        .get(header::LOCATION)
        .and_then(|value| value.to_str().ok())
        .unwrap()
}

fn query_param(location: &str, name: &str) -> Option<String> {
    url::Url::parse(location)
        .ok()?
        .query_pairs()
        .find(|(key, _)| key == name)
        .map(|(_, value)| value.into_owned())
}

async fn call_continue_with_state(
    login_id: &str,
    state: identity_infrastructure::AppState,
    session_cookie: Option<String>,
) -> salvo::Response {
    let app = crate::controllers::oauth2::routes().hoop(salvo::affix_state::inject(state));
    let service = Service::new(app);

    let request = TestClient::get(format!(
        "http://127.0.0.1:5800/oauth2/continue?login_id={login_id}"
    ));
    let request = if let Some(cookie) = session_cookie {
        request.add_header(header::COOKIE, cookie, true)
    } else {
        request
    };

    request.send(&service).await
}

#[tokio::test]
async fn continue_without_sessions_redirects_to_login() {
    let (state, protected_login_id) = continue_test_state().await;

    let response = call_continue_with_state(&protected_login_id, state, None).await;

    assert_eq!(response.status_code, Some(StatusCode::SEE_OTHER));
    assert_eq!(
        location(&response),
        format!(
            "/login?login_id={}",
            urlencoding::encode(&protected_login_id)
        )
    );
}

#[tokio::test]
async fn continue_with_selected_session_and_pending_consent_redirects_to_consent() {
    let (state, protected_login_id, session_oid) = continue_selected_session_state().await;
    let session_cookie = build_session_cookie(&state, &[SessionOid(session_oid)], false)
        .await
        .unwrap();

    let response = call_continue_with_state(&protected_login_id, state, Some(session_cookie)).await;

    assert_eq!(response.status_code, Some(StatusCode::SEE_OTHER));
    assert_eq!(
        location(&response),
        format!(
            "/oauth2/consent?login_id={}",
            urlencoding::encode(&protected_login_id)
        )
    );
}

#[tokio::test]
async fn continue_with_silent_pending_consent_returns_consent_required() {
    let (state, protected_login_id, session_oid) =
        continue_selected_session_with_prompt_state("none").await;
    let session_cookie = build_session_cookie(&state, &[SessionOid(session_oid)], false)
        .await
        .unwrap();

    let response = call_continue_with_state(&protected_login_id, state, Some(session_cookie)).await;

    assert_eq!(response.status_code, Some(StatusCode::SEE_OTHER));
    assert_eq!(
        query_param(location(&response), "error").as_deref(),
        Some("consent_required")
    );
    assert_eq!(
        query_param(location(&response), "state").as_deref(),
        Some("state-123")
    );
}

#[tokio::test]
async fn continue_with_approved_consent_completes_authorization() {
    let (state, protected_login_id, session_oid) =
        continue_selected_session_with_consent_state(ConsentState::Approved).await;
    let session_cookie = build_session_cookie(&state, &[SessionOid(session_oid)], false)
        .await
        .unwrap();

    let response = call_continue_with_state(&protected_login_id, state, Some(session_cookie)).await;

    assert_eq!(response.status_code, Some(StatusCode::SEE_OTHER));
    assert_eq!(
        query_param(location(&response), "state").as_deref(),
        Some("state-123")
    );
    assert!(query_param(location(&response), "code").is_some());
}

#[tokio::test]
async fn continue_with_denied_consent_returns_access_denied() {
    let (state, protected_login_id, session_oid) =
        continue_selected_session_with_consent_state(ConsentState::Denied).await;
    let session_cookie = build_session_cookie(&state, &[SessionOid(session_oid)], false)
        .await
        .unwrap();

    let response = call_continue_with_state(&protected_login_id, state, Some(session_cookie)).await;

    assert_eq!(response.status_code, Some(StatusCode::SEE_OTHER));
    assert_eq!(
        query_param(location(&response), "error").as_deref(),
        Some("access_denied")
    );
    assert_eq!(
        query_param(location(&response), "state").as_deref(),
        Some("state-123")
    );
}

#[tokio::test]
async fn continue_skips_consent_when_client_allows_it() {
    let (state, protected_login_id, session_oid) =
        continue_selected_session_with_fixture(ContinueFixture {
            skip_consent: true,
            ..ContinueFixture::default()
        })
        .await;
    let session_cookie = build_session_cookie(&state, &[SessionOid(session_oid)], false)
        .await
        .unwrap();

    let response = call_continue_with_state(&protected_login_id, state, Some(session_cookie)).await;

    assert_eq!(response.status_code, Some(StatusCode::SEE_OTHER));
    assert_eq!(
        query_param(location(&response), "state").as_deref(),
        Some("state-123")
    );
    assert!(query_param(location(&response), "code").is_some());
}

#[tokio::test]
async fn continue_auto_selects_active_session_before_redirecting_to_consent() {
    let session_oid = uuid::Uuid::new_v4();
    let user_oid = uuid::Uuid::new_v4();
    let (state, protected_login_id, _) = continue_state(ContinueFixture {
        active_session: Some((session_oid, user_oid)),
        ..ContinueFixture::default()
    })
    .await;
    let session_cookie = build_session_cookie(&state, &[SessionOid(session_oid)], false)
        .await
        .unwrap();

    let response = call_continue_with_state(&protected_login_id, state, Some(session_cookie)).await;

    assert_eq!(response.status_code, Some(StatusCode::SEE_OTHER));
    assert_eq!(
        location(&response),
        format!(
            "/oauth2/consent?login_id={}",
            urlencoding::encode(&protected_login_id)
        )
    );
}

#[tokio::test]
async fn continue_with_select_account_prompt_redirects_to_login() {
    let (state, protected_login_id, session_oid) =
        continue_selected_session_with_prompt_state("select_account").await;
    let session_cookie = build_session_cookie(&state, &[SessionOid(session_oid)], false)
        .await
        .unwrap();

    let response = call_continue_with_state(&protected_login_id, state, Some(session_cookie)).await;

    assert_eq!(response.status_code, Some(StatusCode::SEE_OTHER));
    assert_eq!(
        location(&response),
        format!(
            "/login?login_id={}",
            urlencoding::encode(&protected_login_id)
        )
    );
}

#[tokio::test]
async fn continue_with_silent_request_and_no_session_returns_login_required() {
    let (state, protected_login_id, _) = continue_state(ContinueFixture {
        prompt: Some("none".to_owned()),
        ..ContinueFixture::default()
    })
    .await;

    let response = call_continue_with_state(&protected_login_id, state, None).await;

    assert_eq!(response.status_code, Some(StatusCode::SEE_OTHER));
    assert_eq!(
        query_param(location(&response), "error").as_deref(),
        Some("login_required")
    );
    assert_eq!(
        query_param(location(&response), "state").as_deref(),
        Some("state-123")
    );
}

#[tokio::test]
async fn continue_with_expired_session_and_silent_prompt_returns_login_required() {
    let (state, protected_login_id, session_oid) =
        continue_selected_session_with_fixture(ContinueFixture {
            prompt: Some("none".to_owned()),
            max_age: Some(60),
            session_created_at: Some(Utc::now() - Duration::seconds(120)),
            ..ContinueFixture::default()
        })
        .await;
    let session_cookie = build_session_cookie(&state, &[SessionOid(session_oid)], false)
        .await
        .unwrap();

    let response = call_continue_with_state(&protected_login_id, state, Some(session_cookie)).await;

    assert_eq!(response.status_code, Some(StatusCode::SEE_OTHER));
    assert_eq!(
        query_param(location(&response), "error").as_deref(),
        Some("login_required")
    );
    assert_eq!(
        query_param(location(&response), "state").as_deref(),
        Some("state-123")
    );
}
