use std::{
    collections::HashSet,
    slice,
    sync::{Arc, Mutex},
};

use chrono::{DateTime, Duration, Utc};
use identity_domain::{
    auth::{AMR_PASSWORD, AuthenticationContextClass, model::ActiveSession},
    client_authorization::SelectionSource,
    openid_connect::{AuthorizationRequest, OAuthErrorCode, PromptValue, ResponseType, ScopeSet},
};
use url::Url;
use uuid::Uuid;

use super::super::interaction::{
    FlowDecision, determine_authorize_flow_with_selection_recorder, select_active_session,
};
use super::SessionOid;
use crate::error::{code::AppErrorCode, codes::authorize};

fn request(prompt: Option<HashSet<PromptValue>>, max_age: Option<i32>) -> AuthorizationRequest {
    AuthorizationRequest {
        resources: Vec::new(),
        response_type: ResponseType::Code,
        response_mode: None,
        client_id: Uuid::nil(),
        redirect_uri: Url::parse("https://client.example.com/callback").unwrap(),
        redirect_uri_raw: "https://client.example.com/callback".to_owned(),
        redirect_uri_was_supplied: true,
        scope: ScopeSet::parse("openid").unwrap(),
        state: "state123".to_string(),
        nonce: None,
        display: None,
        prompt,
        max_age,
        ui_locales: None,
        claims_locales: None,
        id_token_hint: None,
        login_hint: None,
        acr_values: None,
        claims: None,
        request_uri: None,
        code_challenge: None,
        code_challenge_method: None,
    }
}

fn active_session(created_at: DateTime<Utc>) -> ActiveSession {
    ActiveSession {
        session_oid: SessionOid(Uuid::new_v4()),
        user_oid: Uuid::new_v4(),
        user_name: "alice".to_string(),
        user_email: "alice@example.com".to_string(),
        user_picture: None,
        last_active_at: Some(created_at),
        expires_at: None,
        created_at,
        authenticated_at: created_at,
        acr: Some(AuthenticationContextClass::SingleFactor),
        amr: vec![AMR_PASSWORD.to_owned()],
    }
}

#[test]
fn select_active_session_prefers_matching_login_hint() {
    let matching = ActiveSession {
        session_oid: SessionOid(Uuid::new_v4()),
        user_oid: Uuid::new_v4(),
        user_name: "alice".to_string(),
        user_email: "alice@example.com".to_string(),
        user_picture: None,
        last_active_at: Some(Utc::now()),
        expires_at: None,
        created_at: Utc::now(),
        authenticated_at: Utc::now(),
        acr: Some(AuthenticationContextClass::SingleFactor),
        amr: vec![AMR_PASSWORD.to_owned()],
    };
    let other = ActiveSession {
        session_oid: SessionOid(Uuid::new_v4()),
        user_oid: Uuid::new_v4(),
        user_name: "bob".to_string(),
        user_email: "bob@example.com".to_string(),
        user_picture: None,
        last_active_at: Some(Utc::now()),
        expires_at: None,
        created_at: Utc::now(),
        authenticated_at: Utc::now(),
        acr: Some(AuthenticationContextClass::SingleFactor),
        amr: vec![AMR_PASSWORD.to_owned()],
    };

    let sessions = [other, matching.clone()];
    let selected = select_active_session(&sessions, Some("alice@example.com")).unwrap();

    assert_eq!(selected.user_email, matching.user_email);
}

#[tokio::test]
async fn determine_authorize_flow_returns_continue_for_reusable_session() {
    let recorded = Arc::new(Mutex::new(None));
    let request = request(None, None);
    let session = active_session(Utc::now());

    let decision = determine_authorize_flow_with_selection_recorder(
        &request,
        slice::from_ref(&session),
        "login-123".to_string(),
        {
            let recorded = recorded.clone();
            move |session_oid, user_oid, source| {
                let recorded = recorded.clone();
                async move {
                    *recorded.lock().unwrap() = Some((session_oid, user_oid, source));
                    Ok(())
                }
            }
        },
    )
    .await
    .unwrap();

    assert!(matches!(
        decision,
        FlowDecision::Continue { login_id } if login_id == "login-123"
    ));
    assert_eq!(
        *recorded.lock().unwrap(),
        Some((session.session_oid, session.user_oid, SelectionSource::Auto,))
    );
}

#[tokio::test]
async fn determine_authorize_flow_accepts_aal2_for_an_aal1_request() {
    let mut request = request(None, None);
    request.acr_values = Some(vec![AuthenticationContextClass::SingleFactor]);
    let mut session = active_session(Utc::now());
    session.acr = Some(AuthenticationContextClass::MultiFactor);

    let decision = determine_authorize_flow_with_selection_recorder(
        &request,
        slice::from_ref(&session),
        "login-123".to_string(),
        |_session_oid, _user_oid, _source| async { Ok(()) },
    )
    .await
    .unwrap();

    assert!(matches!(decision, FlowDecision::Continue { .. }));
}

#[tokio::test]
async fn determine_authorize_flow_requires_account_selection_for_several_sessions() {
    let recorded = Arc::new(Mutex::new(None));
    let request = request(None, None);
    let first = active_session(Utc::now());
    let second = active_session(Utc::now());

    let decision = determine_authorize_flow_with_selection_recorder(
        &request,
        &[first, second],
        "login-123".to_string(),
        {
            let recorded = recorded.clone();
            move |session_oid, user_oid, source| {
                let recorded = recorded.clone();
                async move {
                    *recorded.lock().unwrap() = Some((session_oid, user_oid, source));
                    Ok(())
                }
            }
        },
    )
    .await
    .unwrap();

    assert!(matches!(
        decision,
        FlowDecision::LoginRequired { login_id } if login_id == "login-123"
    ));
    assert_eq!(
        *recorded.lock().unwrap(),
        None,
        "no session may be bound before the user chooses an account"
    );
}

#[tokio::test]
async fn determine_authorize_flow_reports_account_selection_required_for_silent_requests() {
    let request = request(Some(HashSet::from([PromptValue::None])), None);
    let first = active_session(Utc::now());
    let second = active_session(Utc::now());

    let decision = determine_authorize_flow_with_selection_recorder(
        &request,
        &[first, second],
        "login-123".to_string(),
        |_session_oid, _user_oid, _source| async { Ok(()) },
    )
    .await
    .unwrap();

    assert!(matches!(
        decision,
        FlowDecision::OAuthError {
            error: OAuthErrorCode::AccountSelectionRequired,
            ..
        }
    ));
}

#[tokio::test]
async fn determine_authorize_flow_binds_the_account_named_by_login_hint() {
    let recorded = Arc::new(Mutex::new(None));
    let mut request = request(None, None);
    request.login_hint = Some("bob@example.com".to_string());
    let alice = active_session(Utc::now());
    let mut bob = active_session(Utc::now());
    bob.user_name = "bob".to_string();
    bob.user_email = "bob@example.com".to_string();

    let decision = determine_authorize_flow_with_selection_recorder(
        &request,
        &[alice, bob.clone()],
        "login-123".to_string(),
        {
            let recorded = recorded.clone();
            move |session_oid, user_oid, source| {
                let recorded = recorded.clone();
                async move {
                    *recorded.lock().unwrap() = Some((session_oid, user_oid, source));
                    Ok(())
                }
            }
        },
    )
    .await
    .unwrap();

    assert!(matches!(decision, FlowDecision::Continue { .. }));
    assert_eq!(
        recorded
            .lock()
            .unwrap()
            .map(|(session_oid, _, source)| (session_oid, source)),
        Some((bob.session_oid, SelectionSource::Auto)),
    );
}

#[tokio::test]
async fn determine_authorize_flow_returns_oauth_error_for_silent_request_without_session() {
    let request = request(Some(HashSet::from([PromptValue::None])), None);

    let decision = determine_authorize_flow_with_selection_recorder(
        &request,
        &[],
        "login-123".to_string(),
        |_session_oid, _user_oid, _source| async { Ok(()) },
    )
    .await
    .unwrap();

    assert!(matches!(
        decision,
        FlowDecision::OAuthError {
            error: OAuthErrorCode::LoginRequired,
            ..
        }
    ));
}

#[tokio::test]
async fn determine_authorize_flow_requires_login_for_prompt_login() {
    let recorded = Arc::new(Mutex::new(None));
    let request = request(Some(HashSet::from([PromptValue::Login])), None);
    let session = active_session(Utc::now());

    let decision = determine_authorize_flow_with_selection_recorder(
        &request,
        slice::from_ref(&session),
        "login-123".to_string(),
        {
            let recorded = recorded.clone();
            move |session_oid, user_oid, source| {
                let recorded = recorded.clone();
                async move {
                    *recorded.lock().unwrap() = Some((session_oid, user_oid, source));
                    Ok(())
                }
            }
        },
    )
    .await
    .unwrap();

    assert!(matches!(
        decision,
        FlowDecision::LoginRequired { login_id } if login_id == "login-123"
    ));
    assert_eq!(*recorded.lock().unwrap(), None);
}

#[tokio::test]
async fn determine_authorize_flow_requires_login_when_max_age_is_exceeded() {
    let recorded = Arc::new(Mutex::new(None));
    let request = request(None, Some(60));
    let session = active_session(Utc::now() - Duration::seconds(120));

    let decision = determine_authorize_flow_with_selection_recorder(
        &request,
        slice::from_ref(&session),
        "login-123".to_string(),
        {
            let recorded = recorded.clone();
            move |session_oid, user_oid, source| {
                let recorded = recorded.clone();
                async move {
                    *recorded.lock().unwrap() = Some((session_oid, user_oid, source));
                    Ok(())
                }
            }
        },
    )
    .await
    .unwrap();

    assert!(matches!(
        decision,
        FlowDecision::LoginRequired { login_id } if login_id == "login-123"
    ));
    assert_eq!(
        *recorded.lock().unwrap(),
        Some((
            session.session_oid,
            session.user_oid,
            SelectionSource::Reauthentication,
        ))
    );
}

#[tokio::test]
async fn determine_authorize_flow_reuses_old_session_after_recent_reauthentication() {
    let request = request(None, Some(60));
    let mut session = active_session(Utc::now() - Duration::hours(12));
    session.authenticated_at = Utc::now();

    let decision = determine_authorize_flow_with_selection_recorder(
        &request,
        slice::from_ref(&session),
        "login-123".to_string(),
        |_session_oid, _user_oid, _source| async { Ok(()) },
    )
    .await
    .unwrap();

    assert!(matches!(decision, FlowDecision::Continue { .. }));
}

#[tokio::test]
async fn determine_authorize_flow_requires_login_for_select_account() {
    let request = request(Some(HashSet::from([PromptValue::SelectAccount])), None);
    let session = active_session(Utc::now());

    let decision = determine_authorize_flow_with_selection_recorder(
        &request,
        slice::from_ref(&session),
        "login-123".to_string(),
        |_session_oid, _user_oid, _source| async { Ok(()) },
    )
    .await
    .unwrap();

    assert!(matches!(
        decision,
        FlowDecision::LoginRequired { login_id } if login_id == "login-123"
    ));
}

#[tokio::test]
async fn determine_authorize_flow_returns_conflict_when_auto_selection_cannot_overwrite() {
    let request = request(None, None);
    let competing_session = active_session(Utc::now());

    let error = determine_authorize_flow_with_selection_recorder(
        &request,
        slice::from_ref(&competing_session),
        "login-123".to_string(),
        |_session_oid, _user_oid, _source| async {
            Err(authorize::error::AuthzInteractionConflict.into())
        },
    )
    .await
    .unwrap_err();

    assert_eq!(
        error.code(),
        authorize::AuthorizeErrorCode::AuthzInteractionConflict.code()
    );
}

#[tokio::test]
async fn determine_authorize_flow_allows_large_i32_max_age() {
    let request = request(None, Some(i32::MAX));
    let session = active_session(Utc::now() - Duration::seconds(30));

    let decision = determine_authorize_flow_with_selection_recorder(
        &request,
        slice::from_ref(&session),
        "login-123".to_string(),
        |_session_oid, _user_oid, _source| async { Ok(()) },
    )
    .await
    .unwrap();

    assert!(matches!(decision, FlowDecision::Continue { .. }));
}
