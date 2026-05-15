use chrono::Utc;
use identity_domain::{
    auth::{
        LoginStatus, SessionOid,
        model::{ActiveSession, Login},
    },
    client_authorization::{
        AuthorizationInteractionState, ConsentState, StoredAuthorizationRequest,
    },
    openid_connect::{AuthorizationRequestData, OAuthErrorCode},
};
use uuid::Uuid;

use crate::openid_connect::authorize::{ContinueAction, determine_continue_action};

fn request() -> AuthorizationRequestData {
    AuthorizationRequestData {
        response_type: "code".to_owned(),
        response_mode: None,
        client_id: Uuid::nil().to_string(),
        redirect_uri: "https://client.example.com/callback".to_owned(),
        scope: "openid".to_owned(),
        state: "state-123".to_owned(),
        nonce: None,
        prompt: None,
        max_age: None,
        login_hint: None,
        code_challenge: None,
        code_challenge_method: None,
        acr_values: None,
        claims: None,
    }
}

fn stored(consent_state: ConsentState) -> StoredAuthorizationRequest {
    StoredAuthorizationRequest {
        request: request(),
        interaction: AuthorizationInteractionState {
            consent_state,
            ..AuthorizationInteractionState::default()
        },
    }
}

fn login(status: &'static str) -> Login {
    Login {
        oid: Uuid::new_v4(),
        client_oid: Uuid::new_v4(),
        client_authorization_oid: Uuid::new_v4(),
        session_oid: None,
        user_oid: None,
        status: status.to_owned(),
        failed_attempts: 0,
        acr: None,
        requested_acr: None,
        created_at: Utc::now(),
    }
}

fn active_session() -> ActiveSession {
    ActiveSession {
        session_oid: SessionOid(Uuid::new_v4()),
        user_oid: Uuid::new_v4(),
        user_name: "Ada".to_owned(),
        user_email: "ada@example.com".to_owned(),
        last_active_at: Some(Utc::now()),
        expires_at: None,
        created_at: Utc::now(),
    }
}

#[test]
fn continue_action_approves_when_consent_is_approved() {
    let selected_session = active_session();

    let action = determine_continue_action(
        &stored(ConsentState::Approved),
        &login(LoginStatus::AUTHENTICATED),
        Some(&selected_session),
        false,
    );

    assert_eq!(
        action,
        ContinueAction::Approve {
            session_oid: selected_session.session_oid,
            user_oid: selected_session.user_oid,
            auth_time: Some(selected_session.created_at.timestamp()),
        }
    );
}

#[test]
fn continue_action_redirects_to_consent_when_pending_and_required() {
    let selected_session = active_session();

    let action = determine_continue_action(
        &stored(ConsentState::Pending),
        &login(LoginStatus::AUTHENTICATED),
        Some(&selected_session),
        false,
    );

    assert_eq!(action, ContinueAction::Consent);
}

#[test]
fn continue_action_returns_consent_required_for_silent_pending_consent() {
    let selected_session = active_session();
    let mut stored = stored(ConsentState::Pending);
    stored.request.prompt = Some("none".to_owned());

    let action = determine_continue_action(
        &stored,
        &login(LoginStatus::AUTHENTICATED),
        Some(&selected_session),
        false,
    );

    assert_eq!(
        action,
        ContinueAction::OAuthError(OAuthErrorCode::ConsentRequired)
    );
}
