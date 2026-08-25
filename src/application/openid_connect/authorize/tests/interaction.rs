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

use crate::openid_connect::authorize::{
    ContinueAction, determine_continue_action, selected_session_exceeds_max_age,
};

fn request() -> AuthorizationRequestData {
    AuthorizationRequestData {
        response_type: "code".parse().unwrap(),
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
        ui_locales: None,
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

fn login(status: LoginStatus) -> Login {
    Login {
        oid: Uuid::new_v4(),
        client_oid: Uuid::new_v4(),
        client_authorization_oid: Uuid::new_v4(),
        session_oid: None,
        user_oid: None,
        status,
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
        user_picture: None,
        last_active_at: Some(Utc::now()),
        expires_at: None,
        created_at: Utc::now(),
        authenticated_at: Utc::now(),
        acr: Some(identity_domain::auth::ACR_AAL1.to_owned()),
        amr: vec![identity_domain::auth::AMR_PASSWORD.to_owned()],
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
            auth_time: Some(selected_session.authenticated_at.timestamp()),
            acr: selected_session.acr.clone(),
            amr: selected_session.amr.clone(),
        }
    );
}

#[test]
fn max_age_uses_latest_authentication_instead_of_session_creation() {
    let mut request = request();
    request.max_age = Some(60);
    let mut session = active_session();
    session.created_at = Utc::now() - chrono::Duration::hours(12);
    session.authenticated_at = Utc::now();

    assert!(!selected_session_exceeds_max_age(&request, &session));
}

#[test]
fn continue_action_rejects_an_authentication_that_does_not_meet_requested_acr() {
    let selected_session = active_session();
    let mut stored = stored(ConsentState::Approved);
    stored.request.acr_values = Some(vec![identity_domain::auth::ACR_AAL2.to_owned()]);

    let action = determine_continue_action(
        &stored,
        &login(LoginStatus::AUTHENTICATED),
        Some(&selected_session),
        false,
    );

    assert_eq!(
        action,
        ContinueAction::OAuthError(OAuthErrorCode::UnmetAuthenticationRequirements)
    );
}

#[test]
fn continue_action_accepts_aal2_for_an_aal1_request() {
    let mut selected_session = active_session();
    selected_session.acr = Some(identity_domain::auth::ACR_AAL2.to_owned());
    let mut stored = stored(ConsentState::Approved);
    stored.request.acr_values = Some(vec![identity_domain::auth::ACR_AAL1.to_owned()]);

    let action = determine_continue_action(
        &stored,
        &login(LoginStatus::AUTHENTICATED),
        Some(&selected_session),
        false,
    );

    assert!(matches!(action, ContinueAction::Approve { .. }));
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
    stored.request.prompt = Some(
        [identity_domain::openid_connect::PromptValue::None]
            .into_iter()
            .collect(),
    );

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
