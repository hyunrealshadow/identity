use chrono::{Duration, Utc};
use identity_domain::{
    auth::{
        AMR_PASSWORD, AuthenticationContextClass, LoginStatus, SessionOid,
        model::{ActiveSession, Login},
    },
    client_authorization::{
        AuthorizationInteractionState, ConsentState, StoredAuthorizationRequest,
    },
    openid_connect::{AuthorizationRequestData, OAuthErrorCode, PromptValue},
};
use uuid::Uuid;

use crate::openid_connect::authorize::{
    ContinueAction, determine_continue_action, selected_session_exceeds_max_age,
};

fn request() -> AuthorizationRequestData {
    AuthorizationRequestData {
        resources: Vec::new(),
        response_type: "code".parse().unwrap(),
        response_mode: None,
        client_id: identity_domain::openid_connect::identifier::client_id(Uuid::nil()),
        redirect_uri: "https://client.example.com/callback".to_owned(),
        redirect_uri_was_supplied: true,
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
        management: None,
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
        submitted_identifier: None,
        requested_acr_values: Vec::new(),
        amr: Vec::new(),
        created_at: Utc::now(),
        expires_at: Utc::now() + Duration::minutes(5),
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
        acr: Some(AuthenticationContextClass::SingleFactor),
        amr: vec![AMR_PASSWORD.to_owned()],
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
            acr: selected_session.acr,
            amr: selected_session.amr.clone(),
        }
    );
}

#[test]
fn max_age_uses_latest_authentication_instead_of_session_creation() {
    let mut request = request();
    request.max_age = Some(60);
    let mut session = active_session();
    session.created_at = Utc::now() - Duration::hours(12);
    session.authenticated_at = Utc::now();

    assert!(!selected_session_exceeds_max_age(&request, &session));
}

#[test]
fn continue_action_rejects_an_authentication_that_does_not_meet_requested_acr() {
    let selected_session = active_session();
    let mut stored = stored(ConsentState::Approved);
    stored.request.acr_values = Some(vec![AuthenticationContextClass::MultiFactor]);

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
    selected_session.acr = Some(AuthenticationContextClass::MultiFactor);
    let mut stored = stored(ConsentState::Approved);
    stored.request.acr_values = Some(vec![AuthenticationContextClass::SingleFactor]);

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
fn prompt_consent_overrides_skip_consent_policy() {
    let selected_session = active_session();
    let mut stored = stored(ConsentState::Pending);
    stored.request.prompt = Some([PromptValue::Consent].into_iter().collect());

    let action = determine_continue_action(
        &stored,
        &login(LoginStatus::AUTHENTICATED),
        Some(&selected_session),
        true,
    );

    assert_eq!(action, ContinueAction::Consent);
    stored.request.prompt = None;
    assert!(matches!(
        determine_continue_action(
            &stored,
            &login(LoginStatus::AUTHENTICATED),
            Some(&selected_session),
            true,
        ),
        ContinueAction::Approve { .. }
    ));
}

#[test]
fn continue_action_returns_consent_required_for_silent_pending_consent() {
    let selected_session = active_session();
    let mut stored = stored(ConsentState::Pending);
    stored.request.prompt = Some([PromptValue::None].into_iter().collect());

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

#[tokio::test]
async fn ensure_account_selection_allowed_rejects_forced_login_and_reauthentication() {
    use std::sync::Arc;

    use crate::{
        error::{code::AppErrorCode, codes::auth::AuthErrorCode},
        openid_connect::authorize::{
            AuthorizeService, AuthorizeServiceDependencies,
            tests::fixtures::{
                FoundClientRepository, TEST_CLIENT_ID, empty_cred_repo, mock_login_repo,
                provider_service,
                repositories::{ClientAuthorizationState, mock_client_auth_repo_with_state},
                stub_key_repo, stub_user_repo, test_data_protector,
                test_signing_algorithm_detector,
            },
        },
        openid_connect::{
            remote::test_remote_fetcher, tests::fixtures::mocks::MockKeyJwkRepository,
        },
    };
    use identity_domain::client_authorization::{
        ClientAuthorization, ClientAuthorizationData, ClientAuthorizationType, SelectionSource,
    };

    let state = Arc::new(ClientAuthorizationState::default());
    let login_repo = Arc::new(mock_login_repo());
    let service = AuthorizeService::new(AuthorizeServiceDependencies {
        client_repo: Arc::new(FoundClientRepository),
        credential_repo: Arc::new(empty_cred_repo()),
        client_authorization_repo: Arc::new(mock_client_auth_repo_with_state(Arc::clone(&state))),
        login_repo: login_repo.clone(),
        user_repo: Arc::new(stub_user_repo()),
        key_repo: Arc::new(stub_key_repo()),
        key_jwk_repo: Arc::new(MockKeyJwkRepository::new()),
        provider_service: provider_service(),
        signing_algorithm_detector: test_signing_algorithm_detector(),
        data_protector: test_data_protector(),
        remote_fetcher: test_remote_fetcher(),
    });

    for (prompt, selection_source, expected_allowed) in [
        (
            Some([PromptValue::Login].into_iter().collect()),
            None,
            false,
        ),
        (None, Some(SelectionSource::Reauthentication), false),
        (
            Some([PromptValue::SelectAccount].into_iter().collect()),
            None,
            true,
        ),
        (None, None, true),
    ] {
        let auth_oid = Uuid::new_v4();
        let login_oid = Uuid::new_v4();
        let mut stored_req = request();
        stored_req.client_id = TEST_CLIENT_ID.to_string();
        stored_req.prompt = prompt;
        state.records.lock().unwrap().insert(
            auth_oid,
            ClientAuthorization {
                oid: auth_oid,
                client_oid: TEST_CLIENT_ID,
                type_: ClientAuthorizationType::AuthorizationRequest,
                data: ClientAuthorizationData::AuthorizationRequest(StoredAuthorizationRequest {
                    request: stored_req,
                    interaction: AuthorizationInteractionState {
                        selection_source,
                        ..AuthorizationInteractionState::default()
                    },
                }),
                expires_at: Utc::now() + Duration::minutes(10),
                completed_at: None,
                revoked_at: None,
                created_at: Utc::now(),
                updated_at: None,
            },
        );
        let mut login_record = login(LoginStatus::CREATED);
        login_record.oid = login_oid;
        login_record.client_oid = TEST_CLIENT_ID;
        login_record.client_authorization_oid = auth_oid;
        *login_repo.find_by_oid_result.lock().unwrap() = Some(Some(login_record));

        let protected_login_id = service.encrypt_login_id(login_oid).await.unwrap();
        let result = service
            .ensure_account_selection_allowed(&protected_login_id)
            .await;
        if expected_allowed {
            assert!(result.is_ok(), "unexpected rejection: {result:?}");
        } else {
            assert_eq!(
                result.unwrap_err().code(),
                AuthErrorCode::InvalidLoginState.code()
            );
        }
    }
}
