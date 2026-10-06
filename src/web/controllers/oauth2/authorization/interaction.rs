use std::{
    collections::{HashMap, HashSet},
    future::Future,
};

use chrono::Utc;
use identity_application::{
    error::codes::authorize_http::AuthorizeHttpErrorCode,
    openid_connect::authorize::ContinueContext,
};
use identity_domain::auth::{SessionOid, acr_satisfies};
use uuid::Uuid;

use crate::{
    application::{error::AppError, openid_connect::authorize::AuthorizeService},
    boot::AppState,
    domain::{
        auth::model::ActiveSession,
        client_authorization::SelectionSource,
        openid_connect::{AuthorizationRequest, OAuthErrorCode, PromptValue},
    },
};

#[derive(Debug)]
pub enum FlowDecision {
    LoginRequired {
        login_id: String,
    },
    Continue {
        login_id: String,
    },
    OAuthError {
        request: Box<AuthorizationRequest>,
        error: OAuthErrorCode,
    },
}

pub fn select_active_session<'a>(
    sessions: &'a [ActiveSession],
    login_hint: Option<&str>,
) -> Option<&'a ActiveSession> {
    match login_hint.filter(|value| !value.is_empty()) {
        Some(hint) => sessions
            .iter()
            .find(|session| session.user_email == hint || session.user_name == hint),
        None => sessions.first(),
    }
}

/// The account a request explicitly names, if it names one.
#[must_use]
fn requested_account(request: &AuthorizationRequest) -> Option<&str> {
    request
        .login_hint
        .as_deref()
        .filter(|value| !value.is_empty())
}

pub fn has_prompt(prompt: Option<&HashSet<PromptValue>>, value: PromptValue) -> bool {
    prompt.map(|items| items.contains(&value)).unwrap_or(false)
}

pub fn requires_account_selection(prompt: Option<&HashSet<PromptValue>>) -> bool {
    has_prompt(prompt, PromptValue::SelectAccount)
}

async fn determine_authorize_flow_with_selection_recorder<F, Fut>(
    request: &AuthorizationRequest,
    sessions: &[ActiveSession],
    login_id: String,
    mut record_selection: F,
) -> Result<FlowDecision, AppError>
where
    F: FnMut(SessionOid, Uuid, SelectionSource) -> Fut,
    Fut: Future<Output = Result<(), AppError>>,
{
    if sessions.is_empty() {
        if has_prompt(request.prompt.as_ref(), PromptValue::None) {
            return Ok(FlowDecision::OAuthError {
                request: Box::new(request.clone()),
                error: OAuthErrorCode::LoginRequired,
            });
        }

        return Ok(FlowDecision::LoginRequired { login_id });
    }

    let selected_session = match select_active_session(sessions, request.login_hint.as_deref()) {
        Some(session) => session,
        None => {
            if has_prompt(request.prompt.as_ref(), PromptValue::None) {
                return Ok(FlowDecision::OAuthError {
                    request: Box::new(request.clone()),
                    error: OAuthErrorCode::LoginRequired,
                });
            }
            return Ok(FlowDecision::LoginRequired { login_id });
        }
    };

    if has_prompt(request.prompt.as_ref(), PromptValue::Login) {
        // `prompt=login` requires a full authentication ceremony. Do not bind
        // an existing session before credential verification, because a bound
        // interaction can accept an OTP without first checking the password.
        // The authenticated user may reuse a browser session afterwards.
        return Ok(FlowDecision::LoginRequired { login_id });
    }

    if requires_account_selection(request.prompt.as_ref()) {
        return Ok(FlowDecision::LoginRequired { login_id });
    }

    // Answering as one of several signed-in accounts is a choice only the user
    // can make. Unless the request names an account (`login_hint`) or asked for
    // selection explicitly, the interaction goes to the account picker instead
    // of silently continuing as the first session — and a request that forbids
    // user interface cannot be answered unambiguously at all.
    if sessions.len() > 1 && requested_account(request).is_none() {
        if has_prompt(request.prompt.as_ref(), PromptValue::None) {
            return Ok(FlowDecision::OAuthError {
                request: Box::new(request.clone()),
                error: OAuthErrorCode::AccountSelectionRequired,
            });
        }
        return Ok(FlowDecision::LoginRequired { login_id });
    }

    if request.acr_values.as_ref().is_some_and(|requested| {
        selected_session
            .acr
            .as_ref()
            .is_none_or(|acr| !requested.iter().any(|value| acr_satisfies(acr, value)))
    }) {
        if has_prompt(request.prompt.as_ref(), PromptValue::None) {
            return Ok(FlowDecision::OAuthError {
                request: Box::new(request.clone()),
                error: OAuthErrorCode::UnmetAuthenticationRequirements,
            });
        }
        record_selection(
            selected_session.session_oid,
            selected_session.user_oid,
            SelectionSource::Reauthentication,
        )
        .await?;
        return Ok(FlowDecision::LoginRequired { login_id });
    }

    if let Some(max_age) = request.max_age {
        let session_age = Utc::now()
            .signed_duration_since(selected_session.authenticated_at)
            .num_seconds();
        if session_age > max_age as i64 {
            if has_prompt(request.prompt.as_ref(), PromptValue::None) {
                return Ok(FlowDecision::OAuthError {
                    request: Box::new(request.clone()),
                    error: OAuthErrorCode::LoginRequired,
                });
            }
            record_selection(
                selected_session.session_oid,
                selected_session.user_oid,
                SelectionSource::Reauthentication,
            )
            .await?;
            return Ok(FlowDecision::LoginRequired { login_id });
        }
    }

    record_selection(
        selected_session.session_oid,
        selected_session.user_oid,
        SelectionSource::Auto,
    )
    .await?;

    Ok(FlowDecision::Continue { login_id })
}

pub async fn determine_authorize_flow(
    request: &AuthorizationRequest,
    sessions: &[ActiveSession],
    protected_session_ids: &HashMap<SessionOid, String>,
    login_id: String,
    authorize_service: &AuthorizeService,
) -> Result<FlowDecision, AppError> {
    determine_authorize_flow_with_selection_recorder(
        request,
        sessions,
        login_id.clone(),
        |session_oid, user_oid, source| {
            let login_id = login_id.clone();
            let protected_session_id = protected_session_ids.get(&session_oid).cloned();
            async move {
                authorize_service
                    .record_selection_by_login(
                        &login_id,
                        session_oid,
                        user_oid,
                        protected_session_id,
                        source,
                    )
                    .await
            }
        },
    )
    .await
}

pub(super) async fn load_active_interaction(
    ctx: &AppState,
    login_id: &str,
) -> Result<ContinueContext, AppError> {
    let continue_context = ctx
        .services()
        .oidc_authorize()
        .load_continue_context_by_login(login_id)
        .await?;
    if continue_context.expires_at <= Utc::now() || continue_context.completed_at.is_some() {
        return Err(AppError::from_code(
            AuthorizeHttpErrorCode::ContinueInteractionUnavailable,
        ));
    }
    Ok(continue_context)
}

pub(super) async fn load_selected_sessions(
    ctx: &AppState,
    selected_session_oid: Option<SessionOid>,
) -> Result<Vec<ActiveSession>, AppError> {
    match selected_session_oid {
        Some(session_oid) => {
            ctx.services()
                .session()
                .get_active_accounts(&[session_oid])
                .await
        }
        None => Ok(Vec::new()),
    }
}

#[cfg(test)]
mod tests {

    use std::{
        collections::HashSet,
        slice,
        sync::{Arc, Mutex},
    };

    use chrono::{DateTime, Duration, Utc};
    use identity_application::error::{
        AppError, code::AppErrorCode, codes::authorize::AuthorizeErrorCode,
    };
    use identity_domain::{
        auth::{ACR_AAL1, ACR_AAL2, AMR_PASSWORD, model::ActiveSession},
        openid_connect::{AuthorizationRequest, ResponseType, ScopeSet},
    };
    use url::Url;
    use uuid::Uuid;

    use super::*;

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
            acr: Some(ACR_AAL1.to_owned()),
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
            acr: Some(ACR_AAL1.to_owned()),
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
            acr: Some(ACR_AAL1.to_owned()),
            amr: vec![AMR_PASSWORD.to_owned()],
        };

        let sessions = [other, matching.clone()];
        let selected = select_active_session(&sessions, Some("alice@example.com")).unwrap();

        assert_eq!(selected.user_email, matching.user_email);
    }

    #[test]
    fn requires_account_selection_when_prompt_contains_select_account() {
        let prompt = HashSet::from([PromptValue::SelectAccount]);
        assert!(requires_account_selection(Some(&prompt)));
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
        request.acr_values = Some(vec![ACR_AAL1.to_owned()]);
        let mut session = active_session(Utc::now());
        session.acr = Some(ACR_AAL2.to_owned());

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
                Err(AppError::from_code(
                    AuthorizeErrorCode::AuthzInteractionConflict,
                ))
            },
        )
        .await
        .unwrap_err();

        assert_eq!(
            error.code(),
            AuthorizeErrorCode::AuthzInteractionConflict.code()
        );
    }
}
