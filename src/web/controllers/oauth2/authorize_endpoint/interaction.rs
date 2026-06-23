use std::collections::HashSet;
use std::future::Future;
use uuid::Uuid;

use identity_domain::auth::SessionOid;

use salvo::Response;

use crate::{
    application::{error::AppError, openid_connect::authorize::AuthorizeService},
    boot::AppState,
    domain::{
        auth::model::ActiveSession,
        client_authorization::SelectionSource,
        openid_connect::{AuthorizationRequest, OAuthErrorCode, OpenIdConnectClient, PromptValue},
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

impl FlowDecision {
    pub fn into_response(self, ctx: &AppState, headers: &http::HeaderMap) -> Response {
        match self {
            FlowDecision::LoginRequired { login_id } => {
                crate::controllers::shared::login_redirect(ctx, &login_id)
            }
            FlowDecision::Continue { login_id } => {
                crate::controllers::response::redirect_to_response(&format!(
                    "/oauth2/continue?login_id={login_id}"
                ))
            }
            FlowDecision::OAuthError { request, error } => {
                super::response::redirect_oauth_error_response(ctx, headers, &request, error)
            }
        }
    }
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

pub fn has_prompt(prompt: Option<&HashSet<PromptValue>>, value: PromptValue) -> bool {
    prompt.map(|items| items.contains(&value)).unwrap_or(false)
}

pub fn requires_account_selection(prompt: Option<&HashSet<PromptValue>>) -> bool {
    has_prompt(prompt, PromptValue::SelectAccount)
}

async fn determine_authorize_flow_with_selection_recorder<F, Fut>(
    request: &AuthorizationRequest,
    sessions: &[ActiveSession],
    authorization_request_id: Uuid,
    login_id: String,
    mut record_selection: F,
) -> Result<FlowDecision, AppError>
where
    F: FnMut(Uuid, SessionOid, Uuid, SelectionSource) -> Fut,
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
        return Ok(FlowDecision::LoginRequired { login_id });
    }

    if requires_account_selection(request.prompt.as_ref()) {
        return Ok(FlowDecision::LoginRequired { login_id });
    }

    if let Some(max_age) = request.max_age {
        let session_age = chrono::Utc::now()
            .signed_duration_since(selected_session.created_at)
            .num_seconds();
        if session_age > max_age as i64 {
            if has_prompt(request.prompt.as_ref(), PromptValue::None) {
                return Ok(FlowDecision::OAuthError {
                    request: Box::new(request.clone()),
                    error: OAuthErrorCode::LoginRequired,
                });
            }
            return Ok(FlowDecision::LoginRequired { login_id });
        }
    }

    record_selection(
        authorization_request_id,
        selected_session.session_oid,
        selected_session.user_oid,
        SelectionSource::Auto,
    )
    .await?;

    Ok(FlowDecision::Continue { login_id })
}

pub async fn determine_authorize_flow(
    request: &AuthorizationRequest,
    _client: &OpenIdConnectClient,
    sessions: &[ActiveSession],
    authorization_request_id: Uuid,
    login_id: String,
    authorize_service: &AuthorizeService,
) -> Result<FlowDecision, AppError> {
    determine_authorize_flow_with_selection_recorder(
        request,
        sessions,
        authorization_request_id,
        login_id,
        |authorization_request_id, session_oid, user_oid, source| {
            authorize_service.record_authorization_selection(
                authorization_request_id,
                session_oid,
                user_oid,
                None,
                source,
            )
        },
    )
    .await
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{Duration, Utc};
    use identity_application::error::{
        AppError, code::AppErrorCode, codes::authorize::AuthorizeErrorCode,
    };
    use identity_domain::{
        auth::model::ActiveSession,
        openid_connect::{AuthorizationRequest, ResponseType, ScopeSet},
    };
    use std::collections::HashSet;
    use std::sync::{Arc, Mutex};
    use url::Url;
    use uuid::Uuid;

    fn request(prompt: Option<HashSet<PromptValue>>, max_age: Option<i32>) -> AuthorizationRequest {
        AuthorizationRequest {
            response_type: ResponseType::Code,
            response_mode: None,
            client_id: Uuid::nil(),
            redirect_uri: Url::parse("https://client.example.com/callback").unwrap(),
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

    fn active_session(created_at: chrono::DateTime<Utc>) -> ActiveSession {
        ActiveSession {
            session_oid: SessionOid(Uuid::new_v4()),
            user_oid: Uuid::new_v4(),
            user_name: "alice".to_string(),
            user_email: "alice@example.com".to_string(),
            last_active_at: Some(created_at),
            expires_at: None,
            created_at,
        }
    }

    #[test]
    fn select_active_session_prefers_matching_login_hint() {
        let matching = ActiveSession {
            session_oid: SessionOid(Uuid::new_v4()),
            user_oid: Uuid::new_v4(),
            user_name: "alice".to_string(),
            user_email: "alice@example.com".to_string(),
            last_active_at: Some(Utc::now()),
            expires_at: None,
            created_at: Utc::now(),
        };
        let other = ActiveSession {
            session_oid: SessionOid(Uuid::new_v4()),
            user_oid: Uuid::new_v4(),
            user_name: "bob".to_string(),
            user_email: "bob@example.com".to_string(),
            last_active_at: Some(Utc::now()),
            expires_at: None,
            created_at: Utc::now(),
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

    #[test]
    fn internal_client_without_session_returns_err() {
        use identity_application::error::codes::authorize_http::AuthorizeHttpErrorCode;
        use identity_application::error::kind::ErrorKind;

        let error = identity_application::error::AppError::from_code(
            AuthorizeHttpErrorCode::InternalClientLoginRequired,
        );

        assert_eq!(error.kind(), ErrorKind::Validation);
    }

    #[tokio::test]
    async fn determine_authorize_flow_returns_continue_for_reusable_session() {
        let recorded = Arc::new(Mutex::new(None));
        let request = request(None, None);
        let authorization_request_id = Uuid::new_v4();
        let session = active_session(Utc::now());

        let decision = determine_authorize_flow_with_selection_recorder(
            &request,
            std::slice::from_ref(&session),
            authorization_request_id,
            "login-123".to_string(),
            {
                let recorded = recorded.clone();
                move |authorization_request_id, session_oid, user_oid, source| {
                    let recorded = recorded.clone();
                    async move {
                        *recorded.lock().unwrap() =
                            Some((authorization_request_id, session_oid, user_oid, source));
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
            Some((
                authorization_request_id,
                session.session_oid,
                session.user_oid,
                SelectionSource::Auto,
            ))
        );
    }

    #[tokio::test]
    async fn determine_authorize_flow_returns_oauth_error_for_silent_request_without_session() {
        let request = request(Some(HashSet::from([PromptValue::None])), None);

        let decision = determine_authorize_flow_with_selection_recorder(
            &request,
            &[],
            Uuid::new_v4(),
            "login-123".to_string(),
            |_authorization_request_id, _session_oid, _user_oid, _source| async { Ok(()) },
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
        let request = request(Some(HashSet::from([PromptValue::Login])), None);
        let session = active_session(Utc::now());

        let decision = determine_authorize_flow_with_selection_recorder(
            &request,
            std::slice::from_ref(&session),
            Uuid::new_v4(),
            "login-123".to_string(),
            |_authorization_request_id, _session_oid, _user_oid, _source| async { Ok(()) },
        )
        .await
        .unwrap();

        assert!(matches!(
            decision,
            FlowDecision::LoginRequired { login_id } if login_id == "login-123"
        ));
    }

    #[tokio::test]
    async fn determine_authorize_flow_requires_login_when_max_age_is_exceeded() {
        let request = request(None, Some(60));
        let session = active_session(Utc::now() - Duration::seconds(120));

        let decision = determine_authorize_flow_with_selection_recorder(
            &request,
            std::slice::from_ref(&session),
            Uuid::new_v4(),
            "login-123".to_string(),
            |_authorization_request_id, _session_oid, _user_oid, _source| async { Ok(()) },
        )
        .await
        .unwrap();

        assert!(matches!(
            decision,
            FlowDecision::LoginRequired { login_id } if login_id == "login-123"
        ));
    }

    #[tokio::test]
    async fn determine_authorize_flow_requires_login_for_select_account() {
        let request = request(Some(HashSet::from([PromptValue::SelectAccount])), None);
        let session = active_session(Utc::now());

        let decision = determine_authorize_flow_with_selection_recorder(
            &request,
            std::slice::from_ref(&session),
            Uuid::new_v4(),
            "login-123".to_string(),
            |_authorization_request_id, _session_oid, _user_oid, _source| async { Ok(()) },
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
            std::slice::from_ref(&competing_session),
            Uuid::new_v4(),
            "login-123".to_string(),
            |_authorization_request_id, _session_oid, _user_oid, _source| async {
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
