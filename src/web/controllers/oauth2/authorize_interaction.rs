use std::collections::HashSet;
use url::Url;
use uuid::Uuid;

use salvo::Response;

use crate::{
    application::{error::AppError, openid_connect::authorize::AuthorizeService},
    boot::AppState,
    domain::{
        auth::model::ActiveSession,
        openid_connect::{AuthorizationRequest, OAuthErrorCode, OpenIdConnectClient, PromptValue},
    },
};

#[derive(Debug)]
pub enum FlowDecision {
    LoginRequired {
        login_id: String,
    },
    ConsentRequired {
        login_id: String,
    },
    AutoApprove {
        redirect_uri: Url,
        response_mode: Option<crate::domain::openid_connect::ResponseMode>,
    },
    ConsentDenied {
        request: AuthorizationRequest,
        error: OAuthErrorCode,
    },
}

impl FlowDecision {
    pub fn into_response(self, ctx: &AppState, headers: &http::HeaderMap) -> Response {
        match self {
            FlowDecision::LoginRequired { login_id } => {
                crate::web::controllers::response::redirect_to_response(&format!(
                    "/login?login_id={login_id}"
                ))
            }
            FlowDecision::ConsentRequired { login_id } => {
                crate::web::controllers::response::redirect_to_response(&format!(
                    "/oauth2/authorize/consent?login_id={login_id}"
                ))
            }
            FlowDecision::AutoApprove {
                redirect_uri,
                response_mode,
            } => match response_mode {
                Some(crate::domain::openid_connect::ResponseMode::FormPost) => {
                    super::authorize_response::render_form_post_redirect_response(
                        ctx,
                        headers,
                        &redirect_uri,
                    )
                }
                _ => crate::web::controllers::response::redirect_to_response(redirect_uri.as_str()),
            },
            FlowDecision::ConsentDenied { request, error } => {
                super::authorize_response::redirect_oauth_error_response(
                    ctx, headers, &request, error,
                )
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

pub fn requires_forced_consent(prompt: Option<&HashSet<PromptValue>>) -> bool {
    has_prompt(prompt, PromptValue::Consent)
}

pub async fn determine_authorize_flow(
    request: &AuthorizationRequest,
    client: &OpenIdConnectClient,
    sessions: &[ActiveSession],
    authorization_request_id: Uuid,
    login_id: String,
    authorize_service: &AuthorizeService,
) -> Result<FlowDecision, AppError> {
    if sessions.is_empty() {
        if has_prompt(request.prompt.as_ref(), PromptValue::None) {
            return Ok(FlowDecision::ConsentDenied {
                request: request.clone(),
                error: OAuthErrorCode::LoginRequired,
            });
        }

        return Ok(FlowDecision::LoginRequired { login_id });
    }

    let selected_session = match select_active_session(sessions, request.login_hint.as_deref()) {
        Some(session) => session,
        None => {
            if has_prompt(request.prompt.as_ref(), PromptValue::None) {
                return Ok(FlowDecision::ConsentDenied {
                    request: request.clone(),
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

    // Enforce max_age: if the session is older than max_age seconds, re-auth is required.
    if let Some(max_age) = request.max_age {
        let session_age = chrono::Utc::now()
            .signed_duration_since(selected_session.created_at)
            .num_seconds();
        if session_age > max_age as i64 {
            if has_prompt(request.prompt.as_ref(), PromptValue::None) {
                return Ok(FlowDecision::ConsentDenied {
                    request: request.clone(),
                    error: OAuthErrorCode::LoginRequired,
                });
            }
            return Ok(FlowDecision::LoginRequired { login_id });
        }
    }

    let should_skip_consent = authorize_service.should_skip_consent(client)
        && !requires_forced_consent(request.prompt.as_ref());

    if should_skip_consent {
        let auth_time = selected_session.created_at.timestamp();
        let redirect_uri = authorize_service
            .approve_authorization_request(
                authorization_request_id,
                selected_session.session_oid,
                selected_session.user_oid,
                Some(auth_time),
            )
            .await?;

        return Ok(FlowDecision::AutoApprove {
            redirect_uri,
            response_mode: request.response_mode,
        });
    }

    if has_prompt(request.prompt.as_ref(), PromptValue::None) {
        return Ok(FlowDecision::ConsentDenied {
            request: request.clone(),
            error: OAuthErrorCode::ConsentRequired,
        });
    }

    Ok(FlowDecision::ConsentRequired { login_id })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::auth::model::ActiveSession;
    use chrono::Utc;
    use std::collections::HashSet;
    use uuid::Uuid;

    #[test]
    fn select_active_session_prefers_matching_login_hint() {
        let matching = ActiveSession {
            session_oid: Uuid::new_v4(),
            user_oid: Uuid::new_v4(),
            user_name: "alice".to_string(),
            user_email: "alice@example.com".to_string(),
            last_active_at: Some(Utc::now()),
            expires_at: None,
            created_at: Utc::now(),
        };
        let other = ActiveSession {
            session_oid: Uuid::new_v4(),
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
    fn requires_forced_consent_when_prompt_contains_consent() {
        let prompt = HashSet::from([PromptValue::Consent]);
        assert!(requires_forced_consent(Some(&prompt)));
    }

    #[test]
    fn internal_client_without_session_returns_err() {
        use crate::application::error::codes::authorize_http::AuthorizeHttpErrorCode;
        use crate::application::error::kind::ErrorKind;

        let error = crate::application::error::AppError::from_code(
            AuthorizeHttpErrorCode::InternalClientLoginRequired,
        );

        assert_eq!(error.kind(), ErrorKind::Validation);
    }
}
