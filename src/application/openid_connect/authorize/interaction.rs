use std::{
    collections::{HashMap, HashSet},
    future::Future,
};

use chrono::Utc;
use uuid::Uuid;

use super::AuthorizeService;
use crate::{
    domain::{
        auth::{
            AuthenticationContextClass, LoginStatus, acr_satisfies_any, authentication_is_fresh,
            model::{ActiveSession, Login, SessionOid},
        },
        client_authorization::{ConsentState, SelectionSource, StoredAuthorizationRequest},
        openid_connect::{
            AuthorizationRequest, AuthorizationRequestData, OAuthErrorCode, PromptValue,
        },
    },
    error::AppError,
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ContinueAction {
    Login,
    OAuthError(OAuthErrorCode),
    Consent,
    Approve {
        session_oid: SessionOid,
        user_oid: Uuid,
        auth_time: Option<i64>,
        acr: Option<AuthenticationContextClass>,
        amr: Vec<String>,
    },
    Deny,
}

#[must_use]
pub fn stored_request_has_prompt(
    prompt: Option<&HashSet<PromptValue>>,
    value: PromptValue,
) -> bool {
    prompt.is_some_and(|items| items.contains(&value))
}

#[must_use]
pub fn selected_session_exceeds_max_age(
    request: &AuthorizationRequestData,
    selected_session: &ActiveSession,
) -> bool {
    request.max_age.is_some_and(|max_age| {
        let Ok(max_age) = u64::try_from(max_age) else {
            return true;
        };
        !authentication_is_fresh(
            selected_session.authenticated_at.timestamp(),
            Utc::now().timestamp(),
            max_age,
        )
    })
}

#[must_use]
pub fn selected_session_satisfies_acr(
    request: &AuthorizationRequestData,
    selected_session: &ActiveSession,
) -> bool {
    request
        .acr_values
        .as_deref()
        .is_none_or(|requested| acr_satisfies_any(selected_session.acr, requested))
}

#[must_use]
fn login_is_authenticated(login: &Login) -> bool {
    login.status == LoginStatus::AUTHENTICATED
}

#[must_use]
fn continue_login_or_error(stored: &StoredAuthorizationRequest) -> ContinueAction {
    if stored_request_has_prompt(stored.request.prompt.as_ref(), PromptValue::None) {
        ContinueAction::OAuthError(OAuthErrorCode::LoginRequired)
    } else {
        ContinueAction::Login
    }
}

#[must_use]
fn approve_action(selected_session: &ActiveSession) -> ContinueAction {
    ContinueAction::Approve {
        session_oid: selected_session.session_oid,
        user_oid: selected_session.user_oid,
        auth_time: Some(selected_session.authenticated_at.timestamp()),
        acr: selected_session.acr,
        amr: selected_session.amr.clone(),
    }
}

#[must_use]
pub fn determine_continue_action(
    stored: &StoredAuthorizationRequest,
    login: &Login,
    selected_session: Option<&ActiveSession>,
    skip_consent: bool,
) -> ContinueAction {
    let Some(selected_session) = selected_session else {
        return continue_login_or_error(stored);
    };

    let requires_forced_login =
        stored_request_has_prompt(stored.request.prompt.as_ref(), PromptValue::Login);
    let requires_explicit_account_selection =
        stored_request_has_prompt(stored.request.prompt.as_ref(), PromptValue::SelectAccount);
    let login_required = requires_forced_login
        || selected_session_exceeds_max_age(&stored.request, selected_session);

    if login_required && !login_is_authenticated(login) {
        return continue_login_or_error(stored);
    }

    if !selected_session_satisfies_acr(&stored.request, selected_session) {
        return if login_is_authenticated(login) {
            ContinueAction::OAuthError(OAuthErrorCode::UnmetAuthenticationRequirements)
        } else {
            continue_login_or_error(stored)
        };
    }

    if requires_explicit_account_selection
        && stored.interaction.selection_source == Some(SelectionSource::Auto)
    {
        return continue_login_or_error(stored);
    }

    match stored.interaction.consent_state {
        ConsentState::Denied => ContinueAction::Deny,
        ConsentState::Approved => approve_action(selected_session),
        ConsentState::Pending
            if skip_consent
                && !stored_request_has_prompt(
                    stored.request.prompt.as_ref(),
                    PromptValue::Consent,
                ) =>
        {
            approve_action(selected_session)
        }
        ConsentState::Pending
            if stored_request_has_prompt(stored.request.prompt.as_ref(), PromptValue::None) =>
        {
            ContinueAction::OAuthError(OAuthErrorCode::ConsentRequired)
        }
        ConsentState::Pending => ContinueAction::Consent,
    }
}

#[must_use]
pub(super) fn select_active_session<'a>(
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

#[must_use]
fn requires_account_selection(prompt: Option<&HashSet<PromptValue>>) -> bool {
    stored_request_has_prompt(prompt, PromptValue::SelectAccount)
}

pub(super) async fn determine_authorize_flow_with_selection_recorder<F, Fut>(
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
        if stored_request_has_prompt(request.prompt.as_ref(), PromptValue::None) {
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
            if stored_request_has_prompt(request.prompt.as_ref(), PromptValue::None) {
                return Ok(FlowDecision::OAuthError {
                    request: Box::new(request.clone()),
                    error: OAuthErrorCode::LoginRequired,
                });
            }
            return Ok(FlowDecision::LoginRequired { login_id });
        }
    };

    if stored_request_has_prompt(request.prompt.as_ref(), PromptValue::Login) {
        // `prompt=login` requires a full authentication. Do not bind an
        // existing session before credential verification, because a bound
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
        if stored_request_has_prompt(request.prompt.as_ref(), PromptValue::None) {
            return Ok(FlowDecision::OAuthError {
                request: Box::new(request.clone()),
                error: OAuthErrorCode::AccountSelectionRequired,
            });
        }
        return Ok(FlowDecision::LoginRequired { login_id });
    }

    if request
        .acr_values
        .as_deref()
        .is_some_and(|requested| !acr_satisfies_any(selected_session.acr, requested))
    {
        if stored_request_has_prompt(request.prompt.as_ref(), PromptValue::None) {
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
        if session_age < 0 || session_age > i64::from(max_age) {
            if stored_request_has_prompt(request.prompt.as_ref(), PromptValue::None) {
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

impl AuthorizeService {
    /// Decide how an authorization request proceeds given the browser's active
    /// sessions, recording any automatic session or reauthentication binding.
    pub async fn determine_authorize_flow(
        &self,
        request: &AuthorizationRequest,
        sessions: &[ActiveSession],
        protected_session_ids: &HashMap<SessionOid, String>,
        login_id: String,
    ) -> Result<FlowDecision, AppError> {
        determine_authorize_flow_with_selection_recorder(
            request,
            sessions,
            login_id.clone(),
            |session_oid, user_oid, source| {
                let login_id = login_id.clone();
                let protected_session_id = protected_session_ids.get(&session_oid).cloned();
                async move {
                    self.record_selection_by_login(
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
}
