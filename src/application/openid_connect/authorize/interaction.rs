use crate::domain::{
    auth::{
        LoginStatus,
        model::{ActiveSession, Login},
    },
    client_authorization::{ConsentState, SelectionSource, StoredAuthorizationRequest},
    openid_connect::{AuthorizationRequestData, OAuthErrorCode},
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ContinueAction {
    Login,
    OAuthError(OAuthErrorCode),
    Consent,
    Approve {
        session_oid: uuid::Uuid,
        user_oid: uuid::Uuid,
        auth_time: Option<i64>,
    },
    Deny,
}

#[must_use]
pub fn stored_request_has_prompt(prompt: Option<&str>, value: &str) -> bool {
    prompt
        .map(|items| items.split_whitespace().any(|item| item == value))
        .unwrap_or(false)
}

#[must_use]
pub fn selected_session_exceeds_max_age(
    request: &AuthorizationRequestData,
    selected_session: &ActiveSession,
) -> bool {
    request.max_age.is_some_and(|max_age| {
        chrono::Utc::now()
            .signed_duration_since(selected_session.created_at)
            .num_seconds()
            > i64::from(max_age)
    })
}

#[must_use]
fn login_is_authenticated(login: &Login) -> bool {
    login.status == LoginStatus::AUTHENTICATED
}

#[must_use]
fn continue_login_or_error(stored: &StoredAuthorizationRequest) -> ContinueAction {
    if stored_request_has_prompt(stored.request.prompt.as_deref(), "none") {
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
        auth_time: Some(selected_session.created_at.timestamp()),
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
        stored_request_has_prompt(stored.request.prompt.as_deref(), "login");
    let requires_explicit_account_selection =
        stored_request_has_prompt(stored.request.prompt.as_deref(), "select_account");
    let login_required = requires_forced_login
        || selected_session_exceeds_max_age(&stored.request, selected_session);

    if login_required && !login_is_authenticated(login) {
        return continue_login_or_error(stored);
    }

    if requires_explicit_account_selection
        && stored.interaction.selection_source == Some(SelectionSource::Auto)
    {
        return continue_login_or_error(stored);
    }

    match stored.interaction.consent_state {
        ConsentState::Denied => ContinueAction::Deny,
        ConsentState::Approved => approve_action(selected_session),
        ConsentState::Pending if skip_consent => approve_action(selected_session),
        ConsentState::Pending
            if stored_request_has_prompt(stored.request.prompt.as_deref(), "none") =>
        {
            ContinueAction::OAuthError(OAuthErrorCode::ConsentRequired)
        }
        ConsentState::Pending => ContinueAction::Consent,
    }
}
