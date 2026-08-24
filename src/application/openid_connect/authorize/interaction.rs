use crate::domain::{
    auth::{
        LoginStatus,
        model::{ActiveSession, Login, SessionOid},
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
        session_oid: SessionOid,
        user_oid: uuid::Uuid,
        auth_time: Option<i64>,
        acr: Option<String>,
        amr: Vec<String>,
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
        let Ok(max_age) = u64::try_from(max_age) else {
            return true;
        };
        !crate::domain::auth::authentication_is_fresh(
            selected_session.authenticated_at.timestamp(),
            chrono::Utc::now().timestamp(),
            max_age,
        )
    })
}

#[must_use]
pub fn selected_session_satisfies_acr(
    request: &AuthorizationRequestData,
    selected_session: &ActiveSession,
) -> bool {
    request.acr_values.as_ref().is_none_or(|requested| {
        selected_session.acr.as_ref().is_some_and(|acr| {
            requested
                .iter()
                .any(|value| crate::domain::auth::acr_satisfies(acr, value))
        })
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
        auth_time: Some(selected_session.authenticated_at.timestamp()),
        acr: selected_session.acr.clone(),
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
        stored_request_has_prompt(stored.request.prompt.as_deref(), "login");
    let requires_explicit_account_selection =
        stored_request_has_prompt(stored.request.prompt.as_deref(), "select_account");
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
        ConsentState::Pending if skip_consent => approve_action(selected_session),
        ConsentState::Pending
            if stored_request_has_prompt(stored.request.prompt.as_deref(), "none") =>
        {
            ContinueAction::OAuthError(OAuthErrorCode::ConsentRequired)
        }
        ConsentState::Pending => ContinueAction::Consent,
    }
}
