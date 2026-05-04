use http::HeaderMap;

use crate::{
    application::error::{AppError, codes::authorize_http::AuthorizeHttpErrorCode},
    controllers::response::AppResponse,
    domain::{
        auth::LoginStatus,
        client_authorization::{ConsentState, SelectionSource},
        openid_connect::{AuthorizationRequestData, OAuthErrorCode},
    },
    web::controllers::shared::load_active_sessions,
};

use super::response::{
    continue_consent_redirect, continue_login_redirect, continue_oauth_error_response,
};
use super::super::{finish_authorize_redirect, response_mode_from_value, select_active_session};

fn stored_request_has_prompt(prompt: Option<&str>, value: &str) -> bool {
    prompt
        .map(|items| items.split_whitespace().any(|item| item == value))
        .unwrap_or(false)
}

fn login_is_authenticated(login: &identity_domain::auth::model::Login) -> bool {
    login.status == LoginStatus::AUTHENTICATED
}

fn selected_session_exceeds_max_age(
    request: &AuthorizationRequestData,
    selected_session: &identity_domain::auth::model::ActiveSession,
) -> bool {
    request.max_age.is_some_and(|max_age| {
        chrono::Utc::now()
            .signed_duration_since(selected_session.created_at)
            .num_seconds()
            > i64::from(max_age)
    })
}

pub(super) async fn handle_continue(
    ctx: &identity_infrastructure::AppState,
    headers: &HeaderMap,
    login_id: &str,
) -> Result<AppResponse, AppError> {
    let continue_context = ctx
        .services()
        .oidc_authorize()
        .load_continue_context_by_login(login_id)
        .await?;
    if continue_context.expires_at <= chrono::Utc::now() || continue_context.completed_at.is_some() {
        return Err(AppError::from_code(
            AuthorizeHttpErrorCode::ContinueInteractionUnavailable,
        ));
    }

    let active_sessions = load_active_sessions(ctx, headers).await?;
    let login = continue_context.login;
    let mut stored = continue_context.stored;
    let client = continue_context.client;

    let mut selected_session = stored
        .interaction
        .selected_session_oid
        .as_deref()
        .and_then(|selected_session_oid| {
            active_sessions
                .iter()
                .find(|session| session.session_oid.to_string() == selected_session_oid)
        });

    let has_stored_selected_session = stored.interaction.selected_session_oid.is_some();
    let requires_forced_login = stored_request_has_prompt(stored.request.prompt.as_deref(), "login");
    let requires_explicit_account_selection =
        stored_request_has_prompt(stored.request.prompt.as_deref(), "select_account");

    if selected_session.is_none() && !has_stored_selected_session {
        let auto_selected_session =
            select_active_session(&active_sessions, stored.request.login_hint.as_deref());

        let auto_selection_requires_login = auto_selected_session
            .map(|session| {
                requires_forced_login || selected_session_exceeds_max_age(&stored.request, session)
            })
            .unwrap_or(false);

        if !requires_explicit_account_selection
            && !auto_selection_requires_login
            && let Some(session) = auto_selected_session
        {
            ctx.services()
                .oidc_authorize()
                .record_authorization_selection(
                    login.client_authorization_oid,
                    session.session_oid,
                    session.user_oid,
                    SelectionSource::Auto,
                )
                .await?;
            stored.interaction.selected_session_oid = Some(session.session_oid.to_string());
            stored.interaction.selected_user_oid = Some(session.user_oid.to_string());
            stored.interaction.selection_source = Some(SelectionSource::Auto);
            selected_session = active_sessions.iter().find(|candidate| {
                candidate.session_oid == session.session_oid && candidate.user_oid == session.user_oid
            });
        }
    }

    let login_required = selected_session
        .map(|selected_session| {
            requires_forced_login
                || selected_session_exceeds_max_age(&stored.request, selected_session)
        })
        .unwrap_or(false);

    if selected_session.is_none()
        && (has_stored_selected_session
            || select_active_session(&active_sessions, stored.request.login_hint.as_deref()).is_none())
    {
        if stored_request_has_prompt(stored.request.prompt.as_deref(), "none") {
            return Ok(
                continue_oauth_error_response(
                    ctx,
                    headers,
                    &stored.request,
                    OAuthErrorCode::LoginRequired,
                )?
                .into(),
            );
        }

        return Ok(continue_login_redirect(login_id).into());
    }

    if login_required && !login_is_authenticated(&login) {
        if stored_request_has_prompt(stored.request.prompt.as_deref(), "none") {
            return Ok(
                continue_oauth_error_response(
                    ctx,
                    headers,
                    &stored.request,
                    OAuthErrorCode::LoginRequired,
                )?
                .into(),
            );
        }

        return Ok(continue_login_redirect(login_id).into());
    }

    if selected_session.is_some()
        && requires_explicit_account_selection
        && stored.interaction.selection_source == Some(SelectionSource::Auto)
    {
        if stored_request_has_prompt(stored.request.prompt.as_deref(), "none") {
            return Ok(
                continue_oauth_error_response(
                    ctx,
                    headers,
                    &stored.request,
                    OAuthErrorCode::LoginRequired,
                )?
                .into(),
            );
        }

        return Ok(continue_login_redirect(login_id).into());
    }

    if selected_session.is_some() && stored.interaction.consent_state == ConsentState::Denied {
        return ctx
            .services()
            .oidc_authorize()
            .deny_authorization_request_by_login(login_id)
            .await
            .map(|redirect| {
                finish_authorize_redirect(
                    ctx,
                    headers,
                    &redirect,
                    response_mode_from_value(stored.request.response_mode.as_deref()),
                )
                .into()
            });
    }

    if let Some(selected_session) = selected_session
        && stored.interaction.consent_state == ConsentState::Approved
    {
        let auth_time = Some(selected_session.created_at.timestamp());
        return ctx
            .services()
            .oidc_authorize()
            .approve_authorization_request_by_login(
                login_id,
                selected_session.session_oid,
                selected_session.user_oid,
                auth_time,
            )
            .await
            .map(|redirect| {
                finish_authorize_redirect(
                    ctx,
                    headers,
                    &redirect,
                    response_mode_from_value(stored.request.response_mode.as_deref()),
                )
                .into()
            });
    }

    if let Some(selected_session) = selected_session
        && ctx.services().oidc_authorize().should_skip_consent(&client)
    {
        let auth_time = Some(selected_session.created_at.timestamp());
        return ctx
            .services()
            .oidc_authorize()
            .approve_authorization_request_by_login(
                login_id,
                selected_session.session_oid,
                selected_session.user_oid,
                auth_time,
            )
            .await
            .map(|redirect| {
                finish_authorize_redirect(
                    ctx,
                    headers,
                    &redirect,
                    response_mode_from_value(stored.request.response_mode.as_deref()),
                )
                .into()
            });
    }

    if selected_session.is_some()
        && stored.interaction.consent_state == ConsentState::Pending
        && !ctx.services().oidc_authorize().should_skip_consent(&client)
    {
        if stored_request_has_prompt(stored.request.prompt.as_deref(), "none") {
            return Ok(
                continue_oauth_error_response(
                    ctx,
                    headers,
                    &stored.request,
                    OAuthErrorCode::ConsentRequired,
                )?
                .into(),
            );
        }

        return Ok(continue_consent_redirect(login_id).into());
    }

    if stored_request_has_prompt(stored.request.prompt.as_deref(), "none") {
        return Ok(
            continue_oauth_error_response(
                ctx,
                headers,
                &stored.request,
                OAuthErrorCode::LoginRequired,
            )?
            .into(),
        );
    }

    Ok(continue_login_redirect(login_id).into())
}
