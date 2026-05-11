use http::HeaderMap;

use crate::{
    application::{
        error::{AppError, codes::authorize_http::AuthorizeHttpErrorCode},
        openid_connect::authorize::{
            ContinueAction, determine_continue_action, selected_session_exceeds_max_age,
            stored_request_has_prompt,
        },
    },
    controllers::response::AppResponse,
    domain::client_authorization::SelectionSource,
    web::controllers::shared::load_active_session_entries,
};

use super::super::{finish_authorize_redirect, response_mode_from_value, select_active_session};
use super::response::{
    continue_consent_redirect, continue_login_redirect, continue_oauth_error_response,
};

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
    if continue_context.expires_at <= chrono::Utc::now() || continue_context.completed_at.is_some()
    {
        return Err(AppError::from_code(
            AuthorizeHttpErrorCode::ContinueInteractionUnavailable,
        ));
    }

    let active_session_entries = load_active_session_entries(ctx, headers).await?;
    let active_sessions: Vec<_> = active_session_entries
        .iter()
        .map(|entry| entry.session.clone())
        .collect();
    let login = continue_context.login;
    let mut stored = continue_context.stored;
    let client = continue_context.client;

    let mut selected_session =
        stored
            .interaction
            .selected_session_oid
            .and_then(|selected_session_oid| {
                active_sessions
                    .iter()
                    .find(|session| session.session_oid == selected_session_oid)
            });

    let has_stored_selected_session = stored.interaction.selected_session_oid.is_some();
    let requires_forced_login =
        stored_request_has_prompt(stored.request.prompt.as_deref(), "login");
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
            let protected_session_id = active_session_entries
                .iter()
                .find(|entry| entry.session.session_oid == session.session_oid)
                .map(|entry| entry.protected_session_id.clone());
            ctx.services()
                .oidc_authorize()
                .record_authorization_selection(
                    login.client_authorization_oid,
                    session.session_oid,
                    session.user_oid,
                    protected_session_id.clone(),
                    SelectionSource::Auto,
                )
                .await?;
            stored.interaction.selected_session_oid = Some(session.session_oid);
            stored.interaction.selected_protected_session_id = protected_session_id;
            stored.interaction.selected_user_oid = Some(session.user_oid.to_string());
            stored.interaction.selection_source = Some(SelectionSource::Auto);
            selected_session = active_sessions.iter().find(|candidate| {
                candidate.session_oid == session.session_oid
                    && candidate.user_oid == session.user_oid
            });
        }
    }

    let selected_protected_session_id = selected_session.and_then(|session| {
        active_session_entries
            .iter()
            .find(|entry| entry.session.session_oid == session.session_oid)
            .map(|entry| entry.protected_session_id.clone())
    });

    match determine_continue_action(
        &stored,
        &login,
        selected_session,
        ctx.services().oidc_authorize().should_skip_consent(&client),
    ) {
        ContinueAction::Login => Ok(continue_login_redirect(login_id).into()),
        ContinueAction::OAuthError(error) => {
            Ok(continue_oauth_error_response(ctx, headers, &stored.request, error)?.into())
        }
        ContinueAction::Consent => Ok(continue_consent_redirect(login_id).into()),
        ContinueAction::Deny => ctx
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
            }),
        ContinueAction::Approve {
            session_oid,
            user_oid,
            auth_time,
        } => ctx
            .services()
            .oidc_authorize()
            .approve_authorization_request_by_login(
                login_id,
                session_oid,
                user_oid,
                selected_protected_session_id,
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
            }),
    }
}
