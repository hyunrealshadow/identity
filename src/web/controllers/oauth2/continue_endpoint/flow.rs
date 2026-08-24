use http::HeaderMap;

use crate::{
    application::{
        error::{AppError, codes::authorize_http::AuthorizeHttpErrorCode},
        openid_connect::authorize::{ContinueAction, determine_continue_action},
    },
    controllers::response::AppResponse,
    web::controllers::shared::{
        append_set_cookie, build_op_session_cookie_with_selected_id, protect_session_id,
    },
};

use super::response::{
    continue_consent_redirect, continue_login_redirect, continue_oauth_error_response,
};
use crate::controllers::oauth2::{finish_authorize_redirect, response_mode_from_value};

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

    let login = continue_context.login;
    let authorization_request_id = login.client_authorization_oid;
    let stored = continue_context.stored;
    let client = continue_context.client;

    let selected_sessions = match login.session_oid {
        Some(session_oid) => {
            ctx.services()
                .session()
                .get_active_accounts(&[session_oid])
                .await?
        }
        None => Vec::new(),
    };
    let selected_session = selected_sessions.first();

    let selected_protected_session_id = if let Some(session) = selected_session {
        Some(protect_session_id(ctx, session.session_oid).await?)
    } else {
        None
    };

    let op_session_cookie = match (selected_session, selected_protected_session_id.as_deref()) {
        (Some(session), Some(protected_session_id)) => Some(
            build_op_session_cookie_with_selected_id(
                ctx,
                headers,
                session.session_oid,
                protected_session_id,
            )
            .await,
        ),
        _ => None,
    };

    let mut response: salvo::Response = match determine_continue_action(
        &stored,
        &login,
        selected_session,
        ctx.services().oidc_authorize().should_skip_consent(&client),
    ) {
        ContinueAction::Login => continue_login_redirect(ctx, login_id)?,
        ContinueAction::OAuthError(error) => {
            continue_oauth_error_response(ctx, headers, &stored.request, error)?
        }
        ContinueAction::Consent => continue_consent_redirect(ctx, login_id)?,
        ContinueAction::Deny => ctx
            .services()
            .oidc_authorize()
            .deny_authorization_request(authorization_request_id)
            .await
            .map(|redirect| {
                finish_authorize_redirect(
                    ctx,
                    headers,
                    &redirect,
                    response_mode_from_value(stored.request.response_mode.as_deref()),
                )
            })?,
        ContinueAction::Approve {
            session_oid,
            user_oid,
            auth_time,
            acr,
            amr,
        } => ctx
            .services()
            .oidc_authorize()
            .approve_authorization_request_with_protected_session_id(
                authorization_request_id,
                identity_application::openid_connect::authorize::AuthorizationApproval {
                    session_oid,
                    user_oid,
                    protected_session_id: selected_protected_session_id,
                    auth_time,
                    acr,
                    amr,
                },
            )
            .await
            .map(|redirect| {
                finish_authorize_redirect(
                    ctx,
                    headers,
                    &redirect,
                    response_mode_from_value(stored.request.response_mode.as_deref()),
                )
            })?,
    };

    if let Some(cookie) = op_session_cookie {
        append_set_cookie(&mut response, &cookie);
    }
    Ok(response.into())
}
