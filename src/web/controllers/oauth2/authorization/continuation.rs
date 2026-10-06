use http::HeaderMap;
use identity_application::openid_connect::authorize::AuthorizationApproval;
use identity_infrastructure::AppState;
use salvo::{Depot, Request, Response, handler, handler::HoopedHandler};
use serde::Deserialize;

use super::{
    super::pipeline::{Endpoint, Extract, RequireState, take},
    interaction::{load_active_interaction, load_selected_sessions},
    response::{continue_oauth_error_response, finish_authorize_redirect},
};
use crate::{
    application::{
        error::AppError,
        openid_connect::authorize::{ContinueAction, determine_continue_action},
    },
    controllers::{
        response::{AppResponse, WebError, WebResult, app_state},
        shared::{consent_redirect, login_redirect},
    },
    domain::{
        client_authorization::ConsentState,
        openid_connect::{OAuthErrorCode, PromptValue},
    },
    web::controllers::shared::{
        append_set_cookie, build_op_session_cookie_with_selected_id, protect_session_id,
    },
};

pub(super) async fn handle_continue(
    ctx: &AppState,
    headers: &HeaderMap,
    login_id: &str,
) -> Result<AppResponse, AppError> {
    let continue_context = load_active_interaction(ctx, login_id).await?;

    let login = continue_context.login;
    let authorization_request_id = login.client_authorization_oid;
    let stored = continue_context.stored;
    let client = continue_context.client;

    let selected_sessions = load_selected_sessions(ctx, login.session_oid).await?;
    let selected_session = selected_sessions.first();

    let client_skips_consent = ctx.services().oidc_authorize().should_skip_consent(&client);
    let should_check_user_consent = stored.interaction.consent_state == ConsentState::Pending
        && !client_skips_consent
        && !stored
            .request
            .prompt
            .as_ref()
            .is_some_and(|prompt| prompt.contains(&PromptValue::Consent));
    let has_user_consent = match (selected_session, should_check_user_consent) {
        (Some(session), true) => {
            ctx.services()
                .oidc_authorize()
                .has_user_consent(session.user_oid, client.client().oid, &stored.request.scope)
                .await?
        }
        _ => false,
    };

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

    let mut response: Response = match determine_continue_action(
        &stored,
        &login,
        selected_session,
        client_skips_consent || has_user_consent,
    ) {
        ContinueAction::Login => login_redirect(ctx, login_id)?,
        ContinueAction::OAuthError(error) => {
            continue_oauth_error_response(ctx, headers, &stored.request, error)?
        }
        ContinueAction::Consent => consent_redirect(ctx, login_id)?,
        ContinueAction::Deny => {
            let request = ctx
                .services()
                .oidc_authorize()
                .deny_authorization_request(authorization_request_id)
                .await?;
            continue_oauth_error_response(ctx, headers, &request, OAuthErrorCode::AccessDenied)?
        }
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
                AuthorizationApproval {
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
                finish_authorize_redirect(ctx, headers, &redirect, stored.request.response_mode)
            })?,
    };

    if let Some(cookie) = op_session_cookie {
        append_set_cookie(&mut response, &cookie);
    }
    Ok(response.into())
}

#[derive(Debug, Deserialize)]
struct ContinueQuery {
    login_id: String,
}

pub fn endpoint() -> HoopedHandler {
    Endpoint::new("continue_get")
        .action("state", RequireState::<WebError>::new())
        .action("parse_query", Extract::<ContinueQuery, WebError>::query())
        .finish("continue_get", continue_get)
}

#[handler]
async fn continue_get(depot: &mut Depot, req: &mut Request) -> WebResult {
    let ctx = app_state(depot)?;
    let headers: HeaderMap = req.headers().clone();
    let query: ContinueQuery = take(depot)?;
    Ok(handle_continue(&ctx, &headers, &query.login_id).await?)
}
