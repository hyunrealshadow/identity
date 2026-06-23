use http::HeaderMap;
use http::StatusCode;
use salvo::{Depot, Request};

use crate::{
    application::error::{AppError, codes::authorize_http::AuthorizeHttpErrorCode},
    boot::AppState,
    domain::client_authorization::ConsentState,
    web::controllers::response::{
        AppResponse, app_state, json_response, parse_form, redirect_to_response,
    },
    web::views::oauth2::{ConsentApiResponse, ConsentDecision, ConsentDecisionForm},
};

use super::context::{has_selected_session, load_consent_context};

pub(super) async fn consent_submit(
    depot: &mut Depot,
    req: &mut Request,
) -> Result<AppResponse, AppError> {
    let ctx = app_state(depot)?;
    let headers = req.headers().clone();
    let form: ConsentDecisionForm = parse_form(req).await?;
    handle_consent_decision(ctx, headers, form.login_id, form.decision, true).await
}

pub(super) async fn handle_consent_decision(
    ctx: AppState,
    headers: HeaderMap,
    login_id: String,
    decision: ConsentDecision,
    is_html: bool,
) -> Result<AppResponse, AppError> {
    let loaded = load_consent_context(&ctx, &headers, &login_id).await?;

    if loaded.stored.interaction.consent_state != ConsentState::Pending {
        if is_html {
            return Ok(redirect_to_response(&loaded.continue_uri).into());
        }

        return Err(AppError::from_code(
            AuthorizeHttpErrorCode::ContinueInteractionUnavailable,
        ));
    }

    if !has_selected_session(
        loaded.stored.interaction.selected_session_oid,
        &loaded.active_sessions,
    ) {
        if is_html {
            return Ok(crate::controllers::shared::login_redirect(&ctx, &login_id).into());
        }

        return Err(AppError::from_code(
            AuthorizeHttpErrorCode::ConsentSessionNotFound,
        ));
    }

    let consent_state = match decision {
        ConsentDecision::Approve => ConsentState::Approved,
        ConsentDecision::Deny => ConsentState::Denied,
    };
    ctx.services()
        .oidc_authorize()
        .record_consent_by_login(&login_id, consent_state)
        .await?;

    if is_html {
        return Ok(redirect_to_response(&loaded.continue_uri).into());
    }

    Ok(json_response(
        StatusCode::OK,
        ConsentApiResponse {
            status: match decision {
                ConsentDecision::Approve => "approved",
                ConsentDecision::Deny => "denied",
            },
            continue_uri: Some(loaded.continue_uri),
            error: None,
        },
    )
    .into())
}
