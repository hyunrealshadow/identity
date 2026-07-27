use crate::{
    application::error::{AppError, codes::authorize_http::AuthorizeHttpErrorCode},
    boot::AppState,
    domain::client_authorization::ConsentState,
    web::controllers::response::{AppResponse, json_response},
    web::views::oauth2::{ConsentApiResponse, ConsentDecision},
};
use http::StatusCode;

use super::context::{has_selected_session, load_consent_context};

pub(super) async fn handle_consent_decision(
    ctx: AppState,
    login_id: String,
    decision: ConsentDecision,
) -> Result<AppResponse, AppError> {
    let loaded = load_consent_context(&ctx, &login_id).await?;

    if loaded.stored.interaction.consent_state != ConsentState::Pending {
        return Err(AppError::from_code(
            AuthorizeHttpErrorCode::ContinueInteractionUnavailable,
        ));
    }

    if !has_selected_session(loaded.selected_session_oid, &loaded.active_sessions) {
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
