use http::StatusCode;
use salvo::{Depot, Request};

use crate::{
    application::error::{AppError, codes::authorize_http::AuthorizeHttpErrorCode},
    domain::{client_authorization::ConsentState, openid_connect::ScopeSet},
    web::controllers::{
        response::{AppResponse, app_state, json_response, parse_json, parse_query},
        shared::csrf_token,
    },
    web::views::oauth2::{ConsentDecisionPayload, ConsentPageData, build_scope_display},
};

use super::{
    ConsentQuery,
    context::{has_selected_session, load_consent_context},
    decision::handle_consent_decision,
};

pub(super) async fn consent_api(
    depot: &mut Depot,
    req: &mut Request,
) -> Result<AppResponse, AppError> {
    let ctx = app_state(depot)?;
    let headers = req.headers().clone();
    let query: ConsentQuery = parse_query(req)?;

    let loaded = load_consent_context(&ctx, &headers, &query.login_id).await?;

    if loaded.stored.interaction.consent_state != ConsentState::Pending {
        return Err(AppError::from_code(
            AuthorizeHttpErrorCode::ContinueInteractionUnavailable,
        ));
    }

    if !has_selected_session(
        loaded.stored.interaction.selected_session_oid,
        &loaded.active_sessions,
    ) {
        return Err(AppError::from_code(
            AuthorizeHttpErrorCode::ConsentSessionNotFound,
        ));
    }

    Ok(json_response(
        StatusCode::OK,
        ConsentPageData {
            login_id: query.login_id,
            client_name: loaded.client.client().name.clone(),
            client_uri: loaded
                .client
                .metadata()
                .client_uri
                .as_ref()
                .map(url::Url::to_string),
            scopes: build_scope_display(
                &ScopeSet::parse(&loaded.stored.request.scope).unwrap_or_default(),
            ),
            csrf_token: csrf_token(depot),
            nonce: String::new(),
        },
    )
    .into())
}

pub(super) async fn consent_api_submit(
    depot: &mut Depot,
    req: &mut Request,
) -> Result<AppResponse, AppError> {
    let ctx = app_state(depot)?;
    let headers = req.headers().clone();
    let payload: ConsentDecisionPayload = parse_json(req).await?;
    handle_consent_decision(ctx, headers, payload.login_id, payload.decision, false).await
}
