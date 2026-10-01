use http::StatusCode;
use salvo::{Depot, Request};

use crate::{
    application::error::{AppError, codes::authorize_http::AuthorizeHttpErrorCode},
    domain::client_authorization::ConsentState,
    web::controllers::{
        response::{AppResponse, app_state, json_response, parse_json, parse_query},
        shared::csrf_token,
    },
    web::views::oauth2::{ConsentDecisionPayload, ConsentPageData, build_scope_display},
};

use super::{
    ConsentQuery,
    context::load_consent_context,
    decision::handle_consent_decision,
    device::{device_consent_api, device_consent_submit, device_login_consent_api},
};

pub(super) async fn consent_api(
    depot: &mut Depot,
    req: &mut Request,
) -> Result<AppResponse, AppError> {
    let ctx = app_state(depot)?;
    let query: ConsentQuery = parse_query(req)?;
    let headers: http::HeaderMap = req.headers().clone();

    if let Some(user_code) = query.device_target()? {
        return Ok(device_consent_api(&ctx, &headers, depot, user_code)
            .await?
            .into());
    }
    let login_id = query.login_id.clone().unwrap_or_default();
    let login = ctx
        .services()
        .oidc_authorize()
        .load_login_by_protected_id(&login_id)
        .await?;
    if ctx
        .services()
        .oidc_device_authorization()
        .login_request(&login)
        .await?
        .is_some()
    {
        return Ok(
            device_login_consent_api(&ctx, &headers, depot, &login_id, &login)
                .await?
                .into(),
        );
    }

    let loaded = load_consent_context(&ctx, &login_id).await?;

    if loaded.stored.interaction.consent_state != ConsentState::Pending {
        return Err(AppError::from_code(
            AuthorizeHttpErrorCode::ContinueInteractionUnavailable,
        ));
    }

    let session = loaded
        .active_sessions
        .iter()
        .find(|session| Some(session.session_oid) == loaded.selected_session_oid)
        .ok_or_else(|| AppError::from_code(AuthorizeHttpErrorCode::ConsentSessionNotFound))?;
    let previously_granted = ctx
        .services()
        .oidc_authorize()
        .user_consented_scope_names(session.user_oid, loaded.client.client().oid)
        .await?;

    Ok(json_response(
        StatusCode::OK,
        ConsentPageData {
            login_id,
            client_name: loaded.client.client().name.clone(),
            logo_uri: loaded
                .client
                .metadata()
                .logo_uri
                .as_ref()
                .map(url::Url::to_string),
            client_uri: loaded
                .client
                .metadata()
                .client_uri
                .as_ref()
                .map(url::Url::to_string),
            scopes: build_scope_display(
                &loaded.scope,
                &previously_granted,
                &ctx.services()
                    .oidc_authorize()
                    .scope_descriptions(&loaded.scope)
                    .await?,
            ),
            csrf_token: csrf_token(depot),
            ui_locales: loaded.stored.request.ui_locales.clone(),
        },
    )
    .into())
}

pub(super) async fn consent_api_submit(
    depot: &mut Depot,
    req: &mut Request,
) -> Result<AppResponse, AppError> {
    let ctx = app_state(depot)?;
    let headers: http::HeaderMap = req.headers().clone();
    let payload: ConsentDecisionPayload = parse_json(req).await?;

    match (payload.login_id.as_deref(), payload.user_code.as_deref()) {
        (Some(login_id), None) => {
            let login = ctx
                .services()
                .oidc_authorize()
                .load_login_by_protected_id(login_id)
                .await?;
            if ctx
                .services()
                .oidc_device_authorization()
                .login_request(&login)
                .await?
                .is_some()
            {
                return Ok(
                    device_consent_submit(&ctx, &headers, &login, payload.decision)
                        .await?
                        .into(),
                );
            }
            handle_consent_decision(ctx, login_id.to_owned(), payload.decision).await
        }
        _ => Err(AppError::from_code(
            AuthorizeHttpErrorCode::ContinueInteractionUnavailable,
        )),
    }
}
