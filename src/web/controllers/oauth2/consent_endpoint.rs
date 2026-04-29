use http::{HeaderMap, StatusCode};
use salvo::{Depot, Request, Response, handler};
use serde::Deserialize;

use crate::{
    application::error::{AppError, codes::authorize_http::AuthorizeHttpErrorCode},
    boot::AppState,
    domain::openid_connect::ScopeSet,
    infrastructure::web,
    web::views::oauth2::{
        ConsentApiResponse, ConsentDecision, ConsentDecisionForm, ConsentDecisionPayload,
        ConsentPageData, build_scope_display,
    },
};

use super::{
    super::{
        response::{
            AppResponse, app_state, parse_form, parse_json, parse_query, redirect_to_response,
            render_app_error, render_html,
        },
        shared::{csrf_token, load_active_sessions},
    },
    authorize_interaction::select_active_session,
    authorize_response::{render_form_post_redirect_response, response_mode_from_value},
};

#[derive(Debug, Deserialize)]
pub(crate) struct ConsentQuery {
    login_id: String,
}

#[handler]
pub async fn consent_page(depot: &mut Depot, req: &mut Request) -> Result<AppResponse, AppError> {
    let ctx = app_state(depot)?;
    let headers = req.headers().clone();
    let query: ConsentQuery = parse_query(req)?;
    let authorize_service = ctx.services().oidc_authorize();
    let active_sessions = load_active_sessions(&ctx, &headers).await?;

    if active_sessions.is_empty() {
        return Ok(redirect_to_response("/login").into());
    }

    let (_login, request, client) = authorize_service
        .load_consent_context_by_login(&query.login_id)
        .await?;

    if select_active_session(&active_sessions, request.login_hint.as_deref()).is_none() {
        return Ok(redirect_to_response("/login").into());
    }

    let data = ConsentPageData {
        login_id: query.login_id,
        client_name: client.client().name.clone(),
        client_uri: client
            .metadata()
            .client_uri
            .as_ref()
            .map(|value| value.to_string()),
        scopes: build_scope_display(&ScopeSet::parse(&request.scope).unwrap_or_default()),
        csrf_token: csrf_token(depot),
    };

    let mut response = Response::new();
    match web::tera::render_view(&ctx, &headers, "oauth2/consent.html", data) {
        Ok(body) => render_html(&mut response, StatusCode::OK, body),
        Err(error) => render_app_error(&mut response, error),
    }
    Ok(response.into())
}

#[handler]
pub async fn consent_api(depot: &mut Depot, req: &mut Request) -> Result<AppResponse, AppError> {
    let ctx = app_state(depot)?;
    let headers = req.headers().clone();
    let query: ConsentQuery = parse_query(req)?;
    let authorize_service = ctx.services().oidc_authorize();
    let active_sessions = load_active_sessions(&ctx, &headers).await?;

    let (_login, request, client) = authorize_service
        .load_consent_context_by_login(&query.login_id)
        .await?;

    if select_active_session(&active_sessions, request.login_hint.as_deref()).is_none() {
        return Err(AppError::from_code(
            AuthorizeHttpErrorCode::ConsentSessionNotFound,
        ));
    }

    Ok(super::super::response::json_response(
        StatusCode::OK,
        ConsentPageData {
            login_id: query.login_id,
            client_name: client.client().name.clone(),
            client_uri: client
                .metadata()
                .client_uri
                .as_ref()
                .map(|value| value.to_string()),
            scopes: build_scope_display(&ScopeSet::parse(&request.scope).unwrap_or_default()),
            csrf_token: csrf_token(depot),
        },
    )
    .into())
}

#[handler]
pub async fn consent_submit(depot: &mut Depot, req: &mut Request) -> Result<AppResponse, AppError> {
    let ctx = app_state(depot)?;
    let headers = req.headers().clone();
    let form: ConsentDecisionForm = parse_form(req).await?;
    handle_consent_decision(ctx, headers, form.login_id, form.decision, true).await
}

#[handler]
pub async fn consent_api_submit(
    depot: &mut Depot,
    req: &mut Request,
) -> Result<AppResponse, AppError> {
    let ctx = app_state(depot)?;
    let headers = req.headers().clone();
    let payload: ConsentDecisionPayload = parse_json(req).await?;
    handle_consent_decision(ctx, headers, payload.login_id, payload.decision, false).await
}

async fn handle_consent_decision(
    ctx: AppState,
    headers: HeaderMap,
    login_id: String,
    decision: ConsentDecision,
    is_html: bool,
) -> Result<AppResponse, AppError> {
    let authorize_service = ctx.services().oidc_authorize();
    let active_sessions = load_active_sessions(&ctx, &headers).await?;

    let (_login, request, _client) = authorize_service
        .load_consent_context_by_login(&login_id)
        .await?;

    let Some(session) = select_active_session(&active_sessions, request.login_hint.as_deref())
    else {
        return Ok(redirect_to_response("/login").into());
    };

    let redirect = match decision {
        ConsentDecision::Approve => {
            // Look up the session to get auth_time for the ID token
            let auth_time = ctx
                .services()
                .session()
                .select_session(session.session_oid)
                .await
                .ok()
                .map(|s| s.created_at.timestamp());
            authorize_service
                .approve_authorization_request_by_login(
                    &login_id,
                    session.session_oid,
                    session.user_oid,
                    auth_time,
                )
                .await?
        }
        ConsentDecision::Deny => {
            authorize_service
                .deny_authorization_request_by_login(&login_id)
                .await?
        }
    };

    if is_html {
        if response_mode_from_value(request.response_mode.as_deref())
            == Some(identity_domain::openid_connect::ResponseMode::FormPost)
        {
            return Ok(render_form_post_redirect_response(&ctx, &headers, &redirect).into());
        }
        return Ok(redirect_to_response(redirect.as_str()).into());
    }

    Ok(super::super::response::json_response(
        StatusCode::OK,
        ConsentApiResponse {
            status: match decision {
                ConsentDecision::Approve => "approved",
                ConsentDecision::Deny => "denied",
            },
            redirect_uri: Some(redirect.to_string()),
            error: None,
        },
    )
    .into())
}
