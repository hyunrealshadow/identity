use axum::{
    extract::{Form, Query, State},
    http::HeaderMap,
    response::{IntoResponse, Redirect, Response},
};
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
        response::AppJson,
        shared::{ensure_csrf_token, is_secure_cookie, load_active_sessions, validate_csrf},
    },
    authorize_interaction::select_active_session,
};

#[derive(Debug, Deserialize)]
pub(crate) struct ConsentQuery {
    login_id: String,
}

#[axum::debug_handler]
pub async fn consent_page(
    State(ctx): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<ConsentQuery>,
) -> Result<Response, AppError> {
    let authorize_service = ctx.services().oidc_authorize();
    let active_sessions = load_active_sessions(&ctx, &headers).await?;

    if active_sessions.is_empty() {
        return Ok(Redirect::to("/login").into_response());
    }

    let (_login, request, client) = authorize_service
        .load_consent_context_by_login(&query.login_id)
        .await?;

    if select_active_session(&active_sessions, request.login_hint.as_deref()).is_none() {
        return Ok(Redirect::to("/login").into_response());
    }

    let (csrf_token, csrf_cookie) = ensure_csrf_token(&headers, is_secure_cookie(&ctx));
    let data = ConsentPageData {
        login_id: query.login_id,
        client_name: client.client().name.clone(),
        client_uri: client
            .metadata()
            .client_uri
            .as_ref()
            .map(|value| value.to_string()),
        scopes: build_scope_display(&ScopeSet::parse(&request.scope).unwrap_or_default()),
        csrf_token,
    };

    let mut response = web::tera::render_view(&ctx, &headers, "oauth2/consent.html", data);
    if let Some(cookie) = csrf_cookie {
        crate::web::controllers::shared::append_set_cookie(&mut response, &cookie);
    }
    Ok(response)
}

#[axum::debug_handler]
pub async fn consent_api(
    State(ctx): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<ConsentQuery>,
) -> Result<Response, AppError> {
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

    Ok(AppJson(ConsentPageData {
        login_id: query.login_id,
        client_name: client.client().name.clone(),
        client_uri: client
            .metadata()
            .client_uri
            .as_ref()
            .map(|value| value.to_string()),
        scopes: build_scope_display(&ScopeSet::parse(&request.scope).unwrap_or_default()),
        csrf_token: String::new(),
    })
    .into_response())
}

#[axum::debug_handler]
pub async fn consent_submit(
    State(ctx): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<ConsentDecisionForm>,
) -> Result<Response, AppError> {
    validate_csrf(&headers, Some(&form.csrf_token))?;
    handle_consent_decision(ctx, headers, form.login_id, form.decision, true).await
}

#[axum::debug_handler]
pub async fn consent_api_submit(
    State(ctx): State<AppState>,
    headers: HeaderMap,
    AppJson(payload): AppJson<ConsentDecisionPayload>,
) -> Result<Response, AppError> {
    handle_consent_decision(ctx, headers, payload.login_id, payload.decision, false).await
}

async fn handle_consent_decision(
    ctx: AppState,
    headers: HeaderMap,
    login_id: String,
    decision: ConsentDecision,
    is_html: bool,
) -> Result<Response, AppError> {
    let authorize_service = ctx.services().oidc_authorize();
    let active_sessions = load_active_sessions(&ctx, &headers).await?;

    let (_login, request, _client) = authorize_service
        .load_consent_context_by_login(&login_id)
        .await?;

    let Some(session) = select_active_session(&active_sessions, request.login_hint.as_deref())
    else {
        return Ok(Redirect::to("/login").into_response());
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
        return Ok(Redirect::to(redirect.as_str()).into_response());
    }

    Ok(AppJson(ConsentApiResponse {
        status: match decision {
            ConsentDecision::Approve => "approved",
            ConsentDecision::Deny => "denied",
        },
        redirect_uri: Some(redirect.to_string()),
        error: None,
    })
    .into_response())
}
