use http::StatusCode;
use salvo::{Depot, Request, Response};

use crate::{
    application::error::AppError,
    domain::{client_authorization::ConsentState, openid_connect::ScopeSet},
    infrastructure::web,
    web::controllers::{
        response::{
            AppResponse, app_state, parse_query, redirect_to_response, render_app_error,
            render_html,
        },
        shared::csrf_token,
    },
    web::views::oauth2::{ConsentPageData, build_scope_display},
};

use super::{
    super::inline_script_csp_header_value,
    ConsentQuery,
    context::{has_selected_session, load_consent_context},
};

pub(super) async fn consent_page(
    depot: &mut Depot,
    req: &mut Request,
) -> Result<AppResponse, AppError> {
    let ctx = app_state(depot)?;
    let headers = req.headers().clone();
    let query: ConsentQuery = parse_query(req)?;

    let loaded = load_consent_context(&ctx, &headers, &query.login_id).await?;

    if loaded.active_sessions.is_empty() {
        return Ok(redirect_to_response("/login").into());
    }

    if loaded.stored.interaction.consent_state != ConsentState::Pending {
        return Ok(redirect_to_response(&loaded.continue_uri).into());
    }

    if !has_selected_session(
        loaded.stored.interaction.selected_session_oid.as_deref(),
        &loaded.active_sessions,
    ) {
        return Ok(redirect_to_response(&format!(
            "/login?login_id={}",
            urlencoding::encode(&query.login_id)
        ))
        .into());
    }

    let data = ConsentPageData {
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
    };

    let mut response = Response::new();
    match web::tera::render_view(&ctx, &headers, "oauth2/consent.html", data) {
        Ok(body) => render_html(&mut response, StatusCode::OK, body),
        Err(error) => render_app_error(&mut response, error),
    }
    response.headers_mut().insert(
        http::header::HeaderName::from_static("content-security-policy"),
        inline_script_csp_header_value(),
    );
    Ok(response.into())
}
