use http::{StatusCode, header::HeaderName};
use identity_infrastructure::web::tera::render_view;
use salvo::{Depot, Request, Response, handler, handler::HoopedHandler};
use serde_json::to_string;

use crate::controllers::oauth2::pipeline::{Endpoint, RequireState, take};
use crate::{
    controllers::{
        response::{WebError, WebResult, app_state, render_app_error, render_html},
        shared::{
            generate_csp_nonce, inline_script_csp_header_value, load_op_active_session_entries,
        },
    },
    views::openid::CheckSessionPageData,
};

struct BrowserState {
    nonce: String,
    value: String,
}

pub fn endpoint() -> HoopedHandler {
    Endpoint::new("check_session")
        .action("state", RequireState::<WebError>::new())
        .action("load_browser_state", load_browser_state)
        .finish("render_iframe", check_session_iframe)
}

#[handler]
async fn load_browser_state(depot: &mut Depot, req: &mut Request) -> WebResult<()> {
    let ctx = app_state(depot)?;
    let nonce = generate_csp_nonce();
    let entries = load_op_active_session_entries(&ctx, req.headers()).await?;
    let value = entries
        .iter()
        .map(|entry| entry.protected_session_id.as_str())
        .collect::<Vec<_>>()
        .join(".");
    depot.insert_typed(BrowserState { nonce, value });
    Ok(())
}

#[handler]
async fn check_session_iframe(
    depot: &mut Depot,
    req: &mut Request,
    res: &mut Response,
) -> WebResult<()> {
    let ctx = app_state(depot)?;
    let BrowserState {
        nonce,
        value: op_browser_state,
    } = take(depot)?;

    let data = CheckSessionPageData {
        op_browser_state_json: to_string(&op_browser_state).unwrap_or_else(|_| "\"\"".to_owned()),
        lang: "en".to_owned(),
        nonce: nonce.clone(),
    };

    match render_view(&ctx, req.headers(), "openid/check_session.html", data) {
        Ok(body) => render_html(res, StatusCode::OK, body),
        Err(error) => render_app_error(res, req.headers(), &ctx, error),
    }

    res.headers_mut().insert(
        HeaderName::from_static("content-security-policy"),
        inline_script_csp_header_value(&nonce),
    );
    Ok(())
}
