use http::header;
use http::StatusCode;
use salvo::{Depot, Request, Response, handler};
use serde::Deserialize;

use crate::application::setting::runtime::SettingProvider;
use crate::web::controllers::response::{WebResult, app_state};

mod api;
mod context;
mod decision;
mod page;

#[cfg(test)]
mod tests;

#[derive(Debug, Deserialize)]
struct ConsentQuery {
    login_id: String,
}

fn accepts_json(accept: Option<&str>) -> bool {
    accept
        .map(|value| {
            value.split(',').map(str::trim).any(|part| {
                let mut segments = part.split(';').map(str::trim);
                let Some(media_type) = segments.next() else {
                    return false;
                };
                if media_type != "application/json" {
                    return false;
                }
                !segments.any(|segment| {
                    segment
                        .strip_prefix("q=")
                        .and_then(|value| value.parse::<f32>().ok())
                        .is_some_and(|quality| quality <= 0.0)
                })
            })
        })
        .unwrap_or(false)
}

fn content_type_is_json(content_type: Option<&str>) -> bool {
    content_type
        .map(|value| value.split(';').next().unwrap_or_default().trim() == "application/json")
        .unwrap_or(false)
}

fn expects_json_post(accept: Option<&str>, content_type: Option<&str>) -> bool {
    accepts_json(accept) && content_type_is_json(content_type)
}

#[handler]
pub async fn consent_get(depot: &mut Depot, req: &mut Request) -> WebResult {
    if accepts_json(
        req.headers()
            .get(header::ACCEPT)
            .and_then(|value| value.to_str().ok()),
    ) {
        return Ok(api::consent_api(depot, req).await?);
    }

    let ctx = app_state(depot)?;
    if ctx.settings().consent_url().current_value().is_some() {
        let mut response = Response::new();
        response.status_code(StatusCode::NOT_FOUND);
        return Ok(response.into());
    }

    Ok(page::consent_page(depot, req).await?)
}

#[handler]
pub async fn consent_post(depot: &mut Depot, req: &mut Request) -> WebResult {
    let accept = req
        .headers()
        .get(header::ACCEPT)
        .and_then(|value| value.to_str().ok());
    let content_type = req
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok());

    if expects_json_post(accept, content_type) {
        return Ok(api::consent_api_submit(depot, req).await?);
    }

    let ctx = app_state(depot)?;
    if ctx.settings().consent_url().current_value().is_some() {
        let mut response = Response::new();
        response.status_code(StatusCode::NOT_FOUND);
        return Ok(response.into());
    }

    Ok(decision::consent_submit(depot, req).await?)
}
