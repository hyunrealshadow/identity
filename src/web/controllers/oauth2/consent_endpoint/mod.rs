use salvo::{Depot, Request, handler};
use serde::Deserialize;

use crate::web::controllers::response::WebResult;

mod api;
mod context;
mod decision;

#[cfg(test)]
mod tests;

#[derive(Debug, Deserialize)]
struct ConsentQuery {
    login_id: String,
}

#[handler]
pub async fn consent_get(depot: &mut Depot, req: &mut Request) -> WebResult {
    Ok(api::consent_api(depot, req).await?)
}

#[handler]
pub async fn consent_post(depot: &mut Depot, req: &mut Request) -> WebResult {
    Ok(api::consent_api_submit(depot, req).await?)
}
