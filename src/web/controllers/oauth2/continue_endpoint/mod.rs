use http::HeaderMap;
use salvo::{Depot, Request, handler};
use serde::Deserialize;

use crate::{
    application::error::AppError,
    web::controllers::response::{AppResponse, app_state, parse_query},
};

mod flow;
mod response;

#[cfg(test)]
mod tests;

#[derive(Debug, Deserialize)]
struct ContinueQuery {
    login_id: String,
}

#[handler]
pub async fn continue_get(depot: &mut Depot, req: &mut Request) -> Result<AppResponse, AppError> {
    let ctx = app_state(depot)?;
    let headers: HeaderMap = req.headers().clone();
    let query: ContinueQuery = parse_query(req)?;
    flow::handle_continue(&ctx, &headers, &query.login_id).await
}
