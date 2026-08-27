use http::StatusCode;
use salvo::{Depot, Router, handler};

use identity_domain::openid_connect::BuiltInWorkload;

use crate::{
    application::error::{AppError, codes::common::CommonErrorCode},
    middleware::authenticated_workload,
    web::controllers::response::{
        AppResponse, JsonWebError, JsonWebResult, app_state, insert_no_store_headers, json_response,
    },
};

pub fn routes() -> Router {
    Router::with_path("workloads/self/runtime-configuration").get(runtime_configuration)
}

#[handler]
async fn runtime_configuration(depot: &mut Depot) -> JsonWebResult<AppResponse> {
    let ctx = app_state(depot).map_err(JsonWebError)?;
    let Some(workload) = authenticated_workload(depot) else {
        return Err(JsonWebError(AppError::from_code(
            CommonErrorCode::Unauthorized,
        )));
    };
    if workload.0 != BuiltInWorkload::Login {
        return Err(JsonWebError(AppError::from_code(
            CommonErrorCode::Forbidden,
        )));
    }
    let Some(config) = ctx
        .services()
        .login_runtime()
        .runtime_config()
        .await
        .map_err(JsonWebError)?
    else {
        return Err(JsonWebError(AppError::from_code(CommonErrorCode::NotFound)));
    };
    let mut response = json_response(StatusCode::OK, config);
    insert_no_store_headers(&mut response);
    Ok(response.into())
}
