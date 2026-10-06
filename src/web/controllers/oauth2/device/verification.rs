//! Exchanges a user code for a login interaction bound to the device request.

use http::StatusCode;
use salvo::{Depot, handler, handler::HoopedHandler};
use serde::Deserialize;
use urlencoding::encode;

use super::super::pipeline::{Endpoint, Extract, RequireState, take};
use crate::controllers::response::{
    AppResponse, JsonWebError, JsonWebResult, app_state, insert_no_store_headers, json_response,
};

#[derive(Debug, Deserialize)]
struct BeginBody {
    user_code: String,
}

pub fn verification_endpoint() -> HoopedHandler {
    Endpoint::new("device_verification")
        .action("state", RequireState::<JsonWebError>::new())
        .action("parse_json", Extract::<BeginBody, JsonWebError>::json())
        .finish("begin_verification", begin_verification)
}

/// Browser entry of the verification flow: exchanges a user code for a fresh
/// login interaction bound to the device request (CSRF protected POST).
#[handler]
async fn begin_verification(depot: &mut Depot) -> JsonWebResult<AppResponse> {
    #[derive(Debug, serde::Serialize)]
    struct BeginResponse {
        login_id: String,
        login_uri: String,
    }

    let ctx = app_state(depot)?;
    let body: BeginBody = take(depot)?;

    let (client_oid, request_oid) = ctx
        .services()
        .oidc_device_authorization()
        .begin_verification(&body.user_code)
        .await?;

    let login_id = ctx
        .services()
        .oidc_authorize()
        .create_login_flow(client_oid, request_oid, None)
        .await?;

    let mut response = json_response(
        StatusCode::CREATED,
        BeginResponse {
            login_uri: format!("/login?login_id={}", encode(&login_id)),
            login_id,
        },
    );
    insert_no_store_headers(&mut response);
    Ok(AppResponse(response))
}
