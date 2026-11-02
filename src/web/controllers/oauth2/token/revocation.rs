use http::StatusCode;
use identity_application::openid_connect::token::TokenRevocationParams;
use salvo::{Depot, Request, Response, handler, handler::HoopedHandler};

use super::{
    super::pipeline::{Endpoint, Extract, RequireState, take},
    error::RevocationWebError,
    request::TokenInspectionForm,
};
use crate::controllers::response::{AppResponse, app_state, insert_no_store_headers};

pub fn endpoint() -> HoopedHandler {
    Endpoint::new("revoke")
        .action("state", RequireState::<RevocationWebError>::new())
        .action(
            "parse_form",
            Extract::<TokenInspectionForm, RevocationWebError>::form(),
        )
        .action("prepare_credentials", prepare_credentials)
        .finish("revoke", revoke)
}

#[handler]
async fn prepare_credentials(
    depot: &mut Depot,
    req: &mut Request,
) -> Result<(), RevocationWebError> {
    let form: TokenInspectionForm = take(depot)?;
    depot.insert_typed(form.prepare(req.headers())?);
    Ok(())
}

#[handler]
async fn revoke(depot: &mut Depot) -> Result<AppResponse, RevocationWebError> {
    let state = app_state(depot)?;
    let params: TokenRevocationParams = take(depot)?;
    state.services().oidc_token().revoke_token(params).await?;

    let mut response = Response::new();
    response.status_code(StatusCode::OK);
    insert_no_store_headers(&mut response);
    Ok(AppResponse(response))
}
