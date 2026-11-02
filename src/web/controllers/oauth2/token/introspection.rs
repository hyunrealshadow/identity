use http::StatusCode;
use identity_application::openid_connect::token::TokenIntrospectionParams;
use salvo::{Depot, Request, handler, handler::HoopedHandler};

use super::{
    super::pipeline::{Endpoint, Extract, RequireState, take},
    error::IntrospectionWebError,
    request::TokenInspectionForm,
};
use crate::controllers::response::{
    AppResponse, app_state, insert_no_store_headers, json_response,
};

pub fn endpoint() -> HoopedHandler {
    Endpoint::new("introspect")
        .action("state", RequireState::<IntrospectionWebError>::new())
        .action(
            "parse_form",
            Extract::<TokenInspectionForm, IntrospectionWebError>::form(),
        )
        .action("prepare_credentials", prepare_credentials)
        .finish("introspect", introspect)
}

#[handler]
async fn prepare_credentials(
    depot: &mut Depot,
    req: &mut Request,
) -> Result<(), IntrospectionWebError> {
    let form: TokenInspectionForm = take(depot)?;
    depot.insert_typed(form.prepare(req.headers())?);
    Ok(())
}

#[handler]
async fn introspect(depot: &mut Depot) -> Result<AppResponse, IntrospectionWebError> {
    let state = app_state(depot)?;
    let params: TokenIntrospectionParams = take(depot)?;
    let result = state
        .services()
        .oidc_token()
        .introspect_token(params)
        .await?;

    let mut response = json_response(StatusCode::OK, result);
    insert_no_store_headers(&mut response);
    Ok(AppResponse(response))
}
