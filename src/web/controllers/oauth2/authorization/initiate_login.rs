use identity_application::openid_connect::authorize::ThirdPartyInitiatedLoginRequest;
use salvo::{Depot, handler, handler::HoopedHandler};
use serde::Deserialize;
use url::Url;

use super::super::pipeline::{Endpoint, Extract, RequireState, take};
use crate::controllers::response::{
    AppResponse, WebError, WebResult, app_state, redirect_to_response,
};

#[derive(Debug, Deserialize)]
struct ThirdPartyInitiatedLoginQuery {
    client_id: String,
    login_hint: Option<String>,
    target_link_uri: Option<Url>,
}

pub fn endpoint() -> HoopedHandler {
    Endpoint::new("initiate_login")
        .action("state", RequireState::<WebError>::new())
        .action(
            "parse_query",
            Extract::<ThirdPartyInitiatedLoginQuery, WebError>::query(),
        )
        .finish("initiate_login", initiate_login)
}

#[handler]
async fn initiate_login(depot: &mut Depot) -> WebResult {
    let ctx = app_state(depot)?;
    let query: ThirdPartyInitiatedLoginQuery = take(depot)?;
    let redirect_uri = ctx
        .services()
        .oidc_authorize()
        .third_party_initiated_login(ThirdPartyInitiatedLoginRequest {
            client_id: query.client_id,
            login_hint: query.login_hint,
            target_link_uri: query.target_link_uri,
        })
        .await?;

    Ok(AppResponse(redirect_to_response(redirect_uri.as_str())))
}
