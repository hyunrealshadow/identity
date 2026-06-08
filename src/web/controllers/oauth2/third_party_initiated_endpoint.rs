use salvo::{Depot, Request, handler};
use serde::Deserialize;
use url::Url;

use identity_application::openid_connect::authorize::ThirdPartyInitiatedLoginRequest;

use crate::controllers::response::{
    AppResponse, WebResult, app_state, parse_query, redirect_to_response,
};

#[derive(Debug, Deserialize)]
struct ThirdPartyInitiatedLoginQuery {
    client_id: String,
    login_hint: Option<String>,
    target_link_uri: Option<Url>,
}

#[handler]
pub async fn initiate_login(depot: &mut Depot, req: &mut Request) -> WebResult {
    let ctx = app_state(depot)?;
    let query: ThirdPartyInitiatedLoginQuery = parse_query(req)?;
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
