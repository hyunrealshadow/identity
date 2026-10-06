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
#[cfg(test)]
mod tests {
    use http::{StatusCode, header};
    use identity_infrastructure::test_app_state_with_cors_origin;
    use salvo::{
        Service,
        affix_state::inject,
        test::{ResponseExt, TestClient},
    };
    use serde_json::{Value, from_str};

    use crate::controllers::oauth2::routes;

    #[tokio::test]
    async fn introspection_route_requires_authentication_and_token() {
        let state = test_app_state_with_cors_origin(None).await;
        let service = Service::new(routes().hoop(inject(state)));
        let mut response = TestClient::post("http://127.0.0.1:5800/oauth2/introspect")
            .add_header(
                header::CONTENT_TYPE,
                "application/x-www-form-urlencoded",
                true,
            )
            .body("token=unknown&token_type_hint=unrecognized")
            .send(&service)
            .await;
        assert_eq!(response.status_code, Some(StatusCode::UNAUTHORIZED));
        assert_eq!(
            response.headers().get(header::CACHE_CONTROL).unwrap(),
            "no-store"
        );
        let json: Value = from_str(&response.take_string().await.unwrap()).unwrap();
        assert_eq!(json["error"], "invalid_client");
        let response = TestClient::post("http://127.0.0.1:5800/oauth2/introspect")
            .add_header(
                header::CONTENT_TYPE,
                "application/x-www-form-urlencoded",
                true,
            )
            .body("client_id=unknown")
            .send(&service)
            .await;
        assert_eq!(response.status_code, Some(StatusCode::BAD_REQUEST));
    }
}
