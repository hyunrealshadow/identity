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

#[cfg(test)]
mod tests {
    use http::{StatusCode, header};
    use identity_infrastructure::test_app_state_with_cors_origin;
    use salvo::{
        Service,
        affix_state::inject,
        test::{ResponseExt, TestClient},
    };

    use crate::controllers::oauth2::routes;

    #[tokio::test]
    async fn route_accepts_cors_preflight_and_returns_rfc_error_for_missing_client() {
        let state = test_app_state_with_cors_origin(Some("http://localhost:3000")).await;
        let service = Service::new(routes().hoop(inject(state)));
        let preflight = TestClient::options("http://127.0.0.1:5800/oauth2/revoke")
            .add_header(header::ORIGIN, "http://localhost:3000", true)
            .add_header(header::ACCESS_CONTROL_REQUEST_METHOD, "POST", true)
            .send(&service)
            .await;
        assert_eq!(preflight.status_code, Some(StatusCode::NO_CONTENT));
        assert_eq!(
            preflight
                .headers()
                .get(header::ACCESS_CONTROL_ALLOW_ORIGIN)
                .unwrap(),
            "http://localhost:3000"
        );

        let mut response = TestClient::post("http://127.0.0.1:5800/oauth2/revoke")
            .add_header(header::ORIGIN, "http://localhost:3000", true)
            .add_header(
                header::CONTENT_TYPE,
                "application/x-www-form-urlencoded",
                true,
            )
            .body("token=unknown&token_type_hint=refresh_token")
            .send(&service)
            .await;
        assert_eq!(response.status_code, Some(StatusCode::BAD_REQUEST));
        assert_eq!(
            response
                .headers()
                .get(header::ACCESS_CONTROL_ALLOW_ORIGIN)
                .unwrap(),
            "http://localhost:3000"
        );
        assert!(
            response
                .take_string()
                .await
                .unwrap()
                .contains("invalid_request")
        );
    }
}
