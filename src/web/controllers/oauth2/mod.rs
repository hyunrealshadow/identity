use salvo::Router;

use crate::cors::{ClientCors, preflight};

use super::shared::{api_csrf_middleware, browser_csrf_middleware};

mod authorization_error;
mod authorize_endpoint;
mod consent_endpoint;
mod continue_endpoint;
mod device_authorization_endpoint;
mod logout_endpoint;
mod registration_endpoint;
mod revocation_endpoint;
mod session_endpoint;
mod third_party_initiated_endpoint;
mod token_endpoint;
mod user_info_endpoint;

#[cfg(test)]
mod tests;

pub use authorize_endpoint::{
    AuthorizeRequestExtractor, FlowDecision, RawAuthorizeRequest, authorize_input_error,
    finish_authorize_redirect, inline_script_csp_header_value, redirect_oauth_error_response,
    response_mode_from_value, select_active_session,
};

pub fn routes() -> Router {
    Router::new()
        .push(Router::with_path("oauth2/continue").get(continue_endpoint::continue_get))
        .push(
            Router::with_path("oauth2/authorize")
                .get(authorize_endpoint::authorize)
                .post(authorize_endpoint::authorize),
        )
        .push(
            Router::with_path("oauth2/token")
                .hoop(ClientCors::new("POST"))
                .post(token_endpoint::token)
                .options(preflight),
        )
        .push(
            Router::with_path("oauth2/revoke")
                .hoop(ClientCors::new("POST"))
                .post(revocation_endpoint::revoke)
                .options(preflight),
        )
        .push(
            Router::with_path("oauth2/device")
                .post(device_authorization_endpoint::device_authorization),
        )
        .push(
            Router::with_path("oauth2/device/login")
                .hoop(api_csrf_middleware())
                .post(device_authorization_endpoint::begin_verification),
        )
        .push(
            Router::with_path("oauth2/register")
                .hoop(ClientCors::new("POST"))
                .post(registration_endpoint::register)
                .options(preflight),
        )
        .push(
            Router::with_path("oauth2/register/{client_id}")
                .hoop(ClientCors::new("GET, DELETE"))
                .get(registration_endpoint::read)
                .delete(registration_endpoint::delete)
                .options(preflight),
        )
        .push(
            Router::with_path("oauth2/initiate_login")
                .get(third_party_initiated_endpoint::initiate_login),
        )
        .push(Router::with_path("oauth2/check_session").get(session_endpoint::check_session_iframe))
        .push(Router::with_path("oauth2/logout").get(logout_endpoint::logout_get))
        .push(
            Router::with_path("oauth2/logout")
                .hoop(browser_csrf_middleware())
                .post(logout_endpoint::logout_post),
        )
        .push(
            Router::with_path("oauth2/userinfo")
                .hoop(ClientCors::new("GET, POST"))
                .get(user_info_endpoint::userinfo)
                .post(user_info_endpoint::userinfo_post)
                .options(preflight),
        )
        .push(
            Router::with_path("oauth2/consent")
                .hoop(api_csrf_middleware())
                .get(consent_endpoint::consent_get)
                .post(consent_endpoint::consent_post),
        )
}

#[cfg(test)]
mod cors_tests {
    use http::{StatusCode, header};
    use salvo::{Service, test::TestClient};

    use super::routes;

    #[tokio::test]
    async fn token_preflight_uses_cached_client_origin_but_authorization_does_not() {
        let state =
            identity_infrastructure::test_app_state_with_cors_origin(Some("http://localhost:3000"))
                .await;
        let service = Service::new(routes().hoop(salvo::affix_state::inject(state)));

        let allowed = TestClient::options("http://127.0.0.1:5800/oauth2/token")
            .add_header(header::ORIGIN, "http://localhost:3000", true)
            .add_header(header::ACCESS_CONTROL_REQUEST_METHOD, "POST", true)
            .send(&service)
            .await;
        assert_eq!(allowed.status_code, Some(StatusCode::NO_CONTENT));
        assert_eq!(
            allowed
                .headers()
                .get(header::ACCESS_CONTROL_ALLOW_ORIGIN)
                .unwrap(),
            "http://localhost:3000"
        );
        assert!(
            allowed
                .headers()
                .get(header::ACCESS_CONTROL_ALLOW_CREDENTIALS)
                .is_none()
        );

        let actual = TestClient::post("http://127.0.0.1:5800/oauth2/token")
            .add_header(header::ORIGIN, "http://localhost:3000", true)
            .add_header(
                header::CONTENT_TYPE,
                "application/x-www-form-urlencoded",
                true,
            )
            .body("grant_type=unsupported")
            .send(&service)
            .await;
        assert_eq!(actual.status_code, Some(StatusCode::BAD_REQUEST));
        assert_eq!(
            actual
                .headers()
                .get(header::ACCESS_CONTROL_ALLOW_ORIGIN)
                .unwrap(),
            "http://localhost:3000"
        );

        let denied = TestClient::options("http://127.0.0.1:5800/oauth2/token")
            .add_header(header::ORIGIN, "https://other.example", true)
            .add_header(header::ACCESS_CONTROL_REQUEST_METHOD, "POST", true)
            .send(&service)
            .await;
        assert_eq!(denied.status_code, Some(StatusCode::FORBIDDEN));
        assert!(
            denied
                .headers()
                .get(header::ACCESS_CONTROL_ALLOW_ORIGIN)
                .is_none()
        );

        let authorize = TestClient::options("http://127.0.0.1:5800/oauth2/authorize")
            .add_header(header::ORIGIN, "http://localhost:3000", true)
            .add_header(header::ACCESS_CONTROL_REQUEST_METHOD, "GET", true)
            .send(&service)
            .await;
        assert!(
            authorize
                .headers()
                .get(header::ACCESS_CONTROL_ALLOW_ORIGIN)
                .is_none()
        );
    }
}
