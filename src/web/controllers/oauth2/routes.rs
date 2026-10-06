use salvo::Router;

use super::{
    super::shared::{api_csrf_middleware, browser_csrf_middleware},
    authorization, device, registration, session, token, user_info,
};
use crate::cors::{ClientCors, preflight};

pub fn routes() -> Router {
    Router::new()
        .push(Router::with_path("oauth2/continue").get(authorization::continue_authorization()))
        .push(
            Router::with_path("oauth2/authorize")
                .get(authorization::authorize())
                .post(authorization::authorize()),
        )
        .push(
            Router::with_path("oauth2/token")
                .hoop(ClientCors::new("POST"))
                .post(token::exchange())
                .options(preflight),
        )
        .push(
            Router::with_path("oauth2/revoke")
                .hoop(ClientCors::new("POST"))
                .post(token::revoke())
                .options(preflight),
        )
        .push(
            Router::with_path("oauth2/par")
                .hoop(ClientCors::new("POST"))
                .post(authorization::par())
                .options(preflight)
                .goal(authorization::method_not_allowed),
        )
        .push(Router::with_path("oauth2/introspect").post(token::introspect()))
        .push(Router::with_path("oauth2/device").post(device::authorize()))
        .push(
            Router::with_path("oauth2/device/login")
                .hoop(api_csrf_middleware())
                .post(device::begin_verification()),
        )
        .push(
            Router::with_path("oauth2/register")
                .hoop(ClientCors::new("POST"))
                .post(registration::register_endpoint())
                .options(preflight),
        )
        .push(
            Router::with_path("oauth2/register/{client_id}")
                .hoop(ClientCors::new("GET, PUT, DELETE"))
                .get(registration::read_endpoint())
                .put(registration::update_endpoint())
                .delete(registration::delete_endpoint())
                .options(preflight),
        )
        .push(Router::with_path("oauth2/initiate_login").get(authorization::initiate_login()))
        .push(Router::with_path("oauth2/check_session").get(session::check()))
        .push(Router::with_path("oauth2/logout").get(session::logout_get()))
        .push(
            Router::with_path("oauth2/logout")
                .hoop(browser_csrf_middleware())
                .post(session::logout_post()),
        )
        .push(
            Router::with_path("oauth2/userinfo")
                .hoop(ClientCors::new("GET, POST"))
                .get(user_info::get_endpoint())
                .post(user_info::post_endpoint())
                .options(preflight),
        )
        .push(
            Router::with_path("oauth2/consent")
                .hoop(api_csrf_middleware())
                .get(authorization::consent_get())
                .post(authorization::consent_post()),
        )
}
