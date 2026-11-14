use salvo::Router;

use super::{super::shared::browser_csrf_middleware, session, user_info};
use crate::cors::{ClientCors, preflight};

pub fn routes() -> Router {
    Router::new()
        .push(Router::with_path("openid/check_session").get(session::check()))
        .push(Router::with_path("openid/logout").get(session::logout_get()))
        .push(
            Router::with_path("openid/logout")
                .hoop(browser_csrf_middleware())
                .post(session::logout_post()),
        )
        .push(
            Router::with_path("openid/userinfo")
                .hoop(ClientCors::new("GET, POST"))
                .get(user_info::get_endpoint())
                .post(user_info::post_endpoint())
                .options(preflight),
        )
}
