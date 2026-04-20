use axum::{Router, middleware, response::Redirect, routing::get};
use tower_http::services::{ServeDir, ServeFile};

use crate::application::setting::runtime::SettingProvider;
use crate::boot::AppState;
use crate::infrastructure::{config::AppConfig, health};

use super::{
    controllers,
    middleware::{locale_middleware, security_headers_middleware},
};

pub fn app_router(state: AppState, config: &AppConfig) -> Router {
    let shared_health_listener = health::shares_listener(&config.health, &config.server);
    let mut router = Router::new().nest_service(
        "/static",
        ServeDir::new("assets/static").not_found_service(ServeFile::new("assets/static/404.html")),
    );

    if state.settings().installation().current_value().initialized {
        router = router
            .route("/", get(|| async { Redirect::to("/login") }))
            .merge(controllers::oauth2::routes())
            .merge(controllers::auth::routes())
            .merge(controllers::auth_ui::routes())
            .merge(controllers::well_known::routes());
    } else {
        router = router
            .merge(controllers::install::routes())
            .fallback(|| async { Redirect::to("/install") });
    }

    #[cfg(feature = "oidc-conformance")]
    if state.context().is_conformance() {
        router = router.merge(controllers::conformance::routes());
    }

    if config.health.enable && shared_health_listener {
        router = router.merge(health::router(&config.health));
    }

    router
        .layer(middleware::from_fn(security_headers_middleware))
        .layer(middleware::from_fn(locale_middleware))
        .with_state(state)
}
