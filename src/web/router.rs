use salvo::{Router, serve_static::StaticDir};

use crate::controllers::response::handle_404;
use crate::health;
use identity_application::setting::runtime::SettingProvider;
use identity_infrastructure::AppState;
use identity_infrastructure::config::{AppConfig, TlsTermination};

use super::{
    controllers,
    middleware::{require_upstream_https_middleware, security_headers_middleware},
};

pub fn app_router(state: AppState, config: &AppConfig) -> Router {
    let shared_health_listener = health::shares_listener(&config.health, &config.server);
    let mut router = Router::new();
    if config.server.tls.termination == TlsTermination::Upstream {
        router = router.hoop(require_upstream_https_middleware);
    }
    router = router
        .hoop(security_headers_middleware)
        .hoop(salvo::affix_state::inject(state.clone()))
        .push(
            Router::with_path("static/{**path}")
                .get(StaticDir::new(["assets/static"]).fallback("404.html")),
        );

    if *state.settings().installation_initialized().current_value() {
        router = router
            .push(controllers::oauth2::routes())
            .push(controllers::auth::routes())
            .push(controllers::well_known::routes());
    } else {
        router = router.push(controllers::install::routes());
    }

    #[cfg(feature = "oidc-conformance")]
    if state.context().is_conformance() {
        router = router.push(controllers::conformance::routes());
    }

    if config.health.enable && shared_health_listener {
        router = router.push(health::router(&config.health));
    }

    router = router.goal(handle_404);

    router
}
