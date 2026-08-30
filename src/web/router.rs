use std::sync::Arc;

use salvo::{Router, serve_static::StaticDir};

use crate::controllers::response::handle_404;
use crate::graphql;
use crate::health;
use identity_domain::openid_connect::WorkloadAuthenticator;
use identity_infrastructure::AppState;
use identity_infrastructure::config::{AppConfig, TlsTermination};

use super::{
    controllers,
    middleware::{
        RequireUpstreamHttps, RequireWorkload, ResolveClientIp, security_headers_middleware,
    },
};

pub fn app_router(state: AppState, config: &AppConfig) -> Router {
    let shared_health_listener = health::shares_listener(&config.health, &config.server);
    let mut router = Router::new();
    if config.server.tls.termination == TlsTermination::Upstream {
        router = router.hoop(RequireUpstreamHttps::new(
            &config.server.tls.trusted_proxies,
            &config.server.tls.direct_http_clients,
        ));
    }
    router = router
        .hoop(ResolveClientIp::new(
            &config.server.tls.trusted_proxies,
            &config.server.tls.direct_http_clients,
        ))
        .hoop(security_headers_middleware)
        .hoop(salvo::affix_state::inject(state.clone()))
        .hoop(salvo::affix_state::inject(
            config.openid_connect.dynamic_registration.clone(),
        ))
        .push(
            Router::with_path("static/{**path}")
                .get(StaticDir::new(["assets/static"]).fallback("404.html")),
        );

    router = router
        .push(controllers::oauth2::routes())
        .push(controllers::auth::routes())
        .push(controllers::well_known::routes());

    #[cfg(feature = "oidc-conformance")]
    if state.context().is_conformance() {
        router = router.push(controllers::conformance::routes());
    }

    if config.health.enable && shared_health_listener {
        router = router.push(health::router(&config.health));
    }
    if graphql::shares_listener(&config.graphql, &config.server) {
        router = router.push(graphql::router(state.clone(), &config.graphql));
    }

    router = router.goal(handle_404);

    router
}

pub fn internal_router(
    state: AppState,
    config: &AppConfig,
    authenticator: Arc<dyn WorkloadAuthenticator>,
) -> Router {
    Router::new()
        .hoop(RequireWorkload::new(authenticator))
        .hoop(ResolveClientIp::new(
            &config.server.tls.trusted_proxies,
            &config.server.tls.direct_http_clients,
        ))
        .hoop(security_headers_middleware)
        .hoop(salvo::affix_state::inject(state))
        .push(
            Router::with_path("internal")
                .push(controllers::install::status_routes())
                .push(controllers::install::routes())
                .push(controllers::login_runtime::routes()),
        )
        .goal(handle_404)
}
