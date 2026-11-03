use std::sync::Arc;

use identity_domain::openid_connect::WorkloadAuthenticator;
use identity_infrastructure::{
    AppState,
    config::{AppConfig, TlsTermination},
    observability::context::TraceTrustPolicy,
};
use salvo::{Router, affix_state::inject, serve_static::StaticDir};

use super::{
    controllers::{auth, install, oauth2, observability, well_known, workload_runtime},
    middleware::{
        RequestIdMiddleware, RequireUpstreamHttps, RequireWorkload, ResolveClientIp,
        TraceContextMiddleware, require_login_workload, security_headers_middleware,
    },
};
use crate::{controllers::response::handle_404, graphql, health};

#[cfg(feature = "oidc-conformance")]
use super::controllers::conformance;

pub fn app_router(state: AppState, config: &AppConfig) -> Router {
    let shared_health_listener = health::shares_listener(&config.health, &config.server);
    let mut router = Router::new().hoop(RequestIdMiddleware::new(TraceTrustPolicy::new(
        config.observability.trace_context.clone(),
    )));
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
        .hoop(TraceContextMiddleware::new(TraceTrustPolicy::new(
            config.observability.trace_context.clone(),
        )))
        .hoop(security_headers_middleware)
        .hoop(inject(state.clone()))
        .hoop(inject(config.openid_connect.dynamic_registration.clone()))
        .push(
            Router::with_path("static/{**path}")
                .get(StaticDir::new(["assets/static"]).fallback("404.html")),
        );

    router = router
        .push(oauth2::routes())
        .push(auth::routes())
        .push(well_known::routes());

    #[cfg(feature = "oidc-conformance")]
    if state.context().is_conformance() {
        router = router.push(conformance::routes());
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
    let mut login = Router::new()
        .hoop(require_login_workload)
        .push(install::status_routes())
        .push(install::routes());
    if config.observability.self_metrics.enable {
        login = login.push(
            Router::with_path(internal_relative_route(
                &config.observability.self_metrics.route,
            ))
            .get(observability::observability_metrics),
        );
    }
    let internal = Router::with_path("internal")
        .push(workload_runtime::routes())
        .push(login);

    Router::new()
        .hoop(RequestIdMiddleware::new(TraceTrustPolicy::new(
            config.observability.trace_context.clone(),
        )))
        .hoop(RequireWorkload::new(authenticator))
        .hoop(ResolveClientIp::new(
            &config.server.tls.trusted_proxies,
            &config.server.tls.direct_http_clients,
        ))
        .hoop(TraceContextMiddleware::new(TraceTrustPolicy::new(
            config.observability.trace_context.clone(),
        )))
        .hoop(security_headers_middleware)
        .hoop(inject(state))
        .push(internal)
        .goal(handle_404)
}

/// Convert the configured self-metrics route into a path relative to the
/// internal listener, which is mounted under `internal`.
fn internal_relative_route(route: &str) -> String {
    let relative = route.trim_start_matches('/');
    relative
        .strip_prefix("internal/")
        .unwrap_or(relative)
        .trim_end_matches('/')
        .to_owned()
}
