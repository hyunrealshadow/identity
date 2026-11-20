use std::sync::Arc;

use identity_domain::openid_connect::WorkloadAuthenticator;
use identity_infrastructure::{
    AppState,
    config::{AppConfig, TlsTermination},
    observability::context::TraceTrustPolicy,
};
use salvo::{Router, Service, affix_state::inject, serve_static::StaticDir};

use super::{
    controllers::{auth, install, oauth2, observability, openid, well_known, workload_runtime},
    middleware::{
        RequestIdMiddleware, RequireUpstreamHttps, RequireWorkload, ResolveClientIp,
        TraceContextMiddleware, audit_request_context, require_login_workload,
        security_headers_middleware, static_cache_control,
    },
};
use crate::{
    controllers::response::{not_found, not_found_fallback},
    graphql, health,
};

#[cfg(feature = "oidc-conformance")]
use super::controllers::conformance;

/// The public listener's service. The request-wide middleware is attached to
/// the service rather than the root router, so it also runs for paths no
/// route matches: those get the same correlation, security headers and
/// not-found answer as every other request.
pub fn app_router(state: AppState, config: &AppConfig) -> Service {
    let shared_health_listener = health::shares_listener(&config.health, &config.server);
    let mut router = Router::new().push(
        Router::with_path("static/{**path}")
            .hoop(static_cache_control)
            .get(StaticDir::new(["assets/static"])),
    );

    router = router
        .push(oauth2::routes())
        .push(openid::routes())
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

    let mut service = Service::new(router.goal(not_found)).hoop(RequestIdMiddleware::new(
        TraceTrustPolicy::new(config.observability.trace_context.clone()),
    ));
    if config.server.tls.termination == TlsTermination::Upstream {
        service = service.hoop(RequireUpstreamHttps::new(
            &config.server.tls.trusted_proxies,
            &config.server.tls.direct_http_clients,
        ));
    }
    service
        .hoop(ResolveClientIp::new(
            &config.server.tls.trusted_proxies,
            &config.server.tls.direct_http_clients,
        ))
        .hoop(audit_request_context)
        .hoop(TraceContextMiddleware::new(TraceTrustPolicy::new(
            config.observability.trace_context.clone(),
        )))
        .hoop(security_headers_middleware)
        .hoop(inject(state))
        .hoop(inject(config.openid_connect.dynamic_registration.clone()))
        .hoop(not_found_fallback)
}

/// The internal workload listener's service; unmatched paths still require
/// workload authentication before they are answered as not found.
pub fn internal_router(
    state: AppState,
    config: &AppConfig,
    authenticator: Arc<dyn WorkloadAuthenticator>,
) -> Service {
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

    Service::new(Router::new().push(internal).goal(not_found))
        .hoop(RequestIdMiddleware::new(TraceTrustPolicy::new(
            config.observability.trace_context.clone(),
        )))
        .hoop(RequireWorkload::new(authenticator))
        .hoop(ResolveClientIp::new(
            &config.server.tls.trusted_proxies,
            &config.server.tls.direct_http_clients,
        ))
        .hoop(audit_request_context)
        .hoop(TraceContextMiddleware::new(TraceTrustPolicy::new(
            config.observability.trace_context.clone(),
        )))
        .hoop(security_headers_middleware)
        .hoop(inject(state))
        .hoop(not_found_fallback)
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
