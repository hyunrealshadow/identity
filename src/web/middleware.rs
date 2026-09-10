use std::{net::IpAddr, sync::Arc};

use async_trait::async_trait;
use http::{HeaderValue, header};
use ipnet::IpNet;
use salvo::{Depot, FlowCtrl, Handler, Request, Response, handler};

use identity_domain::openid_connect::{AuthenticatedWorkload, WorkloadAuthenticator};
use identity_infrastructure::observability::context::{
    self as trace_context, ParentDecision, TraceTrustPolicy,
};
use opentelemetry::trace::Status;
use tracing::Instrument;
use tracing_opentelemetry::OpenTelemetrySpanExt;

use crate::{
    application::error::{AppError, codes::common::CommonErrorCode},
    controllers::response::render_app_error_json,
};

fn render_workload_unauthorized(res: &mut Response, invalid_token: bool) {
    let challenge = if invalid_token {
        HeaderValue::from_static("Bearer realm=\"identity-internal\", error=\"invalid_token\"")
    } else {
        HeaderValue::from_static("Bearer realm=\"identity-internal\"")
    };
    res.headers_mut()
        .insert(header::WWW_AUTHENTICATE, challenge);
    render_app_error_json(res, AppError::from_code(CommonErrorCode::Unauthorized));
}

#[derive(Clone)]
pub struct RequireWorkload {
    authenticator: Arc<dyn WorkloadAuthenticator>,
}

impl RequireWorkload {
    #[must_use]
    pub fn new(authenticator: Arc<dyn WorkloadAuthenticator>) -> Self {
        Self { authenticator }
    }
}

#[async_trait]
impl Handler for RequireWorkload {
    async fn handle(
        &self,
        req: &mut Request,
        depot: &mut Depot,
        res: &mut Response,
        ctrl: &mut FlowCtrl,
    ) {
        let token = req
            .headers()
            .get(header::AUTHORIZATION)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.strip_prefix("Bearer "))
            .filter(|value| !value.is_empty());
        let Some(token) = token else {
            render_workload_unauthorized(res, false);
            ctrl.skip_rest();
            return;
        };
        let Some(workload) = self.authenticator.authenticate(token).await else {
            render_workload_unauthorized(res, true);
            ctrl.skip_rest();
            return;
        };
        depot.inject(workload);
        ctrl.call_next(req, depot, res).await;
    }
}

/// The workload that the current internal API request was authenticated as.
#[must_use]
pub fn authenticated_workload(depot: &Depot) -> Option<AuthenticatedWorkload> {
    depot.obtain::<AuthenticatedWorkload>().ok().copied()
}

/// Extracts W3C trace context, decides whether it may be continued and wraps
/// the rest of the request in a server span. Invalid headers never fail the
/// request; untrusted contexts become links instead of parents.
#[derive(Clone, Debug)]
pub struct TraceContextMiddleware {
    policy: TraceTrustPolicy,
}

impl TraceContextMiddleware {
    #[must_use]
    pub fn new(policy: TraceTrustPolicy) -> Self {
        Self { policy }
    }
}

#[async_trait]
impl Handler for TraceContextMiddleware {
    async fn handle(
        &self,
        req: &mut Request,
        depot: &mut Depot,
        res: &mut Response,
        ctrl: &mut FlowCtrl,
    ) {
        let extracted = trace_context::extract(req.headers());
        let peer = req.remote_addr().ip();
        // Only a verified workload identity counts as trust; the authenticated
        // subject of a user-facing request does not.
        let verified_workload = depot.obtain::<AuthenticatedWorkload>().is_ok();
        let trusted = self.policy.trusts_inbound(peer, verified_workload);
        let decision = extracted.parent_decision(trusted);

        let method = req.method().as_str().to_owned();
        let path = req.uri().path().to_owned();
        let client_address = peer.map(|ip| ip.to_string()).unwrap_or_default();
        let span = tracing::info_span!(
            "http.server",
            otel.kind = "server",
            http.request.method = %method,
            url.path = %path,
            client.address = %client_address,
            http.route = tracing::field::Empty,
            http.response.status_code = tracing::field::Empty,
        );
        match decision {
            ParentDecision::ContinueInbound(parent) => {
                let _ = span.set_parent(parent);
            }
            ParentDecision::NewTraceWithLink(span_context) => span.add_link(span_context),
            ParentDecision::NewTrace => {}
        }

        let request_span = span.clone();
        async { ctrl.call_next(req, depot, res).await }
            .instrument(span)
            .await;

        request_span.record("http.route", req.matched_path());
        if let Some(status) = res.status_code {
            request_span.record("http.response.status_code", status.as_u16());
            if status.is_server_error() {
                request_span.set_status(Status::error(
                    status
                        .canonical_reason()
                        .unwrap_or("server error")
                        .to_owned(),
                ));
            } else {
                request_span.set_status(Status::Ok);
            }
        }
    }
}

#[derive(Clone, Debug)]
pub struct RequireUpstreamHttps {
    trusted_proxies: Arc<[IpNet]>,
    direct_http_clients: Arc<[IpNet]>,
}

#[derive(Clone, Debug)]
pub struct ResolveClientIp {
    trusted_proxies: Arc<[IpNet]>,
}

#[derive(Clone, Copy, Debug)]
struct ClientIp(Option<IpAddr>);

impl ResolveClientIp {
    #[must_use]
    pub fn new(trusted_proxies: &[IpNet], direct_http_clients: &[IpNet]) -> Self {
        Self {
            trusted_proxies: trusted_proxies
                .iter()
                .chain(direct_http_clients)
                .cloned()
                .collect(),
        }
    }
}

impl RequireUpstreamHttps {
    #[must_use]
    pub fn new(trusted_proxies: &[IpNet], direct_http_clients: &[IpNet]) -> Self {
        Self {
            trusted_proxies: trusted_proxies.into(),
            direct_http_clients: direct_http_clients.into(),
        }
    }

    fn peer_is_trusted(&self, req: &Request) -> bool {
        req.remote_addr().ip().is_some_and(|peer| {
            self.trusted_proxies
                .iter()
                .any(|network| network.contains(&peer))
        })
    }

    fn peer_can_use_direct_http(&self, req: &Request) -> bool {
        req.remote_addr().ip().is_some_and(|peer| {
            self.direct_http_clients
                .iter()
                .any(|network| network.contains(&peer))
        })
    }
}

#[async_trait]
impl Handler for ResolveClientIp {
    async fn handle(
        &self,
        req: &mut Request,
        depot: &mut Depot,
        res: &mut Response,
        ctrl: &mut FlowCtrl,
    ) {
        depot.inject(ClientIp(resolve_client_ip(req, &self.trusted_proxies)));
        ctrl.call_next(req, depot, res).await;
    }
}

#[must_use]
pub fn resolved_client_ip(depot: &Depot) -> Option<String> {
    depot
        .obtain::<ClientIp>()
        .ok()
        .and_then(|client| client.0)
        .map(|address| address.to_string())
}

fn resolve_client_ip(req: &Request, trusted_proxies: &[IpNet]) -> Option<IpAddr> {
    let peer = req.remote_addr().ip()?;
    if !trusted_proxies
        .iter()
        .any(|network| network.contains(&peer))
    {
        return Some(peer);
    }

    forwarded_client_ip(req).or(Some(peer))
}

fn forwarded_client_ip(req: &Request) -> Option<IpAddr> {
    if let Some(address) = req
        .headers()
        .get("x-forwarded-for")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.split(',').next())
        .and_then(parse_forwarded_ip)
    {
        return Some(address);
    }

    req.headers()
        .get("x-real-ip")
        .and_then(|value| value.to_str().ok())
        .and_then(parse_forwarded_ip)
}

fn parse_forwarded_ip(value: &str) -> Option<IpAddr> {
    let value = value.trim().trim_matches('"');
    let value = value
        .strip_prefix('[')
        .and_then(|value| value.strip_suffix(']'))
        .unwrap_or(value);
    value.parse().ok()
}

fn forwarded_proto_is_https(req: &Request) -> bool {
    let x_forwarded_proto = req
        .headers()
        .get("x-forwarded-proto")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.split(',').next())
        .is_some_and(|value| value.trim().eq_ignore_ascii_case("https"));
    if x_forwarded_proto {
        return true;
    }

    req.headers()
        .get_all("forwarded")
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(',').next().into_iter())
        .flat_map(|value| value.split(';'))
        .filter_map(|parameter| parameter.trim().split_once('='))
        .any(|(name, value)| {
            name.eq_ignore_ascii_case("proto")
                && value.trim_matches('"').eq_ignore_ascii_case("https")
        })
}

#[async_trait]
impl Handler for RequireUpstreamHttps {
    async fn handle(
        &self,
        req: &mut Request,
        depot: &mut Depot,
        res: &mut Response,
        ctrl: &mut FlowCtrl,
    ) {
        if !self.peer_can_use_direct_http(req)
            && (!self.peer_is_trusted(req) || !forwarded_proto_is_https(req))
        {
            res.status_code(http::StatusCode::BAD_REQUEST);
            ctrl.skip_rest();
            return;
        }

        ctrl.call_next(req, depot, res).await;
    }
}

#[handler]
pub async fn security_headers_middleware(
    req: &mut Request,
    depot: &mut Depot,
    res: &mut Response,
    ctrl: &mut FlowCtrl,
) {
    let allows_framing = req.uri().path() == "/oauth2/check_session";
    ctrl.call_next(req, depot, res).await;
    let headers = res.headers_mut();
    headers.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    if !allows_framing {
        headers.insert(header::X_FRAME_OPTIONS, HeaderValue::from_static("DENY"));
    }
    headers.insert(
        header::HeaderName::from_static("x-xss-protection"),
        HeaderValue::from_static("0"),
    );
    headers.insert(
        header::REFERRER_POLICY,
        HeaderValue::from_static("strict-origin-when-cross-origin"),
    );
    headers
        .entry(header::HeaderName::from_static("content-security-policy"))
        .or_insert(HeaderValue::from_static("default-src 'self'"));
    headers.insert(
        header::STRICT_TRANSPORT_SECURITY,
        HeaderValue::from_static("max-age=31536000; includeSubDomains"),
    );
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use async_trait::async_trait;
    use http::{StatusCode, header};
    use ipnet::IpNet;
    use salvo::{
        Response, Router, Service, handler,
        test::{ResponseExt, TestClient},
    };

    use identity_domain::openid_connect::{
        AuthenticatedWorkload, BuiltInWorkload, WorkloadAuthenticator,
    };
    use identity_infrastructure::observability::context::TraceTrustPolicy;
    use opentelemetry::trace::TracerProvider;
    use tracing_subscriber::layer::SubscriberExt;

    use super::{
        RequireUpstreamHttps, RequireWorkload, TraceContextMiddleware, resolve_client_ip,
        security_headers_middleware,
    };

    struct StubWorkloadAuthenticator {
        token: &'static str,
    }

    #[async_trait]
    impl WorkloadAuthenticator for StubWorkloadAuthenticator {
        async fn authenticate(&self, token: &str) -> Option<AuthenticatedWorkload> {
            (token == self.token).then_some(AuthenticatedWorkload(BuiltInWorkload::Login))
        }
    }

    #[handler]
    async fn ok(res: &mut Response) {
        res.status_code(StatusCode::OK);
    }

    #[tokio::test]
    async fn security_headers_skip_x_frame_options_for_check_session_iframe() {
        let service = Service::new(
            Router::new()
                .hoop(security_headers_middleware)
                .push(Router::with_path("oauth2/check_session").get(ok)),
        );

        let response = TestClient::get("http://127.0.0.1:5800/oauth2/check_session")
            .send(&service)
            .await;

        assert_eq!(response.status_code, Some(StatusCode::OK));
        assert!(response.headers().get(header::X_FRAME_OPTIONS).is_none());
    }

    #[tokio::test]
    async fn security_headers_deny_framing_for_regular_routes() {
        let service = Service::new(
            Router::new()
                .hoop(security_headers_middleware)
                .push(Router::with_path("login").get(ok)),
        );

        let response = TestClient::get("http://127.0.0.1:5800/login")
            .send(&service)
            .await;

        assert_eq!(
            response.headers().get(header::X_FRAME_OPTIONS).unwrap(),
            "DENY"
        );
    }

    #[tokio::test]
    async fn upstream_tls_rejects_requests_without_https_forwarding_metadata() {
        let guard = RequireUpstreamHttps::new(&["127.0.0.1/32".parse::<IpNet>().unwrap()], &[]);
        let service = Service::new(
            Router::new()
                .hoop(guard)
                .push(Router::with_path("login").get(ok)),
        );

        let response = send_from_peer(&service, None, "127.0.0.1:41000").await;

        assert_eq!(response.status_code, Some(StatusCode::BAD_REQUEST));
    }

    #[tokio::test]
    async fn upstream_tls_rejects_spoofed_headers_from_untrusted_peer() {
        let guard = RequireUpstreamHttps::new(&["10.0.0.0/8".parse::<IpNet>().unwrap()], &[]);
        let service = Service::new(
            Router::new()
                .hoop(guard)
                .push(Router::with_path("login").get(ok)),
        );

        let response = send_from_peer(
            &service,
            Some(("x-forwarded-proto", "https")),
            "192.0.2.5:41000",
        )
        .await;

        assert_eq!(response.status_code, Some(StatusCode::BAD_REQUEST));
    }

    #[tokio::test]
    async fn upstream_tls_accepts_forwarded_https_from_trusted_peer() {
        let guard = RequireUpstreamHttps::new(&["10.0.0.0/8".parse::<IpNet>().unwrap()], &[]);
        let service = Service::new(
            Router::new()
                .hoop(guard)
                .push(Router::with_path("login").get(ok)),
        );

        let response = send_from_peer(
            &service,
            Some(("forwarded", "for=192.0.2.4;proto=https")),
            "10.1.2.3:41000",
        )
        .await;

        assert_eq!(response.status_code, Some(StatusCode::OK));
    }

    #[tokio::test]
    async fn upstream_tls_accepts_plain_http_from_an_explicit_direct_client() {
        let guard = RequireUpstreamHttps::new(&[], &["10.42.1.7/32".parse::<IpNet>().unwrap()]);
        let service = Service::new(
            Router::new()
                .hoop(guard)
                .push(Router::with_path("login").get(ok)),
        );

        let response = send_from_peer(&service, None, "10.42.1.7:41000").await;

        assert_eq!(response.status_code, Some(StatusCode::OK));
    }

    #[tokio::test]
    async fn internal_token_rejects_missing_or_wrong_token() {
        let service = Service::new(
            Router::new()
                .hoop(RequireWorkload::new(Arc::new(StubWorkloadAuthenticator {
                    token: "0123456789abcdef0123456789abcdef",
                })))
                .push(Router::with_path("install").post(ok)),
        );

        let mut missing = TestClient::post("http://127.0.0.1:5800/install")
            .send(&service)
            .await;
        assert_eq!(missing.status_code, Some(StatusCode::UNAUTHORIZED));
        assert_eq!(
            missing.headers().get(header::WWW_AUTHENTICATE).unwrap(),
            "Bearer realm=\"identity-internal\""
        );
        let missing_body = missing.take_string().await.unwrap();
        assert!(missing_body.contains("\"code\":10003"), "{missing_body}");
        assert!(missing_body.contains("\"message\":"), "{missing_body}");
        assert!(!missing_body.contains("\"brief\":"), "{missing_body}");

        let mut wrong = TestClient::post("http://127.0.0.1:5800/install")
            .add_header("authorization", "Bearer wrong-token", true)
            .send(&service)
            .await;
        assert_eq!(wrong.status_code, Some(StatusCode::UNAUTHORIZED));
        assert_eq!(
            wrong.headers().get(header::WWW_AUTHENTICATE).unwrap(),
            "Bearer realm=\"identity-internal\", error=\"invalid_token\""
        );
        let wrong_body = wrong.take_string().await.unwrap();
        assert!(wrong_body.contains("\"code\":10003"), "{wrong_body}");
        assert!(wrong_body.contains("\"message\":"), "{wrong_body}");
        assert!(!wrong_body.contains("\"brief\":"), "{wrong_body}");
    }

    #[tokio::test]
    async fn internal_token_accepts_matching_bearer_token() {
        let service = Service::new(
            Router::new()
                .hoop(RequireWorkload::new(Arc::new(StubWorkloadAuthenticator {
                    token: "0123456789abcdef0123456789abcdef",
                })))
                .push(Router::with_path("install").post(ok)),
        );

        let response = TestClient::post("http://127.0.0.1:5800/install")
            .add_header(
                "authorization",
                "Bearer 0123456789abcdef0123456789abcdef",
                true,
            )
            .send(&service)
            .await;

        assert_eq!(response.status_code, Some(StatusCode::OK));
    }

    #[test]
    fn client_ip_ignores_forwarding_headers_from_untrusted_peer() {
        let mut request = TestClient::get("http://127.0.0.1:5800/login")
            .add_header("x-forwarded-for", "203.0.113.10", true)
            .build();
        *request.remote_addr_mut() = "192.0.2.5:41000"
            .parse::<std::net::SocketAddr>()
            .unwrap()
            .into();

        assert_eq!(
            resolve_client_ip(&request, &["10.0.0.0/8".parse::<IpNet>().unwrap()]),
            Some("192.0.2.5".parse().unwrap())
        );
    }

    #[test]
    fn client_ip_accepts_forwarding_headers_from_trusted_peer() {
        let mut request = TestClient::get("http://127.0.0.1:5800/login")
            .add_header("x-forwarded-for", "203.0.113.10, 10.0.0.2", true)
            .build();
        *request.remote_addr_mut() = "10.0.0.2:41000"
            .parse::<std::net::SocketAddr>()
            .unwrap()
            .into();

        assert_eq!(
            resolve_client_ip(&request, &["10.0.0.0/8".parse::<IpNet>().unwrap()]),
            Some("203.0.113.10".parse().unwrap())
        );
    }

    const VALID_TRACEPARENT: &str = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01";

    #[derive(Clone, Debug, Default)]
    struct CapturingSpanExporter {
        spans: Arc<std::sync::Mutex<Vec<opentelemetry_sdk::trace::SpanData>>>,
    }

    impl opentelemetry_sdk::trace::SpanExporter for CapturingSpanExporter {
        async fn export(
            &self,
            batch: Vec<opentelemetry_sdk::trace::SpanData>,
        ) -> opentelemetry_sdk::error::OTelSdkResult {
            self.spans.lock().unwrap().extend(batch);
            Ok(())
        }
    }

    fn trace_policy(trusted_gateway: bool) -> TraceTrustPolicy {
        let config = identity_infrastructure::config::TraceContextConfig {
            trusted_gateways: if trusted_gateway {
                vec!["127.0.0.1/32".parse::<IpNet>().unwrap()]
            } else {
                Vec::new()
            },
            trust_verified_workload: false,
            propagate_to_origins: Vec::new(),
        };
        TraceTrustPolicy::new(config)
    }

    async fn send_with_trace_middleware(
        policy: TraceTrustPolicy,
        traceparent: Option<&str>,
    ) -> (
        Option<StatusCode>,
        Arc<std::sync::Mutex<Vec<opentelemetry_sdk::trace::SpanData>>>,
    ) {
        let exporter = CapturingSpanExporter::default();
        let spans = Arc::clone(&exporter.spans);
        let provider = opentelemetry_sdk::trace::SdkTracerProvider::builder()
            .with_simple_exporter(exporter)
            .build();
        let subscriber = tracing_subscriber::registry()
            .with(tracing_opentelemetry::layer().with_tracer(provider.tracer("middleware-test")));
        let _guard = tracing::subscriber::set_default(subscriber);

        let service = Service::new(
            Router::new()
                .hoop(TraceContextMiddleware::new(policy))
                .push(Router::with_path("authorize").get(ok)),
        );
        let builder = TestClient::get("http://127.0.0.1:5800/authorize");
        let mut request = match traceparent {
            Some(value) => builder.add_header("traceparent", value, true).build(),
            None => builder.build(),
        };
        *request.remote_addr_mut() = "127.0.0.1:41000"
            .parse::<std::net::SocketAddr>()
            .expect("valid test peer")
            .into();
        let response = service.handle(request).await;
        (response.status_code, spans)
    }

    #[tokio::test]
    async fn trusted_inbound_trace_becomes_the_local_parent() {
        let (status, spans) =
            send_with_trace_middleware(trace_policy(true), Some(VALID_TRACEPARENT)).await;
        assert_eq!(status, Some(StatusCode::OK));

        let spans = spans.lock().unwrap();
        let server = spans
            .iter()
            .find(|span| span.name == "http.server")
            .expect("server span exported");
        let inbound_trace =
            opentelemetry::trace::TraceId::from_hex("4bf92f3577b34da6a3ce929d0e0e4736").unwrap();
        let inbound_span = opentelemetry::trace::SpanId::from_hex("00f067aa0ba902b7").unwrap();
        assert_eq!(server.span_context.trace_id(), inbound_trace);
        assert_eq!(server.parent_span_id, inbound_span);
        assert_ne!(server.span_context.span_id(), inbound_span);
    }

    #[tokio::test]
    async fn untrusted_inbound_trace_is_linked_not_continued() {
        let (status, spans) =
            send_with_trace_middleware(trace_policy(false), Some(VALID_TRACEPARENT)).await;
        assert_eq!(status, Some(StatusCode::OK));

        let spans = spans.lock().unwrap();
        let server = spans
            .iter()
            .find(|span| span.name == "http.server")
            .expect("server span exported");
        let inbound_trace =
            opentelemetry::trace::TraceId::from_hex("4bf92f3577b34da6a3ce929d0e0e4736").unwrap();
        let inbound_span = opentelemetry::trace::SpanId::from_hex("00f067aa0ba902b7").unwrap();
        assert_ne!(server.span_context.trace_id(), inbound_trace);
        assert!(server.parent_span_id == opentelemetry::trace::SpanId::INVALID);
        assert!(
            server
                .links
                .iter()
                .any(|link| link.span_context.span_id() == inbound_span),
            "expected a link to the untrusted inbound span"
        );
    }

    #[tokio::test]
    async fn invalid_traceparent_never_fails_the_request() {
        let (status, spans) = send_with_trace_middleware(
            trace_policy(true),
            Some("00-00000000000000000000000000000000-00f067aa0ba902b7-01"),
        )
        .await;
        assert_eq!(status, Some(StatusCode::OK));

        let spans = spans.lock().unwrap();
        let server = spans
            .iter()
            .find(|span| span.name == "http.server")
            .expect("server span exported");
        assert!(server.links.is_empty());
    }

    #[tokio::test]
    async fn requests_without_trace_headers_still_start_a_trace() {
        let (status, spans) = send_with_trace_middleware(trace_policy(true), None).await;
        assert_eq!(status, Some(StatusCode::OK));

        let spans = spans.lock().unwrap();
        let server = spans
            .iter()
            .find(|span| span.name == "http.server")
            .expect("server span exported");
        assert!(server.span_context.is_valid());
        assert!(server.links.is_empty());
    }

    async fn send_from_peer(
        service: &Service,
        header: Option<(&'static str, &'static str)>,
        peer: &str,
    ) -> salvo::Response {
        let builder = TestClient::get("http://127.0.0.1:5800/login");
        let mut request = match header {
            Some((name, value)) => builder.add_header(name, value, true).build(),
            None => builder.build(),
        };
        *request.remote_addr_mut() = peer
            .parse::<std::net::SocketAddr>()
            .expect("valid test peer")
            .into();
        service.handle(request).await
    }
}
