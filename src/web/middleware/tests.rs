use std::{
    net::SocketAddr,
    sync::{Arc, Mutex},
};

use async_trait::async_trait;
use http::{StatusCode, header};
use identity_domain::openid_connect::{
    AuthenticatedWorkload, BuiltInWorkload, WorkloadAuthenticator,
};
use identity_infrastructure::{
    config::TraceContextConfig,
    observability::{context, context::TraceTrustPolicy},
};
use ipnet::IpNet;
use opentelemetry::trace::{SpanId, TraceId, TracerProvider};
use opentelemetry_sdk::{
    error::OTelSdkResult,
    trace::{SdkTracerProvider, SpanData, SpanExporter},
};
use salvo::{
    Response, Router, Service, handler,
    prelude::Json,
    test::{ResponseExt, TestClient},
};
use tracing::subscriber::{NoSubscriber, set_default};
use tracing_opentelemetry::layer;
use tracing_subscriber::{layer::SubscriberExt, registry};
use uuid::Uuid;

use super::{
    RequireUpstreamHttps, RequireWorkload, TraceContextMiddleware, is_content_hashed,
    resolve_client_ip, security_headers_middleware,
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

#[test]
fn only_build_fingerprints_count_as_content_hashed() {
    for hashed in [
        "/static/css/error.fbf6de46402edd3c.css",
        "/static/fonts/inter-latin-wght-normal.3100e775e8616cd2.woff2",
    ] {
        assert!(is_content_hashed(hashed), "{hashed}");
    }
    for plain in [
        "/static/css/error.css",
        "/static/manifest.json",
        "/static/css/.fbf6de46402edd3c.css",
        "/static/css/error.FBF6DE46402EDD3C.css",
        "/static/css/error.fbf6de46402edd3.css",
        "/static/fbf6de46402edd3c.css",
    ] {
        assert!(!is_content_hashed(plain), "{plain}");
    }
}

#[tokio::test]
async fn security_headers_skip_x_frame_options_for_check_session_iframe() {
    let service = Service::new(
        Router::new()
            .hoop(security_headers_middleware)
            .push(Router::with_path("openid/check_session").get(ok)),
    );

    let response = TestClient::get("http://127.0.0.1:5800/openid/check_session")
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
    *request.remote_addr_mut() = "192.0.2.5:41000".parse::<SocketAddr>().unwrap().into();

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
    *request.remote_addr_mut() = "10.0.0.2:41000".parse::<SocketAddr>().unwrap().into();

    assert_eq!(
        resolve_client_ip(&request, &["10.0.0.0/8".parse::<IpNet>().unwrap()]),
        Some("203.0.113.10".parse().unwrap())
    );
}

const VALID_TRACEPARENT: &str = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01";

#[handler]
async fn correlation_echo(depot: &mut salvo::Depot, res: &mut Response) {
    let correlation = depot.get_typed::<super::RequestCorrelation>().unwrap();
    let current = context::current_request_correlation().unwrap();
    assert_eq!(current.request_id, correlation.request_id);
    res.render(Json(
        serde_json::json!({"requestId": correlation.request_id}),
    ));
}

#[tokio::test]
async fn request_id_is_available_without_tracing_and_only_explicit_gateways_can_supply_it() {
    use tracing::instrument::WithSubscriber;
    for (trust_id, incoming, accepted) in [
        (false, "external-id", false),
        (true, "gateway.valid_1", true),
        (true, "bad value", false),
        (
            true,
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            false,
        ),
    ] {
        let policy = TraceTrustPolicy::new(TraceContextConfig {
            trusted_request_id_gateways: if trust_id {
                vec!["127.0.0.1/32".parse().unwrap()]
            } else {
                vec![]
            },
            ..Default::default()
        });
        let service = Service::new(
            Router::new()
                .hoop(TraceContextMiddleware::new(policy))
                .get(correlation_echo),
        );
        let mut request = TestClient::get("http://127.0.0.1:5800/")
            .add_header("x-request-id", incoming, true)
            .build();
        *request.remote_addr_mut() = "127.0.0.1:41000".parse::<SocketAddr>().unwrap().into();
        let mut response = service
            .handle(request)
            .with_subscriber(NoSubscriber::default())
            .await;
        let id = response
            .headers()
            .get("x-request-id")
            .unwrap()
            .to_str()
            .unwrap()
            .to_owned();
        assert_eq!(id == incoming, accepted);
        if !accepted {
            assert!(Uuid::parse_str(&id).is_ok());
        }
        assert!(response.headers().get("x-trace-id").is_none());
        let body: serde_json::Value =
            serde_json::from_str(&response.take_string().await.unwrap()).unwrap();
        assert_eq!(body["requestId"], id);
    }
}

#[derive(Clone, Debug, Default)]
struct CapturingSpanExporter {
    spans: Arc<Mutex<Vec<SpanData>>>,
}

impl SpanExporter for CapturingSpanExporter {
    async fn export(&self, batch: Vec<SpanData>) -> OTelSdkResult {
        self.spans.lock().unwrap().extend(batch);
        Ok(())
    }
}

fn trace_policy(trusted_gateway: bool) -> TraceTrustPolicy {
    let config = TraceContextConfig {
        trusted_gateways: if trusted_gateway {
            vec!["127.0.0.1/32".parse::<IpNet>().unwrap()]
        } else {
            Vec::new()
        },
        trust_verified_workload: false,
        propagate_to_origins: Vec::new(),
        trusted_request_id_gateways: Vec::new(),
    };
    TraceTrustPolicy::new(config)
}

async fn send_with_trace_middleware(
    policy: TraceTrustPolicy,
    traceparent: Option<&str>,
) -> (Option<StatusCode>, Arc<Mutex<Vec<SpanData>>>) {
    let exporter = CapturingSpanExporter::default();
    let spans = Arc::clone(&exporter.spans);
    let provider = SdkTracerProvider::builder()
        .with_simple_exporter(exporter)
        .build();
    let subscriber = registry().with(layer().with_tracer(provider.tracer("middleware-test")));
    let _guard = set_default(subscriber);

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
        .parse::<SocketAddr>()
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
    let inbound_trace = TraceId::from_hex("4bf92f3577b34da6a3ce929d0e0e4736").unwrap();
    let inbound_span = SpanId::from_hex("00f067aa0ba902b7").unwrap();
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
    let inbound_trace = TraceId::from_hex("4bf92f3577b34da6a3ce929d0e0e4736").unwrap();
    let inbound_span = SpanId::from_hex("00f067aa0ba902b7").unwrap();
    assert_ne!(server.span_context.trace_id(), inbound_trace);
    assert!(server.parent_span_id == SpanId::INVALID);
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
) -> Response {
    let builder = TestClient::get("http://127.0.0.1:5800/login");
    let mut request = match header {
        Some((name, value)) => builder.add_header(name, value, true).build(),
        None => builder.build(),
    };
    *request.remote_addr_mut() = peer.parse::<SocketAddr>().expect("valid test peer").into();
    service.handle(request).await
}
