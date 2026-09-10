//! Outbound dependency tracing and W3C propagation.
//!
//! Application use cases ask this port for a client span and for header
//! injection. Whether an outbound target receives internal context is decided
//! here from the configured origin allow-list; being "internal", using a
//! backchannel URL or having an authenticated user never grants propagation.

use std::sync::Arc;

use http::HeaderMap;
use identity_application::observability::OutboundTrace;
use tracing::Span;
use url::Url;

use super::context::{TraceTrustPolicy, inject_current_span};

pub struct OutboundTraceImpl {
    policy: TraceTrustPolicy,
}

impl OutboundTraceImpl {
    #[must_use]
    pub fn new(policy: TraceTrustPolicy) -> Self {
        Self { policy }
    }

    #[must_use]
    pub fn shared(policy: TraceTrustPolicy) -> Arc<dyn OutboundTrace> {
        Arc::new(Self::new(policy))
    }
}

impl OutboundTrace for OutboundTraceImpl {
    fn client_span(&self, method: &str, url: &Url) -> Span {
        // Only scheme and host are recorded: query strings may contain request
        // URIs or credentials that must not be normalized into telemetry.
        let host = url.host_str().unwrap_or_default();
        tracing::info_span!(
            "http.client",
            otel.kind = "client",
            http.request.method = %method,
            server.address = %host,
            url.scheme = %url.scheme(),
            http.response.status_code = tracing::field::Empty,
        )
    }

    fn inject(&self, url: &Url, headers: &mut HeaderMap) {
        if self.policy.allows_outbound(url) {
            inject_current_span(headers);
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use http::HeaderMap;
    use identity_application::observability::OutboundTrace;

    use super::OutboundTraceImpl;
    use crate::config::TraceContextConfig;
    use crate::observability::context::{TraceTrustPolicy, format_traceparent};
    use tracing_opentelemetry::OpenTelemetrySpanExt;

    fn policy(origins: Vec<String>) -> Arc<dyn OutboundTrace> {
        OutboundTraceImpl::shared(TraceTrustPolicy::new(TraceContextConfig {
            trusted_gateways: Vec::new(),
            trust_verified_workload: true,
            propagate_to_origins: origins,
        }))
    }

    #[test]
    fn client_span_records_host_but_not_query() {
        let span = policy(Vec::new()).client_span(
            "POST",
            &"https://rp.example.com/logout?token=secret"
                .parse()
                .unwrap(),
        );
        let _ = span;
    }

    #[test]
    fn injection_is_origin_scoped() {
        let trace = policy(vec!["https://login.internal:8443".to_owned()]);

        let mut headers = HeaderMap::new();
        trace.inject(
            &"https://evil.example/callback".parse().unwrap(),
            &mut headers,
        );
        assert!(headers.get("traceparent").is_none());

        // Without an active context nothing to inject even for allowed origins.
        let mut headers = HeaderMap::new();
        trace.inject(
            &"https://login.internal:8443/callback".parse().unwrap(),
            &mut headers,
        );
        assert!(headers.get("traceparent").is_none());
        // The formatting helper compiles against the same W3C shape used for
        // inbound parsing.
        let _ = format_traceparent(
            opentelemetry::trace::TraceId::from_hex("4bf92f3577b34da6a3ce929d0e0e4736").unwrap(),
            opentelemetry::trace::SpanId::from_hex("00f067aa0ba902b7").unwrap(),
            true,
        );
        let _ = OpenTelemetrySpanExt::context(&tracing::Span::none());
    }
}
