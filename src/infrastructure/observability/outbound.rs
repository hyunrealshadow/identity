//! Outbound dependency tracing and W3C propagation.
//!
//! Application use cases ask this port for a client span and for header
//! injection. Whether an outbound target receives internal context is decided
//! here from the configured origin allow-list; being "internal", using a
//! backchannel URL or having an authenticated user never grants propagation.

use std::sync::Arc;

use http::HeaderMap;
use identity_application::observability::OutboundTrace;
use tracing::{Span, field::Empty, info_span};
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
        info_span!(
            "http.client",
            otel.kind = "client",
            http.request.method = %method,
            server.address = %host,
            url.scheme = %url.scheme(),
            http.response.status_code = Empty,
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
    use super::OutboundTraceImpl;
    use crate::{
        config::TraceContextConfig,
        observability::context::{TraceTrustPolicy, format_traceparent},
    };
    use http::HeaderMap;
    use identity_application::observability::OutboundTrace;
    use opentelemetry::{
        global,
        trace::{TraceContextExt, TracerProvider},
    };
    use opentelemetry_sdk::{
        error::OTelSdkResult,
        propagation::TraceContextPropagator,
        trace::{SdkTracerProvider, SpanData, SpanExporter},
    };
    use std::{
        collections::BTreeMap,
        sync::{Arc, Mutex},
    };
    use tracing::subscriber;
    use tracing_opentelemetry::OpenTelemetrySpanExt;
    use tracing_subscriber::prelude::*;

    #[derive(Debug, Clone, Default)]
    struct Exporter(Arc<Mutex<Vec<SpanData>>>);
    impl SpanExporter for Exporter {
        async fn export(&self, batch: Vec<SpanData>) -> OTelSdkResult {
            self.0.lock().unwrap().extend(batch);
            Ok(())
        }
    }
    fn policy(origins: Vec<String>) -> Arc<dyn OutboundTrace> {
        OutboundTraceImpl::shared(TraceTrustPolicy::new(TraceContextConfig {
            trusted_gateways: Vec::new(),
            trusted_request_id_gateways: Vec::new(),
            trust_verified_workload: true,
            propagate_to_origins: origins,
        }))
    }
    #[test]
    fn client_span_records_host_but_not_query() {
        let exporter = Exporter::default();
        let provider = SdkTracerProvider::builder()
            .with_simple_exporter(exporter.clone())
            .build();
        let subscriber = tracing_subscriber::registry()
            .with(tracing_opentelemetry::layer().with_tracer(provider.tracer("outbound-test")));
        subscriber::with_default(subscriber, || {
            let span = policy(Vec::new()).client_span(
                "POST",
                &"https://rp.example.com/logout?token=secret"
                    .parse()
                    .unwrap(),
            );
            let _entered = span.enter();
        });
        provider.force_flush().unwrap();
        let spans = exporter.0.lock().unwrap();
        assert_eq!(
            spans.len(),
            1,
            "tracing must actually export the client span"
        );
        assert_eq!(spans[0].name, "http.client");
        let attributes: BTreeMap<_, _> = spans[0]
            .attributes
            .iter()
            .map(|a| (a.key.as_str(), a.value.to_string()))
            .collect();
        assert_eq!(
            attributes.get("server.address").map(String::as_str),
            Some("rp.example.com")
        );
        assert_eq!(
            attributes.get("http.request.method").map(String::as_str),
            Some("POST")
        );
        assert_eq!(
            attributes.get("url.scheme").map(String::as_str),
            Some("https")
        );
        let exported = format!("{:?}", spans[0]);
        for sensitive in ["token=", "secret", "/logout", "url.full", "url.query"] {
            assert!(
                !exported.contains(sensitive),
                "sensitive URL detail leaked: {exported}"
            );
        }
    }
    #[test]
    fn injection_is_origin_scoped() {
        // Match normal observability bootstrap: a tracer alone does not install W3C propagation.
        global::set_text_map_propagator(TraceContextPropagator::new());
        let provider = SdkTracerProvider::builder()
            .with_simple_exporter(Exporter::default())
            .build();
        let subscriber = tracing_subscriber::registry()
            .with(tracing_opentelemetry::layer().with_tracer(provider.tracer("outbound-test")));
        let trace = policy(vec!["https://login.internal:8443".to_owned()]);
        subscriber::with_default(subscriber, || {
            let span = tracing::info_span!("request");
            let _entered = span.enter();
            let context = span.context();
            let active = context.span();
            let sc = active.span_context();
            assert!(sc.is_valid());
            let expected = format_traceparent(sc.trace_id(), sc.span_id(), sc.is_sampled());
            let mut allowed = HeaderMap::new();
            trace.inject(
                &"https://login.internal:8443/callback".parse().unwrap(),
                &mut allowed,
            );
            assert_eq!(
                allowed.get("traceparent").unwrap().to_str().unwrap(),
                expected
            );
            for target in [
                "https://evil.example/callback",
                "https://login.internal/callback",
                "http://login.internal:8443/callback",
            ] {
                let mut denied = HeaderMap::new();
                trace.inject(&target.parse().unwrap(), &mut denied);
                assert!(!denied.contains_key("traceparent"), "{target}");
            }
        });
        let mut inactive = HeaderMap::new();
        trace.inject(
            &"https://login.internal:8443/callback".parse().unwrap(),
            &mut inactive,
        );
        assert!(!inactive.contains_key("traceparent"));
    }
}
