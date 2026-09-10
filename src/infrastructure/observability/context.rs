//! W3C Trace Context handling: extraction, trust and injection.
//!
//! Inbound `traceparent` is parsed strictly. Whether the inbound context may
//! become the local parent is a separate trust decision configured under
//! `observability.trace_context`; trace trust never reuses proxy/IP or TLS
//! settings. Untrusted but valid contexts become span links, invalid contexts
//! are ignored (and their `tracestate` is dropped).

use std::net::IpAddr;

use http::HeaderMap;
use opentelemetry::{
    Context, global,
    propagation::Injector,
    trace::{SpanContext, SpanId, TraceContextExt, TraceFlags, TraceId, TraceState},
};
use tracing_opentelemetry::OpenTelemetrySpanExt;
use url::Url;

use crate::config::TraceContextConfig;

pub const TRACEPARENT: &str = "traceparent";
pub const TRACESTATE: &str = "tracestate";

/// Parsed, validated `traceparent` version 00/0x.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TraceParent {
    pub trace_id: TraceId,
    pub span_id: SpanId,
    pub sampled: bool,
}

/// Result of reading W3C headers off a request.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ExtractedTrace {
    pub traceparent: Option<TraceParent>,
    pub tracestate: Option<TraceState>,
}

impl ExtractedTrace {
    /// Whether the inbound request carried a syntactically valid traceparent.
    #[must_use]
    pub fn is_valid(&self) -> bool {
        self.traceparent.is_some()
    }
}

/// How the local server span relates to the inbound context.
#[derive(Debug)]
pub enum ParentDecision {
    /// Trusted inbound context becomes the local parent.
    ContinueInbound(Context),
    /// Valid but untrusted context is linked; a new trace starts locally.
    NewTraceWithLink(SpanContext),
    /// No usable inbound context.
    NewTrace,
}

/// Extract and validate W3C headers. An invalid `traceparent` also drops the
/// `tracestate`, per the specification.
#[must_use]
pub fn extract(headers: &HeaderMap) -> ExtractedTrace {
    let traceparent = headers
        .get(TRACEPARENT)
        .and_then(|value| value.to_str().ok())
        .and_then(parse_traceparent);

    let traceparent = match traceparent {
        Some(traceparent) => traceparent,
        None => return ExtractedTrace::default(),
    };

    let tracestate = headers
        .get(TRACESTATE)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<TraceState>().ok());

    ExtractedTrace {
        traceparent: Some(traceparent),
        tracestate,
    }
}

/// Strict parse of a W3C `traceparent` header value.
#[must_use]
pub fn parse_traceparent(value: &str) -> Option<TraceParent> {
    let mut parts = value.split('-');
    let version = parts.next()?;
    let trace_id = parts.next()?;
    let span_id = parts.next()?;
    let flags = parts.next()?;

    if version.len() != 2 || !is_lower_hex(version) || version == "ff" {
        return None;
    }
    // Version 00 has exactly four fields; future versions may append fields.
    if version == "00" && parts.next().is_some() {
        return None;
    }
    if !parts.all(|field| !field.is_empty()) {
        return None;
    }
    if trace_id.len() != 32 || !is_lower_hex(trace_id) || trace_id.chars().all(|c| c == '0') {
        return None;
    }
    if span_id.len() != 16 || !is_lower_hex(span_id) || span_id.chars().all(|c| c == '0') {
        return None;
    }
    if flags.len() != 2 || !is_lower_hex(flags) {
        return None;
    }

    Some(TraceParent {
        trace_id: TraceId::from_hex(trace_id).ok()?,
        span_id: SpanId::from_hex(span_id).ok()?,
        sampled: flags.as_bytes()[1] & 0x01 == 0x01,
    })
}

/// Render a `traceparent` header value.
#[must_use]
pub fn format_traceparent(trace_id: TraceId, span_id: SpanId, sampled: bool) -> String {
    let flags = if sampled { 0x01 } else { 0x00 };
    format!("00-{trace_id}-{span_id}-{flags:02x}")
}

fn is_lower_hex(value: &str) -> bool {
    value
        .bytes()
        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

impl ExtractedTrace {
    /// Decide the parent for the local server span.
    #[must_use]
    pub fn parent_decision(&self, trusted: bool) -> ParentDecision {
        let Some(traceparent) = self.traceparent else {
            return ParentDecision::NewTrace;
        };

        let span_context = SpanContext::new(
            traceparent.trace_id,
            traceparent.span_id,
            if traceparent.sampled {
                TraceFlags::SAMPLED
            } else {
                TraceFlags::default()
            },
            true,
            self.tracestate.clone().unwrap_or_default(),
        );

        if trusted {
            ParentDecision::ContinueInbound(Context::new().with_remote_span_context(span_context))
        } else {
            ParentDecision::NewTraceWithLink(span_context)
        }
    }

    /// Remote span context of a valid inbound trace, used for link creation.
    #[must_use]
    pub fn remote_span_context(&self) -> Option<SpanContext> {
        self.traceparent.map(|traceparent| {
            SpanContext::new(
                traceparent.trace_id,
                traceparent.span_id,
                if traceparent.sampled {
                    TraceFlags::SAMPLED
                } else {
                    TraceFlags::default()
                },
                true,
                self.tracestate.clone().unwrap_or_default(),
            )
        })
    }
}

/// Trace trust and outbound propagation policy.
#[derive(Clone, Debug)]
pub struct TraceTrustPolicy {
    config: TraceContextConfig,
}

impl TraceTrustPolicy {
    #[must_use]
    pub fn new(config: TraceContextConfig) -> Self {
        Self { config }
    }

    /// Whether an inbound context may be continued.
    ///
    /// `verified_workload` is true only when the request already passed a
    /// verifiable service identity check (e.g. the internal API workload
    /// authenticator). Being on an internal address or using a backchannel is
    /// not by itself trust.
    #[must_use]
    pub fn trusts_inbound(&self, peer: Option<IpAddr>, verified_workload: bool) -> bool {
        if verified_workload && self.config.trust_verified_workload {
            return true;
        }
        peer.is_some_and(|peer| {
            self.config
                .trusted_gateways
                .iter()
                .any(|network| network.contains(&peer))
        })
    }

    /// Whether internal trace context may be injected for an outbound target.
    #[must_use]
    pub fn allows_outbound(&self, url: &Url) -> bool {
        let origin = url.origin().ascii_serialization();
        self.config
            .propagate_to_origins
            .iter()
            .any(|allowed| allowed == &origin)
    }
}

struct HeaderInjector<'a>(&'a mut HeaderMap);

impl Injector for HeaderInjector<'_> {
    fn set(&mut self, key: &str, value: String) {
        if let Ok(name) = http::header::HeaderName::from_bytes(key.as_bytes())
            && let Ok(value) = http::header::HeaderValue::from_str(&value)
        {
            self.0.insert(name, value);
        }
    }
}

/// Inject an explicit span context using the global propagator.
pub fn inject_span_context(span_context: &SpanContext, headers: &mut HeaderMap) {
    let context = Context::new().with_remote_span_context(span_context.clone());
    inject_context(&context, headers);
}

/// Inject an OTel context using the global W3C propagator.
pub fn inject_context(context: &Context, headers: &mut HeaderMap) {
    global::get_text_map_propagator(|propagator| {
        propagator.inject_context(context, &mut HeaderInjector(headers));
    });
}

/// Inject the currently active span (if any) into outbound headers.
pub fn inject_current_span(headers: &mut HeaderMap) {
    let context = tracing::Span::current().context();
    if context.has_active_span() {
        inject_context(&context, headers);
    }
}

/// Trace context of the currently active span, for event correlation.
#[must_use]
pub fn current_span_context() -> Option<SpanContext> {
    let context = tracing::Span::current().context();
    context
        .has_active_span()
        .then(|| context.span().span_context().clone())
}

#[cfg(test)]
mod tests {
    use std::net::IpAddr;

    use http::HeaderMap;
    use ipnet::IpNet;
    use opentelemetry::trace::{SpanId, TraceId};

    use super::{ParentDecision, TraceTrustPolicy, extract, format_traceparent, parse_traceparent};
    use crate::config::TraceContextConfig;

    const VALID: &str = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01";

    #[test]
    fn parses_and_formats_valid_traceparent() {
        let parsed = parse_traceparent(VALID).unwrap();
        assert!(parsed.sampled);
        assert_eq!(
            parsed.trace_id,
            TraceId::from_hex("4bf92f3577b34da6a3ce929d0e0e4736").unwrap()
        );
        assert_eq!(
            parsed.span_id,
            SpanId::from_hex("00f067aa0ba902b7").unwrap()
        );
        assert_eq!(
            format_traceparent(parsed.trace_id, parsed.span_id, parsed.sampled),
            VALID
        );
    }

    #[test]
    fn rejects_malformed_traceparents() {
        for value in [
            "",
            "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7",
            "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01-extra",
            "00-00000000000000000000000000000000-00f067aa0ba902b7-01",
            "00-4bf92f3577b34da6a3ce929d0e0e4736-0000000000000000-01",
            "00-4BF92F3577B34DA6A3CE929D0E0E4736-00f067aa0ba902b7-01",
            "ff-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01",
            "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-zz",
        ] {
            assert!(parse_traceparent(value).is_none(), "accepted {value:?}");
        }
    }

    #[test]
    fn accepts_future_version_with_extra_fields() {
        let value = "01-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01-extra-field";
        assert!(parse_traceparent(value).is_some());
    }

    #[test]
    fn invalid_traceparent_drops_tracestate() {
        let mut headers = HeaderMap::new();
        headers.insert("traceparent", "not-a-traceparent".parse().unwrap());
        headers.insert("tracestate", "vendor=value".parse().unwrap());

        let extracted = extract(&headers);
        assert!(!extracted.is_valid());
        assert!(extracted.tracestate.is_none());
    }

    #[test]
    fn trust_policy_defaults_to_no_network_trust() {
        let policy = TraceTrustPolicy::new(TraceContextConfig::default());
        assert!(!policy.trusts_inbound(Some("10.0.0.1".parse().unwrap()), false));
        // Verified workload identity is independent from network position.
        assert!(policy.trusts_inbound(None, true));

        let mut headers = HeaderMap::new();
        headers.insert("traceparent", VALID.parse().unwrap());
        let extracted = extract(&headers);
        assert!(matches!(
            extracted.parent_decision(false),
            ParentDecision::NewTraceWithLink(_)
        ));
        assert!(matches!(
            extracted.parent_decision(true),
            ParentDecision::ContinueInbound(_)
        ));
    }

    #[test]
    fn gateway_trust_can_be_configured_per_network() {
        let config = TraceContextConfig {
            trusted_gateways: vec!["10.0.0.0/8".parse::<IpNet>().unwrap()],
            trust_verified_workload: false,
            propagate_to_origins: Vec::new(),
        };
        let policy = TraceTrustPolicy::new(config);
        assert!(policy.trusts_inbound(Some("10.1.2.3".parse::<IpAddr>().unwrap()), false));
        assert!(!policy.trusts_inbound(Some("192.168.1.1".parse::<IpAddr>().unwrap()), false));
        // Network trust is independent from the workload identity flag: a
        // trusted gateway stays trusted, and an untrusted peer stays untrusted.
        assert!(policy.trusts_inbound(Some("10.1.2.3".parse::<IpAddr>().unwrap()), true));
        assert!(!policy.trusts_inbound(Some("192.168.1.1".parse::<IpAddr>().unwrap()), true));
    }

    #[test]
    fn outbound_propagation_is_origin_scoped() {
        let config = TraceContextConfig {
            trusted_gateways: Vec::new(),
            trust_verified_workload: true,
            propagate_to_origins: vec!["https://login.internal:8443".to_owned()],
        };
        let policy = TraceTrustPolicy::new(config);

        assert!(policy.allows_outbound(&"https://login.internal:8443/callback".parse().unwrap()));
        assert!(!policy.allows_outbound(&"https://evil.example/callback".parse().unwrap()));
        assert!(!policy.allows_outbound(&"https://login.internal/callback".parse().unwrap()));
    }
}
