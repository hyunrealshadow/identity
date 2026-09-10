//! Output port for business results, security audit facts and key events.
//!
//! Application use cases express what happened in domain terms and never touch
//! the observability pipeline directly. The infrastructure layer attaches an
//! implementation that renders PII markings, captures trace context and hands
//! records to a bounded, non-blocking exporter. Implementing this trait must
//! never block the caller and must never fail business operations.

use std::sync::{Arc, OnceLock};

/// Whether a record is a security audit fact or a business result.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EventCategory {
    Business,
    Audit,
}

/// Severity of an emitted event. Same values as diagnostic severity, applied at
/// the event boundary instead of the diagnostic filter.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EventSeverity {
    Info,
    Warn,
    Error,
}

/// Attribute value carried by an event.
#[derive(Clone, Debug, PartialEq)]
pub enum EventValue {
    Text(String),
    Integer(i64),
    Float(f64),
    Boolean(bool),
    /// PII that must render as `[REDACTED]` unless the deployment configured
    /// HMAC pseudonymization.
    Redacted(String),
    /// PII correlated by value across records. The purpose is a stable,
    /// low-cardinality field name.
    Pseudonymized {
        purpose: &'static str,
        value: String,
    },
    /// Credentials and other never-recordable values. Always `[REDACTED]`.
    Credential,
}

/// A key business result or security audit fact.
#[derive(Clone, Debug, PartialEq)]
pub struct BusinessEvent {
    pub name: &'static str,
    pub category: EventCategory,
    pub severity: EventSeverity,
    pub outcome: Option<&'static str>,
    pub reason: Option<&'static str>,
    pub attributes: Vec<(&'static str, EventValue)>,
}

impl BusinessEvent {
    #[must_use]
    pub fn business(name: &'static str) -> Self {
        Self {
            name,
            category: EventCategory::Business,
            severity: EventSeverity::Info,
            outcome: None,
            reason: None,
            attributes: Vec::new(),
        }
    }

    #[must_use]
    pub fn audit(name: &'static str) -> Self {
        Self {
            category: EventCategory::Audit,
            ..Self::business(name)
        }
    }

    #[must_use]
    pub fn severity(mut self, severity: EventSeverity) -> Self {
        self.severity = severity;
        self
    }

    #[must_use]
    pub fn outcome(mut self, outcome: &'static str) -> Self {
        self.outcome = Some(outcome);
        self
    }

    #[must_use]
    pub fn reason(mut self, reason: &'static str) -> Self {
        self.reason = Some(reason);
        self
    }

    #[must_use]
    pub fn attribute(mut self, key: &'static str, value: EventValue) -> Self {
        self.attributes.push((key, value));
        self
    }
}

/// Sink for key events and audit facts.
pub trait EventSink: Send + Sync + 'static {
    /// Enqueue an event. Implementations must not block waiting for export and
    /// must not return errors; dropped records are reflected in pipeline
    /// metrics instead.
    fn emit(&self, event: BusinessEvent);
}

/// Port for outbound dependency tracing and W3C propagation.
///
/// Application code creates the client span before awaiting an outbound call
/// and asks the port to inject trace context. The implementation decides
/// whether a target origin may receive internal context; arbitrary request
/// URIs, third-party JWKS endpoints and logout targets never inherit it by
/// default.
pub trait OutboundTrace: Send + Sync + 'static {
    /// Span describing one real outbound HTTP call. It records the method and
    /// target host, but not query strings or credentials.
    fn client_span(&self, method: &str, url: &url::Url) -> tracing::Span;

    /// Inject the active client trace context into outbound headers when the
    /// target origin is allowed. A no-op otherwise.
    fn inject(&self, url: &url::Url, headers: &mut http::HeaderMap);
}

/// Used when no outbound trace policy is installed. Spans are disabled and no
/// context is propagated.
#[derive(Clone, Copy, Debug, Default)]
pub struct NoopOutboundTrace;

impl OutboundTrace for NoopOutboundTrace {
    fn client_span(&self, _method: &str, _url: &url::Url) -> tracing::Span {
        tracing::Span::none()
    }

    fn inject(&self, _url: &url::Url, _headers: &mut http::HeaderMap) {}
}

/// Sink used when observability is disabled, in tests and in composition
/// roots that do not wire the pipeline.
#[derive(Clone, Copy, Debug, Default)]
pub struct NoopEventSink;

impl EventSink for NoopEventSink {
    fn emit(&self, _event: BusinessEvent) {}
}

/// Bounded outcome/reason categories for a failed use case. The numeric error
/// code carries the specific cause; free-form error text never becomes a
/// metric label or event name.
#[must_use]
pub fn error_outcome(error: &crate::error::AppError) -> (&'static str, &'static str) {
    match error.kind() {
        crate::error::kind::ErrorKind::Internal => ("failure", "system_error"),
        crate::error::kind::ErrorKind::Unauthorized => ("rejected", "unauthorized"),
        crate::error::kind::ErrorKind::Forbidden => ("rejected", "forbidden"),
        crate::error::kind::ErrorKind::Conflict => ("rejected", "conflict"),
        crate::error::kind::ErrorKind::Gone => ("rejected", "expired"),
        crate::error::kind::ErrorKind::Validation => ("rejected", "invalid_request"),
        crate::error::kind::ErrorKind::NotFound => ("rejected", "not_found"),
        crate::error::kind::ErrorKind::RateLimit => ("rejected", "rate_limited"),
    }
}

static OUTBOUND_TRACE: OnceLock<Arc<dyn OutboundTrace>> = OnceLock::new();

/// Install the process-wide outbound trace policy. Called by the composition
/// root after configuration is loaded.
pub fn install_outbound_trace(trace: Arc<dyn OutboundTrace>) {
    let _ = OUTBOUND_TRACE.set(trace);
}

/// Outbound trace policy for dependency calls, or a no-op before startup.
#[must_use]
pub fn outbound_trace() -> Arc<dyn OutboundTrace> {
    OUTBOUND_TRACE
        .get()
        .cloned()
        .unwrap_or_else(|| Arc::new(NoopOutboundTrace))
}

static EVENT_SINK: OnceLock<Arc<dyn EventSink>> = OnceLock::new();

/// Install the process-wide key event sink. Called by the composition root
/// once the observability pipeline is available.
pub fn install_event_sink(sink: Arc<dyn EventSink>) {
    let _ = EVENT_SINK.set(sink);
}

/// Process-wide key event sink, or a no-op before startup. Infrastructure
/// helpers that cannot receive the sink through their constructor (settings
/// cache, background tasks) use this accessor.
#[must_use]
pub fn event_sink() -> Arc<dyn EventSink> {
    EVENT_SINK
        .get()
        .cloned()
        .unwrap_or_else(|| Arc::new(NoopEventSink))
}
