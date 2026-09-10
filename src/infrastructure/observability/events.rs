//! Non-blocking pipeline for key business results and security audit facts.
//!
//! Records are rendered (including PII policy) and enqueued with `try_send`
//! into a bounded channel. A dedicated worker turns them into OTel log records
//! for the events provider. The queue never blocks a request: when it is full
//! the record is dropped and reflected in [`super::metrics`].

use std::{
    sync::{
        Arc, OnceLock,
        atomic::{AtomicBool, Ordering},
        mpsc::{SyncSender, TrySendError, sync_channel},
    },
    thread,
    time::{Duration, SystemTime},
};

use identity_application::observability::{
    BusinessEvent, EventCategory, EventSeverity, EventSink, EventValue,
};
use opentelemetry::{
    logs::{AnyValue, LogRecord, Logger, LoggerProvider, Severity},
    trace::{SpanId, TraceContextExt, TraceFlags, TraceId},
};
use opentelemetry_sdk::logs::SdkLoggerProvider;

use super::{
    metrics::global as metrics,
    pii::{Pii, REDACTED},
};
use crate::config::EventsPipelineConfig;

const INSTRUMENTATION_SCOPE: &str = "identity.events";
const DROP_WORKER_DELAY: Duration = Duration::from_millis(200);

/// Process-wide event sink.
static PIPELINE: OnceLock<EventPipeline> = OnceLock::new();

/// Install the process-wide event pipeline. Later calls are ignored.
pub(crate) fn install(config: &EventsPipelineConfig, provider: &SdkLoggerProvider) {
    let pipeline = EventPipeline::start(config, provider.logger(INSTRUMENTATION_SCOPE));
    let _ = PIPELINE.set(pipeline);
}

/// Global sink for application use cases. Falls back to a drop-counting no-op
/// before initialization and in tests.
#[must_use]
pub fn sink() -> Arc<dyn EventSink> {
    match PIPELINE.get() {
        Some(pipeline) => Arc::new(pipeline.clone()),
        None => Arc::new(UninitializedSink),
    }
}

/// Stop accepting new events and close the queue. The worker drains what is
/// already queued; the caller bounds export time via provider shutdown.
pub(crate) fn close() {
    if let Some(pipeline) = PIPELINE.get() {
        pipeline.close();
    }
}

#[derive(Clone)]
struct EventPipeline {
    tx: SyncSender<RenderedEvent>,
    closed: Arc<AtomicBool>,
    drop_notice: Arc<AtomicBool>,
}

impl EventPipeline {
    fn start(config: &EventsPipelineConfig, logger: impl Logger + Send + 'static) -> Self {
        metrics().configure_events_queue(config.queue_capacity, config.queue_bytes);

        let (tx, rx) = sync_channel::<RenderedEvent>(config.queue_capacity);
        let closed = Arc::new(AtomicBool::new(false));
        let drop_notice = Arc::new(AtomicBool::new(false));
        let worker_closed = Arc::clone(&closed);

        thread::Builder::new()
            .name("identity.observability.events".to_owned())
            .spawn(move || {
                loop {
                    match rx.recv_timeout(DROP_WORKER_DELAY) {
                        Ok(event) => {
                            metrics().events_dequeued(event.bytes);
                            let category = match event.category {
                                EventCategory::Audit => "audit",
                                EventCategory::Business => "business",
                            };
                            emit_record(&logger, event);
                            metrics().events_emitted(category);
                            if worker_closed.load(Ordering::Acquire) && queue_is_empty() {
                                break;
                            }
                        }
                        Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
                            if worker_closed.load(Ordering::Acquire) && queue_is_empty() {
                                break;
                            }
                        }
                        Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => break,
                    }
                }
            })
            .expect("event pipeline worker thread must start");

        Self {
            tx,
            closed,
            drop_notice,
        }
    }

    fn close(&self) {
        self.closed.store(true, Ordering::Release);
    }
    fn notify_drop(&self, reason: &'static str) {
        metrics().events_dropped(reason);
        // One diagnostic notice per process makes the audit gap traceable
        // without flooding the diagnostic pipeline once the queue stays full.
        if !self.drop_notice.swap(true, Ordering::AcqRel) {
            tracing::warn!(
                target: "identity.observability",
                reason,
                "key event dropped: event queue exceeded its configured bound"
            );
        }
    }
}

impl EventSink for EventPipeline {
    fn emit(&self, event: BusinessEvent) {
        if self.closed.load(Ordering::Acquire) {
            self.notify_drop("not_initialized");
            return;
        }

        let rendered = render(event);
        let bytes = rendered.bytes;
        if bytes > 0 {
            let queued_bytes = metrics().queued_event_bytes();
            let limit = metrics().event_queue_byte_limit();
            if queued_bytes.saturating_add(bytes) > limit {
                self.notify_drop("byte_limit");
                return;
            }
        }

        match self.tx.try_send(rendered) {
            Ok(()) => metrics().events_enqueued(bytes),
            Err(TrySendError::Full(_)) => self.notify_drop("queue_full"),
            Err(TrySendError::Disconnected(_)) => self.notify_drop("not_initialized"),
        }
    }
}

#[derive(Clone, Copy)]
struct UninitializedSink;

impl EventSink for UninitializedSink {
    fn emit(&self, _event: BusinessEvent) {
        metrics().events_dropped("not_initialized");
    }
}

fn queue_is_empty() -> bool {
    metrics().event_queue_depth() == 0
}

struct RenderedEvent {
    name: &'static str,
    category: EventCategory,
    severity: EventSeverity,
    outcome: Option<&'static str>,
    reason: Option<&'static str>,
    attributes: Vec<(&'static str, RenderedValue)>,
    trace: Option<(TraceId, SpanId, TraceFlags)>,
    bytes: usize,
}

enum RenderedValue {
    Text(String),
    Integer(i64),
    Float(f64),
    Boolean(bool),
}

fn render(event: BusinessEvent) -> RenderedEvent {
    let mut bytes = event.name.len() + 32;
    if let Some(outcome) = event.outcome {
        bytes += outcome.len() + 8;
    }
    if let Some(reason) = event.reason {
        bytes += reason.len() + 8;
    }

    let attributes = event
        .attributes
        .into_iter()
        .map(|(key, value)| {
            let rendered = match value {
                EventValue::Text(value) => RenderedValue::Text(value),
                EventValue::Integer(value) => RenderedValue::Integer(value),
                EventValue::Float(value) => RenderedValue::Float(value),
                EventValue::Boolean(value) => RenderedValue::Boolean(value),
                EventValue::Redacted(value) => {
                    RenderedValue::Text(Pii::redacted(value).to_string())
                }
                EventValue::Pseudonymized { purpose, value } => {
                    RenderedValue::Text(Pii::pseudonymized(purpose, value).to_string())
                }
                EventValue::Credential => RenderedValue::Text(REDACTED.to_owned()),
            };
            bytes += key.len() + rendered.byte_size() + 16;
            (key, rendered)
        })
        .collect();

    RenderedEvent {
        name: event.name,
        category: event.category,
        severity: event.severity,
        outcome: event.outcome,
        reason: event.reason,
        attributes,
        trace: current_trace_context(),
        bytes,
    }
}

fn current_trace_context() -> Option<(TraceId, SpanId, TraceFlags)> {
    opentelemetry::Context::map_current(|context| {
        let span = context.span();
        let span_context = span.span_context();
        span_context.is_valid().then(|| {
            (
                span_context.trace_id(),
                span_context.span_id(),
                span_context.trace_flags(),
            )
        })
    })
}

impl RenderedValue {
    fn byte_size(&self) -> usize {
        match self {
            Self::Text(value) => value.len(),
            Self::Integer(_) | Self::Float(_) | Self::Boolean(_) => 8,
        }
    }

    fn into_any_value(self) -> AnyValue {
        match self {
            Self::Text(value) => AnyValue::String(value.into()),
            Self::Integer(value) => AnyValue::Int(value),
            Self::Float(value) => AnyValue::Double(value),
            Self::Boolean(value) => AnyValue::Boolean(value),
        }
    }
}

fn emit_record(logger: &impl Logger, event: RenderedEvent) {
    let mut record = logger.create_log_record();
    record.set_event_name(event.name);
    record.set_timestamp(SystemTime::now());
    record.set_severity_number(severity_number(event.severity));
    record.set_severity_text(severity_text(event.severity));
    record.set_body(AnyValue::String(event.name.into()));
    record.add_attribute(
        "identity.event.category",
        match event.category {
            EventCategory::Audit => "audit",
            EventCategory::Business => "business",
        },
    );
    if let Some(outcome) = event.outcome {
        record.add_attribute("identity.event.outcome", outcome);
    }
    if let Some(reason) = event.reason {
        record.add_attribute("identity.event.reason", reason);
    }
    if let Some((trace_id, span_id, flags)) = event.trace {
        record.set_trace_context(trace_id, span_id, Some(flags));
    }
    for (key, value) in event.attributes {
        record.add_attribute(key, value.into_any_value());
    }
    logger.emit(record);
}

const fn severity_number(severity: EventSeverity) -> Severity {
    match severity {
        EventSeverity::Info => Severity::Info,
        EventSeverity::Warn => Severity::Warn,
        EventSeverity::Error => Severity::Error,
    }
}

const fn severity_text(severity: EventSeverity) -> &'static str {
    match severity {
        EventSeverity::Info => "INFO",
        EventSeverity::Warn => "WARN",
        EventSeverity::Error => "ERROR",
    }
}

#[cfg(test)]
mod tests {
    use std::{sync::Arc, time::Duration};

    use identity_application::observability::{
        BusinessEvent, EventSeverity, EventSink, EventValue,
    };
    use opentelemetry::logs::LoggerProvider;
    use opentelemetry_sdk::{
        error::OTelSdkResult,
        logs::{LogBatch, SdkLoggerProvider},
    };

    use super::{EventPipeline, render};
    use crate::config::EventsPipelineConfig;

    #[derive(Clone, Debug, Default)]
    struct CollectingExporter {
        records: Arc<std::sync::Mutex<Vec<String>>>,
    }

    impl opentelemetry_sdk::logs::LogExporter for CollectingExporter {
        async fn export(&self, batch: LogBatch<'_>) -> OTelSdkResult {
            let mut records = self.records.lock().unwrap();
            for (record, _) in batch.iter() {
                if let Some(name) = record.event_name() {
                    records.push(name.to_owned());
                }
            }
            Ok(())
        }
    }

    #[test]
    fn rendering_applies_pii_policy_and_keeps_trace_free_records() {
        let event = BusinessEvent::business("token.exchange.result")
            .severity(EventSeverity::Info)
            .outcome("success")
            .attribute("client_oid", EventValue::Text("client-1".to_owned()))
            .attribute(
                "user_oid",
                EventValue::Pseudonymized {
                    purpose: "user_oid",
                    value: "user-1".to_owned(),
                },
            )
            .attribute("secret", EventValue::Credential);

        let rendered = render(event);
        let values: Vec<String> = rendered
            .attributes
            .iter()
            .map(|(key, value)| match value {
                super::RenderedValue::Text(value) => format!("{key}={value}"),
                _ => key.to_string(),
            })
            .collect();

        assert!(values.iter().any(|value| value == "client_oid=client-1"));
        assert!(values.iter().any(|value| value == "user_oid=[REDACTED]"));
        assert!(values.iter().any(|value| value == "secret=[REDACTED]"));
        assert!(rendered.trace.is_none());
    }

    #[test]
    fn full_queue_drops_instead_of_blocking() {
        let exporter = CollectingExporter::default();
        let records = Arc::clone(&exporter.records);
        let provider = SdkLoggerProvider::builder()
            .with_simple_exporter(exporter)
            .build();
        let config = EventsPipelineConfig {
            queue_capacity: 1,
            queue_bytes: 1024 * 1024,
        };
        let pipeline = EventPipeline::start(&config, provider.logger("identity.events.test"));

        // Emitting more than the queue can hold must return immediately.
        for index in 0..100 {
            pipeline.emit(
                BusinessEvent::business("test.event")
                    .attribute("index", EventValue::Integer(index)),
            );
        }

        let deadline = std::time::Instant::now() + Duration::from_secs(2);
        while records.lock().unwrap().is_empty() && std::time::Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(10));
        }

        // At least one record is eventually exported; later emits were dropped.
        assert!(!records.lock().unwrap().is_empty());
    }
}
