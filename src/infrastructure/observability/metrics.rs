//! Independent self-metrics for the observability pipeline.
//!
//! These counters exist so that dropped audit records, saturated queues and
//! failed exports stay visible even when the collector is unreachable. They are
//! intentionally not routed through the OTLP pipeline they describe; the web
//! layer exposes them on a separate internal scrape endpoint.

use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

/// Signal kind for export failure metrics. Bounded label set.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ExportSignal {
    Traces,
    Logs,
    Metrics,
}

impl ExportSignal {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Traces => "traces",
            Self::Logs => "logs",
            Self::Metrics => "metrics",
        }
    }
}

/// Pipeline kind for export failure metrics. Bounded label set.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ExportPipeline {
    Diagnostics,
    Events,
}

impl ExportPipeline {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Diagnostics => "diagnostics",
            Self::Events => "events",
        }
    }
}

/// Process-wide observability failure counters.
#[derive(Debug, Default)]
pub struct ObservabilityMetrics {
    events_queue_capacity: AtomicUsize,
    events_queue_depth: AtomicUsize,
    events_queue_bytes: AtomicUsize,
    events_queue_byte_limit: AtomicUsize,
    events_emitted_business: AtomicU64,
    events_emitted_audit: AtomicU64,
    events_dropped_queue_full: AtomicU64,
    events_dropped_byte_limit: AtomicU64,
    events_dropped_uninitialized: AtomicU64,
    export_failures_traces_diagnostics: AtomicU64,
    export_failures_logs_diagnostics: AtomicU64,
    export_failures_metrics: AtomicU64,
    export_failures_logs_events: AtomicU64,
    sdk_reported_dropped_spans: AtomicU64,
    sdk_reported_dropped_logs: AtomicU64,
}

static METRICS: ObservabilityMetrics = ObservabilityMetrics::new();

/// Global metrics registry installed for the process lifetime.
#[must_use]
pub fn global() -> &'static ObservabilityMetrics {
    &METRICS
}

impl ObservabilityMetrics {
    #[allow(clippy::new_without_default)]
    const fn new() -> Self {
        Self {
            events_queue_capacity: AtomicUsize::new(0),
            events_queue_depth: AtomicUsize::new(0),
            events_queue_bytes: AtomicUsize::new(0),
            events_queue_byte_limit: AtomicUsize::new(0),
            events_emitted_business: AtomicU64::new(0),
            events_emitted_audit: AtomicU64::new(0),
            events_dropped_queue_full: AtomicU64::new(0),
            events_dropped_byte_limit: AtomicU64::new(0),
            events_dropped_uninitialized: AtomicU64::new(0),
            export_failures_traces_diagnostics: AtomicU64::new(0),
            export_failures_logs_diagnostics: AtomicU64::new(0),
            export_failures_metrics: AtomicU64::new(0),
            export_failures_logs_events: AtomicU64::new(0),
            sdk_reported_dropped_spans: AtomicU64::new(0),
            sdk_reported_dropped_logs: AtomicU64::new(0),
        }
    }

    pub(crate) fn configure_events_queue(&self, capacity: usize, byte_limit: usize) {
        self.events_queue_capacity
            .store(capacity, Ordering::Relaxed);
        self.events_queue_byte_limit
            .store(byte_limit, Ordering::Relaxed);
    }

    pub(crate) fn events_enqueued(&self, bytes: usize) {
        self.events_queue_depth.fetch_add(1, Ordering::Relaxed);
        self.events_queue_bytes.fetch_add(bytes, Ordering::Relaxed);
    }

    pub(crate) fn events_dequeued(&self, bytes: usize) {
        self.events_queue_depth.fetch_sub(1, Ordering::Relaxed);
        self.events_queue_bytes.fetch_sub(bytes, Ordering::Relaxed);
    }

    pub(crate) fn events_emitted(&self, category: &'static str) {
        match category {
            "audit" => self.events_emitted_audit.fetch_add(1, Ordering::Relaxed),
            _ => self.events_emitted_business.fetch_add(1, Ordering::Relaxed),
        };
    }

    pub(crate) fn events_dropped(&self, reason: &'static str) {
        match reason {
            "queue_full" => self
                .events_dropped_queue_full
                .fetch_add(1, Ordering::Relaxed),
            "byte_limit" => self
                .events_dropped_byte_limit
                .fetch_add(1, Ordering::Relaxed),
            _ => self
                .events_dropped_uninitialized
                .fetch_add(1, Ordering::Relaxed),
        };
    }

    pub(crate) fn queued_event_bytes(&self) -> usize {
        self.events_queue_bytes.load(Ordering::Relaxed)
    }

    pub(crate) fn event_queue_byte_limit(&self) -> usize {
        self.events_queue_byte_limit.load(Ordering::Relaxed)
    }

    pub(crate) fn event_queue_depth(&self) -> usize {
        self.events_queue_depth.load(Ordering::Relaxed)
    }

    pub(crate) fn export_failed(&self, signal: ExportSignal, pipeline: ExportPipeline) {
        let counter = match (signal, pipeline) {
            (ExportSignal::Traces, ExportPipeline::Diagnostics) => {
                &self.export_failures_traces_diagnostics
            }
            (ExportSignal::Traces, ExportPipeline::Events) => {
                &self.export_failures_traces_diagnostics
            }
            (ExportSignal::Logs, ExportPipeline::Diagnostics) => {
                &self.export_failures_logs_diagnostics
            }
            (ExportSignal::Logs, ExportPipeline::Events) => &self.export_failures_logs_events,
            (ExportSignal::Metrics, _) => &self.export_failures_metrics,
        };
        counter.fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn sdk_reported_dropped_spans(&self, count: u64) {
        self.sdk_reported_dropped_spans
            .fetch_add(count.max(1), Ordering::Relaxed);
    }

    pub(crate) fn sdk_reported_dropped_logs(&self, count: u64) {
        self.sdk_reported_dropped_logs
            .fetch_add(count.max(1), Ordering::Relaxed);
    }

    fn u64(&self, value: &AtomicU64) -> u64 {
        value.load(Ordering::Relaxed)
    }

    fn usize(&self, value: &AtomicUsize) -> usize {
        value.load(Ordering::Relaxed)
    }

    /// Render Prometheus text exposition for the independent scrape endpoint.
    #[must_use]
    pub fn render_prometheus(&self) -> String {
        let mut output = String::with_capacity(2048);
        let family = |output: &mut String, name: &str, kind: &str, help: &str| {
            output.push_str(&format!("# HELP {name} {help}\n# TYPE {name} {kind}\n"));
        };
        let sample = |output: &mut String, name: &str, labels: &str, value: String| {
            output.push_str(&format!("{name}{labels} {value}\n"));
        };

        family(
            &mut output,
            "identity_observability_events_queue_capacity",
            "gauge",
            "Configured capacity of the key event and audit queue.",
        );
        family(
            &mut output,
            "identity_observability_events_queue_depth",
            "gauge",
            "Records currently waiting in the key event and audit queue.",
        );
        family(
            &mut output,
            "identity_observability_events_queue_bytes",
            "gauge",
            "Approximate bytes currently waiting in the key event and audit queue.",
        );
        family(
            &mut output,
            "identity_observability_events_queue_byte_limit",
            "gauge",
            "Configured byte budget of the key event and audit queue.",
        );
        family(
            &mut output,
            "identity_observability_events_emitted_total",
            "counter",
            "Key events and audit records accepted for export.",
        );
        family(
            &mut output,
            "identity_observability_events_dropped_total",
            "counter",
            "Key events and audit records dropped instead of blocking.",
        );
        family(
            &mut output,
            "identity_observability_export_failures_total",
            "counter",
            "Failed OTLP exports by signal and pipeline.",
        );
        family(
            &mut output,
            "identity_observability_sdk_reported_dropped_spans_total",
            "counter",
            "Spans reported dropped by the SDK batch processor.",
        );
        family(
            &mut output,
            "identity_observability_sdk_reported_dropped_logs_total",
            "counter",
            "Log records reported dropped by the SDK batch processor.",
        );

        let emitted_total =
            self.u64(&self.events_emitted_business) + self.u64(&self.events_emitted_audit);
        let samples: [(&str, &str, String); 14] = [
            (
                "identity_observability_events_queue_capacity",
                "",
                self.usize(&self.events_queue_capacity).to_string(),
            ),
            (
                "identity_observability_events_queue_depth",
                "",
                self.usize(&self.events_queue_depth).to_string(),
            ),
            (
                "identity_observability_events_queue_bytes",
                "",
                self.usize(&self.events_queue_bytes).to_string(),
            ),
            (
                "identity_observability_events_queue_byte_limit",
                "",
                self.usize(&self.events_queue_byte_limit).to_string(),
            ),
            (
                "identity_observability_events_emitted_total",
                "",
                emitted_total.to_string(),
            ),
            (
                "identity_observability_events_dropped_total",
                "{reason=\"queue_full\"}",
                self.u64(&self.events_dropped_queue_full).to_string(),
            ),
            (
                "identity_observability_events_dropped_total",
                "{reason=\"byte_limit\"}",
                self.u64(&self.events_dropped_byte_limit).to_string(),
            ),
            (
                "identity_observability_events_dropped_total",
                "{reason=\"not_initialized\"}",
                self.u64(&self.events_dropped_uninitialized).to_string(),
            ),
            (
                "identity_observability_export_failures_total",
                "{signal=\"traces\",pipeline=\"diagnostics\"}",
                self.u64(&self.export_failures_traces_diagnostics)
                    .to_string(),
            ),
            (
                "identity_observability_export_failures_total",
                "{signal=\"logs\",pipeline=\"diagnostics\"}",
                self.u64(&self.export_failures_logs_diagnostics).to_string(),
            ),
            (
                "identity_observability_export_failures_total",
                "{signal=\"logs\",pipeline=\"events\"}",
                self.u64(&self.export_failures_logs_events).to_string(),
            ),
            (
                "identity_observability_export_failures_total",
                "{signal=\"metrics\",pipeline=\"diagnostics\"}",
                self.u64(&self.export_failures_metrics).to_string(),
            ),
            (
                "identity_observability_sdk_reported_dropped_spans_total",
                "",
                self.u64(&self.sdk_reported_dropped_spans).to_string(),
            ),
            (
                "identity_observability_sdk_reported_dropped_logs_total",
                "",
                self.u64(&self.sdk_reported_dropped_logs).to_string(),
            ),
        ];
        for (name, labels, value) in samples {
            sample(&mut output, name, labels, value);
        }

        output
    }
}

#[cfg(test)]
mod tests {
    use super::{ExportPipeline, ExportSignal, ObservabilityMetrics};

    #[test]
    fn renders_bounded_and_independent_series() {
        let metrics = ObservabilityMetrics::new();
        metrics.configure_events_queue(16, 1024);
        metrics.events_enqueued(128);
        metrics.events_emitted("audit");
        metrics.events_dropped("queue_full");
        metrics.export_failed(ExportSignal::Logs, ExportPipeline::Events);

        let rendered = metrics.render_prometheus();

        assert!(rendered.contains("identity_observability_events_queue_depth 1\n"));
        assert!(rendered.contains("identity_observability_events_queue_bytes 128\n"));
        assert!(rendered.contains("identity_observability_events_emitted_total 1\n"));
        assert!(
            rendered
                .contains("identity_observability_events_dropped_total{reason=\"queue_full\"} 1\n")
        );
        assert!(rendered.contains(
            "identity_observability_export_failures_total{signal=\"logs\",pipeline=\"events\"} 1\n"
        ));
        assert_eq!(
            rendered
                .matches("# HELP identity_observability_events_dropped_total")
                .count(),
            1
        );
        // No business identifiers or free-form values in label positions.
        assert!(!rendered.contains("trace_id"));
        assert!(!rendered.contains("user_oid"));
    }
}
