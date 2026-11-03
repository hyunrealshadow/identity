use opentelemetry::{
    KeyValue, global,
    metrics::{Counter, Histogram},
};
use std::{sync::OnceLock, time::Instant};

struct Instruments {
    requests: Counter<u64>,
    duration: Histogram<f64>,
}
static INSTRUMENTS: OnceLock<Instruments> = OnceLock::new();

/// Only bounded labels enter metrics. Documents, variable values, user-supplied
/// operation names, request IDs and subject identifiers never become labels.
pub(super) struct RequestObservation {
    started: Instant,
    pub operation: &'static str,
    pub outcome: &'static str,
}

impl RequestObservation {
    pub fn new() -> Self {
        Self {
            started: Instant::now(),
            operation: "request",
            outcome: "protocol_error",
        }
    }
}

impl Drop for RequestObservation {
    fn drop(&mut self) {
        let instruments = INSTRUMENTS.get_or_init(|| {
            let meter = global::meter("identity.graphql");
            Instruments {
                requests: meter.u64_counter("identity.graphql.requests").build(),
                duration: meter
                    .f64_histogram("identity.graphql.duration")
                    .with_unit("s")
                    .build(),
            }
        });
        let attributes = [
            KeyValue::new("operation", self.operation),
            KeyValue::new("outcome", self.outcome),
        ];
        let seconds = self.started.elapsed().as_secs_f64();
        instruments.requests.add(1, &attributes);
        instruments.duration.record(seconds, &attributes);
        tracing::info!(target: "identity.graphql", operation = self.operation, outcome = self.outcome,
            duration_ms = seconds * 1000.0, "graphql request completed");
    }
}
