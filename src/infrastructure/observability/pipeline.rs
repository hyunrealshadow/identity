//! OTLP providers, exporters and tracing subscriber composition.
//!
//! All exporters are async-transport (HTTP protobuf, reqwest blocking client on
//! dedicated exporter threads) behind bounded batch processors. The request
//! path only ever does a non-blocking enqueue.

use std::{sync::Arc, time::Duration};

use opentelemetry::{
    Context, KeyValue,
    logs::{AnyValue, Severity},
    trace::{TraceContextExt, TraceState},
};
use opentelemetry_appender_tracing::layer::OpenTelemetryTracingBridge;
use opentelemetry_otlp::{Compression, WithExportConfig, WithHttpConfig};
use opentelemetry_sdk::{
    Resource,
    error::OTelSdkResult,
    logs::{
        BatchConfig as LogBatchConfig, BatchConfigBuilder as LogBatchConfigBuilder,
        BatchLogProcessor, LogBatch, LogExporter, SdkLoggerProvider,
    },
    metrics::{PeriodicReader, SdkMeterProvider, exporter::PushMetricExporter},
    trace::{
        BatchConfigBuilder as SpanBatchConfigBuilder, BatchSpanProcessor, Sampler,
        SamplingDecision, SamplingResult, SdkTracerProvider, ShouldSample, SpanData, SpanExporter,
    },
};
use tracing_subscriber::{EnvFilter, Layer, fmt, layer::SubscriberExt, util::SubscriberInitExt};

use super::metrics::{ExportPipeline, ExportSignal, global as metrics};
use crate::config::{
    AppEnvironment, DiagnosticsPipelineConfig, LogFormat, LoggerConfig, ObservabilityConfig,
    OtlpCompression,
};

/// Providers that must be flushed and shut down on exit.
pub(crate) struct Providers {
    pub tracer: SdkTracerProvider,
    pub events_logs: SdkLoggerProvider,
    pub diagnostics_logs: Option<SdkLoggerProvider>,
    pub metrics: Option<SdkMeterProvider>,
}

/// Build every provider described by `config`.
pub(crate) fn build_providers(
    config: &ObservabilityConfig,
    environment: &AppEnvironment,
    console: bool,
    excluded_trace_paths: Vec<String>,
) -> Result<Providers, Box<dyn std::error::Error + Send + Sync + 'static>> {
    let resource = build_resource(environment);
    let diagnostics = &config.diagnostics;

    // Traces are always captured so key events can carry valid identifiers,
    // even when nothing is exported.
    let mut tracer_builder = SdkTracerProvider::builder()
        .with_resource(resource.clone())
        .with_sampler(build_sampler(config, environment, excluded_trace_paths));
    if config.otlp.enable {
        let exporter = CountingSpanExporter {
            inner: span_exporter(&config.otlp)?,
            signal: ExportSignal::Traces,
        };
        tracer_builder = tracer_builder.with_span_processor(
            BatchSpanProcessor::builder(exporter)
                .with_batch_config(span_batch_config(diagnostics))
                .build(),
        );
    }
    let tracer = tracer_builder.build();

    // Key events and audit records have their own bounded queue and provider so
    // diagnostics volume can never evict them.
    let mut events_builder = SdkLoggerProvider::builder().with_resource(resource.clone());
    if config.otlp.enable {
        let exporter = CountingLogExporter {
            inner: log_exporter(&config.otlp)?,
            signal: ExportSignal::Logs,
            pipeline: ExportPipeline::Events,
        };
        events_builder = events_builder.with_log_processor(
            BatchLogProcessor::builder(exporter)
                .with_batch_config(log_batch_config(diagnostics))
                .build(),
        );
    }
    if console {
        events_builder = events_builder.with_simple_exporter(ConsoleLogExporter);
    }
    let events_logs = events_builder.build();

    let diagnostics_logs = if config.otlp.enable {
        let exporter = CountingLogExporter {
            inner: log_exporter(&config.otlp)?,
            signal: ExportSignal::Logs,
            pipeline: ExportPipeline::Diagnostics,
        };
        Some(
            SdkLoggerProvider::builder()
                .with_resource(resource.clone())
                .with_log_processor(
                    BatchLogProcessor::builder(exporter)
                        .with_batch_config(log_batch_config(diagnostics))
                        .build(),
                )
                .build(),
        )
    } else {
        None
    };

    let metrics_provider = if config.otlp.enable {
        let exporter = CountingMetricExporter {
            inner: metric_exporter(&config.otlp)?,
        };
        let reader = PeriodicReader::builder(exporter)
            .with_interval(Duration::from_secs(60))
            .build();
        Some(
            SdkMeterProvider::builder()
                .with_resource(resource)
                .with_reader(reader)
                .build(),
        )
    } else {
        None
    };

    Ok(Providers {
        tracer,
        events_logs,
        diagnostics_logs,
        metrics: metrics_provider,
    })
}

/// Compose and install the tracing subscriber.
pub(crate) fn init_subscriber(
    logger: &LoggerConfig,
    console: bool,
    tracer: opentelemetry_sdk::trace::Tracer,
    diagnostics_logs: Option<&SdkLoggerProvider>,
) {
    let filter =
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(logger.level.clone()));

    let subscriber = tracing_subscriber::registry()
        .with(filter)
        .with(tracing_opentelemetry::layer().with_tracer(tracer))
        .with(
            diagnostics_logs
                .map(OpenTelemetryTracingBridge::new)
                // The SDK reports its own failures through `tracing`; feeding
                // those back into the same exporter would recurse.
                .map(|layer| {
                    layer.with_filter(tracing_subscriber::filter::filter_fn(|metadata| {
                        !metadata.target().starts_with("opentelemetry")
                    }))
                }),
        )
        .with(InternalTelemetryLayer);

    if console {
        match logger.format {
            LogFormat::Json => subscriber.with(fmt::layer().json()).init(),
            LogFormat::Pretty => subscriber.with(fmt::layer().pretty()).init(),
            LogFormat::Compact => subscriber.with(fmt::layer()).init(),
        }
    } else {
        subscriber.init();
    }
}

/// Flush and shut down every provider with a bounded wait.
pub(crate) fn shutdown(providers: &Providers, timeout: Duration) {
    let _ = providers.events_logs.shutdown_with_timeout(timeout);
    if let Some(diagnostics) = &providers.diagnostics_logs {
        let _ = diagnostics.shutdown_with_timeout(timeout);
    }
    let _ = providers.tracer.shutdown_with_timeout(timeout);
    if let Some(metrics) = &providers.metrics {
        let _ = metrics.shutdown_with_timeout(timeout);
    }
}

fn build_resource(environment: &AppEnvironment) -> Resource {
    let service_name = std::env::var("OTEL_SERVICE_NAME").unwrap_or_else(|_| "identity".to_owned());
    let instance_id = std::env::var("HOSTNAME")
        .ok()
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| uuid::Uuid::new_v4().to_string());

    Resource::builder()
        .with_service_name(service_name)
        .with_attributes([
            KeyValue::new("service.version", env!("CARGO_PKG_VERSION")),
            KeyValue::new("service.instance.id", instance_id),
            KeyValue::new(
                "deployment.environment.name",
                environment.as_str().to_owned(),
            ),
        ])
        .build()
}

fn build_sampler(
    config: &ObservabilityConfig,
    environment: &AppEnvironment,
    excluded_root_paths: Vec<String>,
) -> Sampler {
    let ratio = config.sampling.trace_ratio.unwrap_or_else(|| {
        if environment.is_production() {
            0.1
        } else {
            1.0
        }
    });
    Sampler::ParentBased(Box::new(IdentitySampler {
        inner: Sampler::TraceIdRatioBased(ratio),
        excluded_root_paths: Arc::new(excluded_root_paths),
    }))
}

/// Head sampler that keeps successful probe traffic out of traces. Only root
/// spans are dropped so a trusted parent decision is never contradicted.
#[derive(Clone, Debug)]
pub(crate) struct IdentitySampler {
    inner: Sampler,
    excluded_root_paths: Arc<Vec<String>>,
}

impl ShouldSample for IdentitySampler {
    fn should_sample(
        &self,
        parent_context: Option<&Context>,
        trace_id: opentelemetry::trace::TraceId,
        name: &str,
        span_kind: &opentelemetry::trace::SpanKind,
        attributes: &[KeyValue],
        links: &[opentelemetry::trace::Link],
    ) -> SamplingResult {
        let has_parent = parent_context.is_some_and(Context::has_active_span);
        if !has_parent
            && let Some(path) = attribute_str(attributes, "url.path")
            && self
                .excluded_root_paths
                .iter()
                .any(|excluded| excluded == path)
        {
            return SamplingResult {
                decision: SamplingDecision::Drop,
                attributes: Vec::new(),
                trace_state: TraceState::default(),
            };
        }
        self.inner
            .should_sample(parent_context, trace_id, name, span_kind, attributes, links)
    }
}

fn attribute_str<'a>(attributes: &'a [KeyValue], key: &str) -> Option<&'a str> {
    attributes
        .iter()
        .find(|attribute| attribute.key.as_str() == key)
        .and_then(|attribute| match &attribute.value {
            opentelemetry::Value::String(value) => Some(value.as_str()),
            _ => None,
        })
}

fn span_batch_config(
    diagnostics: &DiagnosticsPipelineConfig,
) -> opentelemetry_sdk::trace::BatchConfig {
    SpanBatchConfigBuilder::default()
        .with_max_queue_size(diagnostics.span_queue_capacity)
        .with_max_export_batch_size(diagnostics.max_export_batch_size)
        .with_scheduled_delay(Duration::from_millis(diagnostics.schedule_delay_ms))
        .build()
}

fn log_batch_config(diagnostics: &DiagnosticsPipelineConfig) -> LogBatchConfig {
    LogBatchConfigBuilder::default()
        .with_max_queue_size(diagnostics.log_queue_capacity)
        .with_max_export_batch_size(diagnostics.max_export_batch_size)
        .with_scheduled_delay(Duration::from_millis(diagnostics.schedule_delay_ms))
        .build()
}

/// Build the signal-specific endpoint. The configured value is the collector
/// base URL; the OTLP/HTTP signal path is appended. A value that already ends
/// with the signal path is accepted unchanged.
fn signal_endpoint(base: &str, signal_path: &str) -> String {
    let trimmed = base.trim_end_matches('/');
    if trimmed.ends_with(signal_path) {
        trimmed.to_owned()
    } else {
        format!("{trimmed}{signal_path}")
    }
}

fn span_exporter(
    config: &crate::config::OtlpConfig,
) -> Result<opentelemetry_otlp::SpanExporter, Box<dyn std::error::Error + Send + Sync + 'static>> {
    let builder = opentelemetry_otlp::SpanExporter::builder()
        .with_http()
        .with_endpoint(signal_endpoint(&config.endpoint, "/v1/traces"))
        .with_timeout(Duration::from_millis(config.timeout_ms));
    let builder = match config.compression {
        OtlpCompression::None => builder,
        OtlpCompression::Gzip => builder.with_compression(Compression::Gzip),
    };
    Ok(builder.build()?)
}

fn log_exporter(
    config: &crate::config::OtlpConfig,
) -> Result<opentelemetry_otlp::LogExporter, Box<dyn std::error::Error + Send + Sync + 'static>> {
    let builder = opentelemetry_otlp::LogExporter::builder()
        .with_http()
        .with_endpoint(signal_endpoint(&config.endpoint, "/v1/logs"))
        .with_timeout(Duration::from_millis(config.timeout_ms));
    let builder = match config.compression {
        OtlpCompression::None => builder,
        OtlpCompression::Gzip => builder.with_compression(Compression::Gzip),
    };
    Ok(builder.build()?)
}

fn metric_exporter(
    config: &crate::config::OtlpConfig,
) -> Result<opentelemetry_otlp::MetricExporter, Box<dyn std::error::Error + Send + Sync + 'static>>
{
    let builder = opentelemetry_otlp::MetricExporter::builder()
        .with_http()
        .with_endpoint(signal_endpoint(&config.endpoint, "/v1/metrics"))
        .with_timeout(Duration::from_millis(config.timeout_ms));
    let builder = match config.compression {
        OtlpCompression::None => builder,
        OtlpCompression::Gzip => builder.with_compression(Compression::Gzip),
    };
    Ok(builder.build()?)
}

/// Export failures must never recurse into the pipeline that failed.
#[derive(Debug)]
struct CountingSpanExporter<E> {
    inner: E,
    signal: ExportSignal,
}

impl<E: SpanExporter> SpanExporter for CountingSpanExporter<E> {
    async fn export(&self, batch: Vec<SpanData>) -> OTelSdkResult {
        let result = self.inner.export(batch).await;
        if result.is_err() {
            metrics().export_failed(self.signal, ExportPipeline::Diagnostics);
        }
        result
    }

    fn shutdown_with_timeout(&self, timeout: Duration) -> OTelSdkResult {
        self.inner.shutdown_with_timeout(timeout)
    }

    fn force_flush(&self) -> OTelSdkResult {
        self.inner.force_flush()
    }

    fn set_resource(&mut self, resource: &Resource) {
        self.inner.set_resource(resource);
    }
}

#[derive(Debug)]
struct CountingLogExporter<E> {
    inner: E,
    signal: ExportSignal,
    pipeline: ExportPipeline,
}

impl<E: LogExporter> LogExporter for CountingLogExporter<E> {
    async fn export(&self, batch: LogBatch<'_>) -> OTelSdkResult {
        let result = self.inner.export(batch).await;
        if result.is_err() {
            metrics().export_failed(self.signal, self.pipeline);
        }
        result
    }

    fn shutdown_with_timeout(&self, timeout: Duration) -> OTelSdkResult {
        self.inner.shutdown_with_timeout(timeout)
    }

    fn event_enabled(&self, level: Severity, target: &str, name: Option<&str>) -> bool {
        self.inner.event_enabled(level, target, name)
    }

    fn set_resource(&mut self, resource: &Resource) {
        self.inner.set_resource(resource);
    }
}

#[derive(Debug)]
struct CountingMetricExporter<E> {
    inner: E,
}

impl<E: PushMetricExporter> PushMetricExporter for CountingMetricExporter<E> {
    async fn export(
        &self,
        metrics: &opentelemetry_sdk::metrics::data::ResourceMetrics,
    ) -> OTelSdkResult {
        let result = self.inner.export(metrics).await;
        if result.is_err() {
            super::metrics::global()
                .export_failed(ExportSignal::Metrics, ExportPipeline::Diagnostics);
        }
        result
    }

    fn force_flush(&self) -> OTelSdkResult {
        self.inner.force_flush()
    }

    fn shutdown_with_timeout(&self, timeout: Duration) -> OTelSdkResult {
        self.inner.shutdown_with_timeout(timeout)
    }

    fn temporality(&self) -> opentelemetry_sdk::metrics::Temporality {
        self.inner.temporality()
    }
}

/// Prints key events and audit records when the console is enabled. Raw values
/// are already rendered through the shared PII policy.
#[derive(Debug, Default, Clone, Copy)]
pub(crate) struct ConsoleLogExporter;

impl LogExporter for ConsoleLogExporter {
    async fn export(&self, batch: LogBatch<'_>) -> OTelSdkResult {
        for (record, _scope) in batch.iter() {
            println!("{}", format_record(record));
        }
        Ok(())
    }
}

fn format_record(record: &opentelemetry_sdk::logs::SdkLogRecord) -> String {
    let timestamp = record
        .timestamp()
        .map(|time| {
            chrono::DateTime::<chrono::Utc>::from(time)
                .format("%Y-%m-%dT%H:%M:%S%.3fZ")
                .to_string()
        })
        .unwrap_or_else(|| "-".to_owned());
    let severity = record
        .severity_number()
        .map(|severity| format!("{severity:?}"))
        .unwrap_or_default();
    let name = record.event_name().unwrap_or("event");
    let mut line = format!("{timestamp} {severity:>5} {name}");
    for (key, value) in record.attributes_iter() {
        line.push(' ');
        line.push_str(key.as_str());
        line.push('=');
        line.push_str(&any_value_to_string(value));
    }
    if let Some(trace) = record.trace_context() {
        line.push_str(&format!(
            " trace_id={} span_id={}",
            trace.trace_id, trace.span_id
        ));
    }
    line
}

fn any_value_to_string(value: &AnyValue) -> String {
    match value {
        AnyValue::String(value) => value.to_string(),
        AnyValue::Boolean(value) => value.to_string(),
        AnyValue::Int(value) => value.to_string(),
        AnyValue::Double(value) => value.to_string(),
        AnyValue::Bytes(value) => format!("{} bytes", value.len()),
        AnyValue::ListAny(values) => {
            let rendered: Vec<String> = values.iter().map(any_value_to_string).collect();
            format!("[{}]", rendered.join(","))
        }
        AnyValue::Map(values) => {
            let rendered: Vec<String> = values
                .iter()
                .map(|(key, value)| format!("{}={}", key.as_str(), any_value_to_string(value)))
                .collect();
            format!("{{{}}}", rendered.join(","))
        }
        other => format!("{other:?}"),
    }
}

/// Watches the SDK's own `tracing` diagnostics for reported queue drops and
/// records them in the independent metrics registry.
#[derive(Clone, Copy, Debug, Default)]
struct InternalTelemetryLayer;

impl<S: tracing::Subscriber> Layer<S> for InternalTelemetryLayer {
    fn on_event(
        &self,
        event: &tracing::Event<'_>,
        _context: tracing_subscriber::layer::Context<'_, S>,
    ) {
        if !event.metadata().target().starts_with("opentelemetry") {
            return;
        }
        let mut visitor = InternalTelemetryVisitor::default();
        event.record(&mut visitor);
        let Some(name) = visitor.name.as_deref() else {
            return;
        };
        match name {
            "BatchSpanProcessor.SpanDroppingStarted" => {
                metrics().sdk_reported_dropped_spans(1);
            }
            "BatchLogProcessor.LogDroppingStarted" => {
                metrics().sdk_reported_dropped_logs(1);
            }
            "BatchSpanProcessor.SpansDropped" => {
                metrics().sdk_reported_dropped_spans(visitor.count.unwrap_or(1));
            }
            "BatchLogProcessor.LogsDropped" => {
                metrics().sdk_reported_dropped_logs(visitor.count.unwrap_or(1));
            }
            _ => {}
        }
    }
}

#[derive(Default)]
struct InternalTelemetryVisitor {
    name: Option<String>,
    count: Option<u64>,
}

impl tracing::field::Visit for InternalTelemetryVisitor {
    fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
        if field.name() == "name" {
            self.name = Some(value.to_owned());
        }
    }

    fn record_u64(&mut self, field: &tracing::field::Field, value: u64) {
        if matches!(field.name(), "dropped_span_count" | "dropped_logs_count") {
            self.count = Some(value);
        }
    }

    fn record_debug(&mut self, _field: &tracing::field::Field, _value: &dyn std::fmt::Debug) {}
}

#[cfg(test)]
mod tests {
    use opentelemetry::KeyValue;
    use opentelemetry::trace::SpanKind;
    use opentelemetry_sdk::trace::ShouldSample;

    use super::{IdentitySampler, build_sampler};
    use crate::config::{AppEnvironment, ObservabilityConfig};

    #[test]
    fn health_root_spans_are_not_sampled() {
        let sampler = IdentitySampler {
            inner: opentelemetry_sdk::trace::Sampler::TraceIdRatioBased(1.0),
            excluded_root_paths: std::sync::Arc::new(vec!["/health".to_owned()]),
        };
        let attributes = [KeyValue::new("url.path", "/health")];
        let result = sampler.should_sample(
            None,
            opentelemetry::trace::TraceId::from_hex("4bf92f3577b34da6a3ce929d0e0e4736").unwrap(),
            "http.server",
            &SpanKind::Server,
            &attributes,
            &[],
        );
        assert_eq!(
            result.decision,
            opentelemetry_sdk::trace::SamplingDecision::Drop
        );

        let allowed = [KeyValue::new("url.path", "/authorize")];
        let result = sampler.should_sample(
            None,
            opentelemetry::trace::TraceId::from_hex("4bf92f3577b34da6a3ce929d0e0e4736").unwrap(),
            "http.server",
            &SpanKind::Server,
            &allowed,
            &[],
        );
        assert_eq!(
            result.decision,
            opentelemetry_sdk::trace::SamplingDecision::RecordAndSample
        );
    }

    #[test]
    fn appends_signal_paths_to_the_collector_base_url() {
        assert_eq!(
            super::signal_endpoint("http://collector:4318", "/v1/traces"),
            "http://collector:4318/v1/traces"
        );
        assert_eq!(
            super::signal_endpoint("http://collector:4318/", "/v1/logs"),
            "http://collector:4318/v1/logs"
        );
        assert_eq!(
            super::signal_endpoint("http://collector:4318/v1/metrics", "/v1/metrics"),
            "http://collector:4318/v1/metrics"
        );
    }

    #[test]
    fn production_defaults_to_ten_percent() {
        let sampler = build_sampler(
            &ObservabilityConfig::default(),
            &AppEnvironment::Production,
            vec!["/health".to_owned()],
        );
        let debug = format!("{sampler:?}");
        assert!(debug.contains("0.1"), "unexpected sampler: {debug}");

        let development = build_sampler(
            &ObservabilityConfig::default(),
            &AppEnvironment::Development,
            Vec::new(),
        );
        assert!(format!("{development:?}").contains("1.0"));
    }
}

#[cfg(test)]
mod otlp_construction_tests {
    use std::time::Duration;

    use super::{build_providers, shutdown};
    use crate::config::{AppEnvironment, ObservabilityConfig};

    /// Building and shutting down the OTLP providers inside a Tokio runtime
    /// must not panic: reqwest's blocking client and the batch processors run
    /// on their own threads, so the async request path never blocks.
    #[tokio::test]
    async fn otlp_providers_build_inside_a_tokio_runtime() {
        let mut config = ObservabilityConfig::default();
        config.otlp.enable = true;
        // Unroutable local port: exports fail fast and are counted.
        config.otlp.endpoint = "http://127.0.0.1:1".to_owned();
        config.otlp.timeout_ms = 200;

        let providers = build_providers(&config, &AppEnvironment::Development, false, Vec::new())
            .expect("OTLP providers must build");
        shutdown(&providers, Duration::from_millis(500));
    }
}

#[cfg(test)]
mod otlp_export_tests {
    use std::{sync::Arc, time::Duration};

    use opentelemetry::{
        logs::{LogRecord, Logger, LoggerProvider},
        trace::{Span as _, Tracer, TracerProvider},
    };
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::TcpListener,
        sync::Mutex,
    };

    use super::{build_providers, shutdown};
    use crate::config::{AppEnvironment, ObservabilityConfig};

    #[derive(Clone, Debug, Default)]
    struct MockCollector {
        requests: Arc<Mutex<Vec<(String, String)>>>,
    }

    impl MockCollector {
        async fn start() -> (Self, String) {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let address = listener.local_addr().unwrap();
            let collector = Self::default();
            let requests = Arc::clone(&collector.requests);
            tokio::spawn(async move {
                loop {
                    let Ok((mut socket, _)) = listener.accept().await else {
                        return;
                    };
                    let requests = Arc::clone(&requests);
                    tokio::spawn(async move {
                        let mut buffer = Vec::new();
                        let mut chunk = [0_u8; 8192];
                        loop {
                            let read = match socket.read(&mut chunk).await {
                                Ok(0) | Err(_) => break,
                                Ok(read) => read,
                            };
                            buffer.extend_from_slice(&chunk[..read]);
                            let Some(headers_end) =
                                buffer.windows(4).position(|window| window == b"\r\n\r\n")
                            else {
                                continue;
                            };
                            let headers =
                                String::from_utf8_lossy(&buffer[..headers_end]).to_string();
                            let content_length = headers
                                .lines()
                                .find_map(|line| {
                                    line.to_ascii_lowercase()
                                        .strip_prefix("content-length:")
                                        .and_then(|value| value.trim().parse::<usize>().ok())
                                })
                                .unwrap_or(0);
                            if buffer.len() >= headers_end + 4 + content_length {
                                break;
                            }
                        }
                        let request = String::from_utf8_lossy(&buffer).to_string();
                        let path = request
                            .lines()
                            .next()
                            .and_then(|line| line.split_whitespace().nth(1))
                            .unwrap_or_default()
                            .to_owned();
                        let body = request
                            .split("\r\n\r\n")
                            .nth(1)
                            .unwrap_or_default()
                            .to_owned();
                        requests.lock().await.push((path, body));
                        let response = "HTTP/1.1 200 OK\r\ncontent-length: 0\r\n\r\n";
                        let _ = socket.write_all(response.as_bytes()).await;
                    });
                }
            });
            (collector, format!("http://{address}"))
        }
    }

    #[tokio::test]
    async fn exports_spans_and_logs_to_the_configured_collector() {
        let (collector, endpoint) = MockCollector::start().await;
        let mut config = ObservabilityConfig::default();
        config.otlp.enable = true;
        config.otlp.endpoint = endpoint;
        config.diagnostics.schedule_delay_ms = 10;

        let providers = build_providers(&config, &AppEnvironment::Development, false, Vec::new())
            .expect("OTLP providers must build");

        let tracer = providers.tracer.tracer("export-test");
        let mut span = tracer.start("export.test.span");
        span.end();

        let logger = providers.events_logs.logger("export-test");
        let mut record = logger.create_log_record();
        record.set_event_name("export.test.event");
        logger.emit(record);

        let _ = providers.tracer.force_flush();
        let _ = providers.events_logs.force_flush();
        tokio::time::sleep(Duration::from_millis(200)).await;
        shutdown(&providers, Duration::from_secs(2));

        let requests = collector.requests.lock().await.clone();
        let paths: Vec<&str> = requests.iter().map(|(path, _)| path.as_str()).collect();
        assert!(paths.contains(&"/v1/traces"), "requests: {paths:?}");
        assert!(paths.contains(&"/v1/logs"), "requests: {paths:?}");
        let trace_body = &requests
            .iter()
            .find(|(path, _)| path == "/v1/traces")
            .unwrap()
            .1;
        assert!(!trace_body.is_empty());
        let log_body = &requests
            .iter()
            .find(|(path, _)| path == "/v1/logs")
            .unwrap()
            .1;
        assert!(!log_body.is_empty());
    }
}
