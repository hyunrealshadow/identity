//! Observability initialization: console output, OTLP pipelines, PII policy,
//! W3C trace context and the non-blocking event/audit sink.
//!
//! See `docs/observability-design.md` and `docs/observability-coverage.md` for
//! the confirmed design this module implements.

pub mod context;
pub mod events;
pub mod metrics;
pub mod outbound;
pub mod pii;
mod pipeline;

use std::{error::Error, sync::OnceLock, time::Duration};

use opentelemetry::trace::TracerProvider;
use opentelemetry_sdk::propagation::TraceContextPropagator;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;

use crate::config::{AppConfig, AppEnvironment, LogFormat, LoggerConfig};

use self::pii::PiiPolicy;
use self::pipeline::Providers;

pub type ObservabilityResult<T> = Result<T, Box<dyn Error + Send + Sync + 'static>>;

static PROVIDERS: OnceLock<Providers> = OnceLock::new();

/// Initialize observability. Must be called once, after configuration is
/// loaded and before the servers start.
pub fn init(config: &AppConfig, environment: &AppEnvironment) -> ObservabilityResult<()> {
    let observability = &config.observability;

    if !observability.enable {
        if config.logger.enable {
            init_console_only(&config.logger);
        }
        return Ok(());
    }

    let console = config.logger.enable
        && observability
            .console
            .unwrap_or(!environment.is_production());

    if !observability.otlp.enable && !console {
        return Err(
            "observability is enabled but neither the console nor OTLP export is configured".into(),
        );
    }

    // PII policy must be installed before any output layer can format a value.
    let (policy, policy_warning) = resolve_pii_policy(&config.observability.pii);
    pii::install(policy);

    opentelemetry::global::set_text_map_propagator(TraceContextPropagator::new());
    identity_application::observability::install_outbound_trace(
        outbound::OutboundTraceImpl::shared(context::TraceTrustPolicy::new(
            observability.trace_context.clone(),
        )),
    );

    let excluded_paths = excluded_trace_paths(config);
    let providers = pipeline::build_providers(observability, environment, console, excluded_paths)?;
    let tracer = providers.tracer.tracer("identity");

    pipeline::init_subscriber(
        &config.logger,
        console,
        tracer,
        providers.diagnostics_logs.as_ref(),
    );
    events::install(&observability.events, &providers.events_logs);
    identity_application::observability::install_event_sink(events::sink());
    let _ = PROVIDERS.set(providers);

    if let Some(warning) = policy_warning {
        tracing::warn!(target: "identity.observability", "{warning}");
    }

    Ok(())
}

/// Flush bounded queues and shut providers down with an upper bound on the wait.
pub fn shutdown(timeout: Duration) {
    events::close();
    if let Some(providers) = PROVIDERS.get() {
        pipeline::shutdown(providers, timeout);
    }
}

/// Whether the OTLP/event pipeline was initialized.
#[must_use]
pub fn is_initialized() -> bool {
    PROVIDERS.get().is_some()
}

fn resolve_pii_policy(config: &crate::config::PiiConfig) -> (Option<PiiPolicy>, Option<String>) {
    let Some(source) = config.hmac_key.as_ref() else {
        return (None, None);
    };
    match source.resolve() {
        Ok(Some(key)) if !key.is_empty() => (
            Some(PiiPolicy::new(key, config.hmac_key_version.clone())),
            None,
        ),
        Ok(_) => (
            None,
            Some(
                "observability.pii.hmac_key resolved to an empty value; PII falls back to REDACTED"
                    .to_owned(),
            ),
        ),
        Err(error) => (
            None,
            Some(format!(
                "observability.pii.hmac_key could not be resolved ({error}); PII falls back to REDACTED"
            )),
        ),
    }
}

/// Paths whose successful requests are useful as metrics but not as traces.
fn excluded_trace_paths(config: &AppConfig) -> Vec<String> {
    let mut paths = Vec::new();
    if config.health.enable {
        paths.push(normalize_route(&config.health.route));
    }
    if config.observability.self_metrics.enable {
        paths.push(normalize_route(&config.observability.self_metrics.route));
    }
    paths
}

fn normalize_route(route: &str) -> String {
    let trimmed = route.trim();
    if trimmed.starts_with('/') {
        trimmed.to_owned()
    } else {
        format!("/{trimmed}")
    }
}

fn init_console_only(logger: &LoggerConfig) {
    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new(logger.level.clone()));
    let subscriber = tracing_subscriber::registry().with(filter);
    match logger.format {
        LogFormat::Json => subscriber
            .with(tracing_subscriber::fmt::layer().json())
            .init(),
        LogFormat::Pretty => subscriber
            .with(tracing_subscriber::fmt::layer().pretty())
            .init(),
        LogFormat::Compact => subscriber.with(tracing_subscriber::fmt::layer()).init(),
    }
}
