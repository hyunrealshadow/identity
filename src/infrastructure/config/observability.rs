use std::{fmt, fs};

use ipnet::IpNet;
use serde::Deserialize;

use super::{ConfigResult, default_true, invalid_config};

/// Observability pipeline configuration.
///
/// Trace trust, sampling, PII handling and OTLP delivery are configured here.
/// The console output level/format stays under [`super::LoggerConfig`].
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObservabilityConfig {
    #[serde(default = "default_true")]
    pub enable: bool,
    /// Force the human-readable console layer on or off. Defaults to on for
    /// non-production environments and off for production, where OTLP is the
    /// primary channel.
    #[serde(default)]
    pub console: Option<bool>,
    #[serde(default)]
    pub otlp: OtlpConfig,
    #[serde(default)]
    pub sampling: SamplingConfig,
    #[serde(default)]
    pub trace_context: TraceContextConfig,
    #[serde(default)]
    pub pii: PiiConfig,
    #[serde(default)]
    pub events: EventsPipelineConfig,
    #[serde(default)]
    pub diagnostics: DiagnosticsPipelineConfig,
    #[serde(default)]
    pub self_metrics: SelfMetricsConfig,
}

impl Default for ObservabilityConfig {
    fn default() -> Self {
        Self {
            enable: true,
            console: None,
            otlp: OtlpConfig::default(),
            sampling: SamplingConfig::default(),
            trace_context: TraceContextConfig::default(),
            pii: PiiConfig::default(),
            events: EventsPipelineConfig::default(),
            diagnostics: DiagnosticsPipelineConfig::default(),
            self_metrics: SelfMetricsConfig::default(),
        }
    }
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OtlpConfig {
    /// Export traces, logs and metrics to the collector. Disabled by default so
    /// development and test only need the console; deployments enable it and
    /// point [`Self::endpoint`] at the collector.
    #[serde(default)]
    pub enable: bool,
    /// Base OTLP/HTTP endpoint. `/v1/traces`, `/v1/logs` and `/v1/metrics` are
    /// appended automatically per signal.
    #[serde(default = "default_otlp_endpoint")]
    pub endpoint: String,
    #[serde(default = "default_otlp_timeout_ms")]
    pub timeout_ms: u64,
    #[serde(default)]
    pub compression: OtlpCompression,
}

impl Default for OtlpConfig {
    fn default() -> Self {
        Self {
            enable: false,
            endpoint: default_otlp_endpoint(),
            timeout_ms: default_otlp_timeout_ms(),
            compression: OtlpCompression::default(),
        }
    }
}

#[derive(Clone, Copy, Debug, Default, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum OtlpCompression {
    #[default]
    None,
    Gzip,
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SamplingConfig {
    /// Head sampling ratio for normal traces. `None` uses the environment
    /// default: 10% in production, 100% everywhere else.
    #[serde(default)]
    pub trace_ratio: Option<f64>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TraceContextConfig {
    /// Networks whose inbound `traceparent` may be continued. Trace trust is
    /// configured separately from proxy/IP trust and defaults to trusting
    /// nothing.
    #[serde(default)]
    pub trusted_gateways: Vec<IpNet>,
    /// Continue the inbound trace of requests authenticated as a verified
    /// workload (internal API). This is a service identity check, not a
    /// network position check.
    #[serde(default = "default_true")]
    pub trust_verified_workload: bool,
    /// Origins that may receive W3C trace context on outbound calls. Empty by
    /// default: arbitrary `request_uri`, JWKS or logout targets never inherit
    /// internal context.
    #[serde(default)]
    pub propagate_to_origins: Vec<String>,
}

impl Default for TraceContextConfig {
    fn default() -> Self {
        Self {
            trusted_gateways: Vec::new(),
            trust_verified_workload: true,
            propagate_to_origins: Vec::new(),
        }
    }
}

#[derive(Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PiiConfig {
    /// HMAC key used to pseudonymize PII fields that opt in with
    /// [`crate::observability::pii::Pii::pseudonymized`]. Without a key those
    /// fields fall back to `[REDACTED]`; raw values are never emitted.
    #[serde(default)]
    pub hmac_key: Option<SecretSourceConfig>,
    /// Key version included in pseudonymized output so rotations remain
    /// explicit in stored data.
    #[serde(default = "default_hmac_key_version")]
    pub hmac_key_version: String,
}

impl fmt::Debug for PiiConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PiiConfig")
            .field("hmac_key", &self.hmac_key.as_ref().map(|_| "[REDACTED]"))
            .field("hmac_key_version", &self.hmac_key_version)
            .finish()
    }
}

/// One-of file/environment/inline secret source.
#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SecretSourceConfig {
    #[serde(default)]
    pub file: Option<String>,
    #[serde(default)]
    pub environment: Option<String>,
    #[serde(default)]
    pub token: Option<String>,
}

impl fmt::Debug for SecretSourceConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SecretSourceConfig")
            .field("file", &self.file)
            .field("environment", &self.environment)
            .field("token", &self.token.as_ref().map(|_| "[REDACTED]"))
            .finish()
    }
}

impl SecretSourceConfig {
    #[must_use]
    pub fn has_exactly_one_source(&self) -> bool {
        [
            self.file.as_deref(),
            self.environment.as_deref(),
            self.token.as_deref(),
        ]
        .into_iter()
        .filter(|value| value.is_some_and(|value| !value.trim().is_empty()))
        .count()
            == 1
    }

    /// Resolve the secret bytes. The caller decides whether a missing secret is
    /// fatal or degrades to redaction.
    pub fn resolve(&self) -> ConfigResult<Option<Vec<u8>>> {
        if let Some(path) = self.file.as_deref().filter(|value| !value.is_empty()) {
            let raw = fs::read(path)?;
            return Ok(Some(raw));
        }
        if let Some(name) = self
            .environment
            .as_deref()
            .filter(|value| !value.is_empty())
        {
            return Ok(std::env::var(name).ok().map(String::into_bytes));
        }
        Ok(self
            .token
            .as_deref()
            .filter(|value| !value.is_empty())
            .map(|value| value.as_bytes().to_vec()))
    }
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EventsPipelineConfig {
    /// Bounded queue for key business events and audit records. Records are
    /// dropped instead of blocking when the queue is full.
    #[serde(default = "default_events_queue_capacity")]
    pub queue_capacity: usize,
    /// Approximate byte budget for the same queue.
    #[serde(default = "default_events_queue_bytes")]
    pub queue_bytes: usize,
}

impl Default for EventsPipelineConfig {
    fn default() -> Self {
        Self {
            queue_capacity: default_events_queue_capacity(),
            queue_bytes: default_events_queue_bytes(),
        }
    }
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DiagnosticsPipelineConfig {
    #[serde(default = "default_diagnostics_queue_capacity")]
    pub log_queue_capacity: usize,
    #[serde(default = "default_diagnostics_queue_capacity")]
    pub span_queue_capacity: usize,
    #[serde(default = "default_diagnostics_batch_size")]
    pub max_export_batch_size: usize,
    #[serde(default = "default_diagnostics_schedule_delay_ms")]
    pub schedule_delay_ms: u64,
    #[serde(default = "default_otlp_timeout_ms")]
    pub export_timeout_ms: u64,
}

impl Default for DiagnosticsPipelineConfig {
    fn default() -> Self {
        Self {
            log_queue_capacity: default_diagnostics_queue_capacity(),
            span_queue_capacity: default_diagnostics_queue_capacity(),
            max_export_batch_size: default_diagnostics_batch_size(),
            schedule_delay_ms: default_diagnostics_schedule_delay_ms(),
            export_timeout_ms: default_otlp_timeout_ms(),
        }
    }
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SelfMetricsConfig {
    /// Independent scrape endpoint for pipeline failures (drops, queue usage,
    /// export failures) that must stay observable when the collector is down.
    #[serde(default = "default_true")]
    pub enable: bool,
    #[serde(default = "default_self_metrics_route")]
    pub route: String,
}

impl Default for SelfMetricsConfig {
    fn default() -> Self {
        Self {
            enable: true,
            route: default_self_metrics_route(),
        }
    }
}

impl ObservabilityConfig {
    pub fn validate(&self) -> ConfigResult<()> {
        if self
            .sampling
            .trace_ratio
            .is_some_and(|ratio| !(0.0..=1.0).contains(&ratio))
        {
            return Err(invalid_config(
                "observability.sampling.trace_ratio must be between 0 and 1",
            )
            .into());
        }
        if self.otlp.enable && self.otlp.endpoint.trim().is_empty() {
            return Err(invalid_config(
                "observability.otlp.endpoint must not be empty when OTLP is enabled",
            )
            .into());
        }
        if self.otlp.enable && self.otlp.timeout_ms == 0 {
            return Err(invalid_config("observability.otlp.timeout_ms must be positive").into());
        }
        if self.events.queue_capacity == 0 || self.events.queue_bytes == 0 {
            return Err(
                invalid_config("observability.events queue limits must be positive").into(),
            );
        }
        if self.diagnostics.log_queue_capacity == 0 || self.diagnostics.span_queue_capacity == 0 {
            return Err(
                invalid_config("observability.diagnostics queue limits must be positive").into(),
            );
        }
        if self.diagnostics.max_export_batch_size == 0 {
            return Err(invalid_config(
                "observability.diagnostics.max_export_batch_size must be positive",
            )
            .into());
        }
        if self
            .pii
            .hmac_key
            .as_ref()
            .is_some_and(|source| !source.has_exactly_one_source())
        {
            return Err(invalid_config(
                "observability.pii.hmac_key must configure exactly one of file, environment, or token",
            )
            .into());
        }
        Ok(())
    }
}

fn default_otlp_endpoint() -> String {
    "http://127.0.0.1:4318".to_owned()
}

const fn default_otlp_timeout_ms() -> u64 {
    10_000
}

fn default_hmac_key_version() -> String {
    "v1".to_owned()
}

const fn default_events_queue_capacity() -> usize {
    8192
}

const fn default_events_queue_bytes() -> usize {
    16 * 1024 * 1024
}

const fn default_diagnostics_queue_capacity() -> usize {
    4096
}

const fn default_diagnostics_batch_size() -> usize {
    512
}

const fn default_diagnostics_schedule_delay_ms() -> u64 {
    5_000
}

fn default_self_metrics_route() -> String {
    "/internal/observability/metrics".to_owned()
}
