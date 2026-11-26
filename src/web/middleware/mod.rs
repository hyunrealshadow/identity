use std::{net::IpAddr, sync::Arc};

use async_trait::async_trait;
use http::{HeaderValue, StatusCode, header, header::HeaderName};
use identity_application::audit::{self, AuditRequestContext};
use identity_domain::openid_connect::{
    AuthenticatedWorkload, BuiltInWorkload, WorkloadAuthenticator,
};
use identity_infrastructure::observability::context::{
    self as trace_context, ParentDecision, TraceTrustPolicy,
};
use ipnet::IpNet;
use opentelemetry::trace::Status;
use salvo::{Depot, FlowCtrl, Handler, Request, Response, handler};
use tracing::{Instrument, field::Empty, info_span};
use tracing_opentelemetry::OpenTelemetrySpanExt;
use uuid::Uuid;

use crate::{application::error::codes::common, controllers::response::write_error_response};

/// Correlation is assigned before parsing the body and exists even without an
/// OTel subscriber or sampling. Trace IDs are included only for valid spans.
pub use identity_infrastructure::observability::context::RequestCorrelation;

mod workload;
pub use workload::*;
mod correlation;
pub use correlation::*;
mod network;
pub use network::*;
mod headers;
pub use headers::*;
#[cfg(test)]
mod tests;
