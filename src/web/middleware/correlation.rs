//! Request IDs and trusted trace context.

use super::*;

pub(super) fn valid_request_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
}

/// Assigns or validates a trusted `X-Request-ID` header for each request.
#[derive(Clone, Debug)]
pub struct RequestIdMiddleware {
    policy: TraceTrustPolicy,
}

impl RequestIdMiddleware {
    pub fn new(policy: TraceTrustPolicy) -> Self {
        Self { policy }
    }
}

#[async_trait]
impl Handler for RequestIdMiddleware {
    async fn handle(
        &self,
        req: &mut Request,
        depot: &mut Depot,
        res: &mut Response,
        ctrl: &mut FlowCtrl,
    ) {
        let request_id = req
            .headers()
            .get("x-request-id")
            .and_then(|value| value.to_str().ok())
            .filter(|value| {
                self.policy.trusts_request_id(req.remote_addr().ip()) && valid_request_id(value)
            })
            .map(str::to_owned)
            .unwrap_or_else(|| Uuid::new_v4().to_string());
        let correlation = RequestCorrelation {
            request_id: request_id.clone(),
            trace_id: None,
        };
        depot.insert_typed(correlation.clone());
        trace_context::with_request_correlation(correlation, ctrl.call_next(req, depot, res)).await;
        if let Ok(value) = HeaderValue::from_str(&request_id) {
            res.headers_mut().insert("x-request-id", value);
        }
    }
}

/// Extracts W3C trace context, decides whether it may be continued and wraps
/// the rest of the request in a server span. Invalid headers never fail the
/// request; untrusted contexts become links instead of parents.
#[derive(Clone, Debug)]
pub struct TraceContextMiddleware {
    policy: TraceTrustPolicy,
}

impl TraceContextMiddleware {
    #[must_use]
    pub fn new(policy: TraceTrustPolicy) -> Self {
        Self { policy }
    }
}

#[async_trait]
impl Handler for TraceContextMiddleware {
    async fn handle(
        &self,
        req: &mut Request,
        depot: &mut Depot,
        res: &mut Response,
        ctrl: &mut FlowCtrl,
    ) {
        let extracted = trace_context::extract(req.headers());
        let peer = req.remote_addr().ip();
        let request_id = depot
            .get_typed::<RequestCorrelation>()
            .ok()
            .map(|value| value.request_id.clone())
            .unwrap_or_else(|| {
                req.headers()
                    .get("x-request-id")
                    .and_then(|value| value.to_str().ok())
                    .filter(|value| self.policy.trusts_request_id(peer) && valid_request_id(value))
                    .map(str::to_owned)
                    .unwrap_or_else(|| Uuid::new_v4().to_string())
            });
        // Only a verified workload identity counts as trust; the authenticated
        // subject of a user-facing request does not.
        let verified_workload = depot.get_typed::<AuthenticatedWorkload>().is_ok();
        let trusted = self.policy.trusts_inbound(peer, verified_workload);
        let decision = extracted.parent_decision(trusted);

        let method = req.method().as_str().to_owned();
        let path = req.uri().path().to_owned();
        let client_address = peer.map(|ip| ip.to_string()).unwrap_or_default();
        let span = info_span!(
            parent: None,
            "http.server",
            otel.kind = "server",
            http.request.method = %method,
            url.path = %path,
            client.address = %client_address,
            request.id = %request_id,
            http.route = Empty,
            http.response.status_code = Empty,
        );
        match decision {
            ParentDecision::ContinueInbound(parent) => {
                let _ = span.set_parent(parent);
            }
            ParentDecision::NewTraceWithLink(span_context) => span.add_link(span_context),
            ParentDecision::NewTrace => {}
        }

        let request_span = span.clone();
        async {
            let trace_id = trace_context::current_span_context()
                .filter(|context| context.is_valid())
                .map(|context| context.trace_id().to_string());
            let correlation = RequestCorrelation {
                request_id: request_id.clone(),
                trace_id: trace_id.clone(),
            };
            depot.insert_typed(correlation.clone());
            trace_context::with_request_correlation(correlation, ctrl.call_next(req, depot, res))
                .await;
            if let Ok(value) = HeaderValue::from_str(&request_id) {
                res.headers_mut().insert("x-request-id", value);
            }
            if let Some(trace_id) = trace_id.and_then(|id| HeaderValue::from_str(&id).ok()) {
                res.headers_mut().insert("x-trace-id", trace_id);
            } else {
                res.headers_mut().remove("x-trace-id");
            }
        }
        .instrument(span)
        .await;

        request_span.record("http.route", req.matched_path());
        if let Some(status) = res.status_code {
            request_span.record("http.response.status_code", status.as_u16());
            if status.is_server_error() {
                request_span.set_status(Status::error(
                    status
                        .canonical_reason()
                        .unwrap_or("server error")
                        .to_owned(),
                ));
            } else {
                request_span.set_status(Status::Ok);
            }
        }
    }
}
