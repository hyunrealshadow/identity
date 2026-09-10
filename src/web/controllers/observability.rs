use salvo::{Response, handler, writing::Text};

use identity_infrastructure::observability::metrics;

/// Independent self-metrics endpoint. Deliberately served from the internal,
/// workload-authenticated listener so it stays reachable when the collector or
/// the public stack is unhealthy. It must not depend on liveness checks.
#[handler]
pub async fn observability_metrics(res: &mut Response) {
    res.render(Text::Plain(metrics::global().render_prometheus()));
}
