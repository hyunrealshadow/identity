//! Client address resolution, upstream HTTPS enforcement and the audit request context.

use super::*;

#[derive(Clone, Debug)]
pub struct RequireUpstreamHttps {
    trusted_proxies: Arc<[IpNet]>,
    direct_http_clients: Arc<[IpNet]>,
}

#[derive(Clone, Debug)]
pub struct ResolveClientIp {
    trusted_proxies: Arc<[IpNet]>,
}

#[derive(Clone, Copy, Debug)]
pub(super) struct ClientIp(Option<IpAddr>);

impl ResolveClientIp {
    #[must_use]
    pub fn new(trusted_proxies: &[IpNet], direct_http_clients: &[IpNet]) -> Self {
        Self {
            trusted_proxies: trusted_proxies
                .iter()
                .chain(direct_http_clients)
                .cloned()
                .collect(),
        }
    }
}

impl RequireUpstreamHttps {
    #[must_use]
    pub fn new(trusted_proxies: &[IpNet], direct_http_clients: &[IpNet]) -> Self {
        Self {
            trusted_proxies: trusted_proxies.into(),
            direct_http_clients: direct_http_clients.into(),
        }
    }

    pub(super) fn peer_is_trusted(&self, req: &Request) -> bool {
        req.remote_addr().ip().is_some_and(|peer| {
            self.trusted_proxies
                .iter()
                .any(|network| network.contains(&peer))
        })
    }

    pub(super) fn peer_can_use_direct_http(&self, req: &Request) -> bool {
        req.remote_addr().ip().is_some_and(|peer| {
            self.direct_http_clients
                .iter()
                .any(|network| network.contains(&peer))
        })
    }
}

#[async_trait]
impl Handler for ResolveClientIp {
    async fn handle(
        &self,
        req: &mut Request,
        depot: &mut Depot,
        res: &mut Response,
        ctrl: &mut FlowCtrl,
    ) {
        depot.insert_typed(ClientIp(resolve_client_ip(req, &self.trusted_proxies)));
        ctrl.call_next(req, depot, res).await;
    }
}

/// Makes the request's client address and User-Agent available to audit
/// records written while handling it. Runs after [`ResolveClientIp`].
#[handler]
pub async fn audit_request_context(
    req: &mut Request,
    depot: &mut Depot,
    res: &mut Response,
    ctrl: &mut FlowCtrl,
) {
    let context = AuditRequestContext {
        ip_address: depot
            .get_typed::<ClientIp>()
            .ok()
            .and_then(|client| client.0),
        user_agent: req
            .headers()
            .get(header::USER_AGENT)
            .and_then(|value| value.to_str().ok())
            .map(str::to_owned),
    };
    audit::with_request(context, ctrl.call_next(req, depot, res)).await;
}

#[must_use]
pub fn resolved_client_ip(depot: &Depot) -> Option<String> {
    depot
        .get_typed::<ClientIp>()
        .ok()
        .and_then(|client| client.0)
        .map(|address| address.to_string())
}

pub(super) fn resolve_client_ip(req: &Request, trusted_proxies: &[IpNet]) -> Option<IpAddr> {
    let peer = req.remote_addr().ip()?;
    if !trusted_proxies
        .iter()
        .any(|network| network.contains(&peer))
    {
        return Some(peer);
    }

    forwarded_client_ip(req).or(Some(peer))
}

pub(super) fn forwarded_client_ip(req: &Request) -> Option<IpAddr> {
    if let Some(address) = req
        .headers()
        .get("x-forwarded-for")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.split(',').next())
        .and_then(parse_forwarded_ip)
    {
        return Some(address);
    }

    req.headers()
        .get("x-real-ip")
        .and_then(|value| value.to_str().ok())
        .and_then(parse_forwarded_ip)
}

pub(super) fn parse_forwarded_ip(value: &str) -> Option<IpAddr> {
    let value = value.trim().trim_matches('"');
    let value = value
        .strip_prefix('[')
        .and_then(|value| value.strip_suffix(']'))
        .unwrap_or(value);
    value.parse().ok()
}

pub(super) fn forwarded_proto_is_https(req: &Request) -> bool {
    let x_forwarded_proto = req
        .headers()
        .get("x-forwarded-proto")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.split(',').next())
        .is_some_and(|value| value.trim().eq_ignore_ascii_case("https"));
    if x_forwarded_proto {
        return true;
    }

    req.headers()
        .get_all("forwarded")
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(',').next().into_iter())
        .flat_map(|value| value.split(';'))
        .filter_map(|parameter| parameter.trim().split_once('='))
        .any(|(name, value)| {
            name.eq_ignore_ascii_case("proto")
                && value.trim_matches('"').eq_ignore_ascii_case("https")
        })
}

#[async_trait]
impl Handler for RequireUpstreamHttps {
    async fn handle(
        &self,
        req: &mut Request,
        depot: &mut Depot,
        res: &mut Response,
        ctrl: &mut FlowCtrl,
    ) {
        if !self.peer_can_use_direct_http(req)
            && (!self.peer_is_trusted(req) || !forwarded_proto_is_https(req))
        {
            res.status_code(StatusCode::BAD_REQUEST);
            ctrl.skip_rest();
            return;
        }

        ctrl.call_next(req, depot, res).await;
    }
}
