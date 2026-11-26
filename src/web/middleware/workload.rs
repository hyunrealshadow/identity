//! Authenticating internal workload callers.

use super::*;

pub(super) fn render_workload_unauthorized(
    req: &Request,
    depot: &Depot,
    res: &mut Response,
    invalid_token: bool,
) {
    let challenge = if invalid_token {
        HeaderValue::from_static("Bearer realm=\"identity-internal\", error=\"invalid_token\"")
    } else {
        HeaderValue::from_static("Bearer realm=\"identity-internal\"")
    };
    res.headers_mut()
        .insert(header::WWW_AUTHENTICATE, challenge);
    write_error_response(
        res,
        depot,
        req.headers(),
        common::error::Unauthorized.into(),
    );
}

#[derive(Clone)]
pub struct RequireWorkload {
    authenticator: Arc<dyn WorkloadAuthenticator>,
}

impl RequireWorkload {
    #[must_use]
    pub fn new(authenticator: Arc<dyn WorkloadAuthenticator>) -> Self {
        Self { authenticator }
    }
}

#[async_trait]
impl Handler for RequireWorkload {
    async fn handle(
        &self,
        req: &mut Request,
        depot: &mut Depot,
        res: &mut Response,
        ctrl: &mut FlowCtrl,
    ) {
        let token = req
            .headers()
            .get(header::AUTHORIZATION)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.strip_prefix("Bearer "))
            .filter(|value| !value.is_empty());
        let Some(token) = token else {
            render_workload_unauthorized(req, depot, res, false);
            ctrl.skip_rest();
            return;
        };
        let Some(workload) = self.authenticator.authenticate(token).await else {
            render_workload_unauthorized(req, depot, res, true);
            ctrl.skip_rest();
            return;
        };
        depot.insert_typed(workload);
        ctrl.call_next(req, depot, res).await;
    }
}

/// The workload that the current internal API request was authenticated as.
#[must_use]
pub fn authenticated_workload(depot: &Depot) -> Option<AuthenticatedWorkload> {
    depot.get_typed::<AuthenticatedWorkload>().ok().copied()
}

/// Installation and operational controls belong to the Login workload.
#[handler]
pub async fn require_login_workload(
    req: &mut Request,
    depot: &mut Depot,
    res: &mut Response,
    ctrl: &mut FlowCtrl,
) {
    if authenticated_workload(depot) != Some(AuthenticatedWorkload(BuiltInWorkload::Login)) {
        write_error_response(res, depot, req.headers(), common::error::Forbidden.into());
        ctrl.skip_rest();
    }
}
