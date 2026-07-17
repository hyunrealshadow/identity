use http::{HeaderValue, header};
use salvo::{Depot, FlowCtrl, Request, Response, handler};

fn forwarded_proto_is_https(req: &Request) -> bool {
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

#[handler]
pub async fn require_upstream_https_middleware(
    req: &mut Request,
    depot: &mut Depot,
    res: &mut Response,
    ctrl: &mut FlowCtrl,
) {
    if !forwarded_proto_is_https(req) {
        res.status_code(http::StatusCode::BAD_REQUEST);
        return;
    }

    ctrl.call_next(req, depot, res).await;
}

#[handler]
pub async fn security_headers_middleware(
    req: &mut Request,
    depot: &mut Depot,
    res: &mut Response,
    ctrl: &mut FlowCtrl,
) {
    let allows_framing = req.uri().path() == "/oauth2/check_session";
    ctrl.call_next(req, depot, res).await;
    let headers = res.headers_mut();
    headers.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    if !allows_framing {
        headers.insert(header::X_FRAME_OPTIONS, HeaderValue::from_static("DENY"));
    }
    headers.insert(
        header::HeaderName::from_static("x-xss-protection"),
        HeaderValue::from_static("0"),
    );
    headers.insert(
        header::REFERRER_POLICY,
        HeaderValue::from_static("strict-origin-when-cross-origin"),
    );
    headers
        .entry(header::HeaderName::from_static("content-security-policy"))
        .or_insert(HeaderValue::from_static("default-src 'self'"));
    headers.insert(
        header::STRICT_TRANSPORT_SECURITY,
        HeaderValue::from_static("max-age=31536000; includeSubDomains"),
    );
}

#[cfg(test)]
mod tests {
    use http::{StatusCode, header};
    use salvo::{Response, Router, Service, handler, test::TestClient};

    use super::{require_upstream_https_middleware, security_headers_middleware};

    #[handler]
    async fn ok(res: &mut Response) {
        res.status_code(StatusCode::OK);
    }

    #[tokio::test]
    async fn security_headers_skip_x_frame_options_for_check_session_iframe() {
        let service = Service::new(
            Router::new()
                .hoop(security_headers_middleware)
                .push(Router::with_path("oauth2/check_session").get(ok)),
        );

        let response = TestClient::get("http://127.0.0.1:5800/oauth2/check_session")
            .send(&service)
            .await;

        assert_eq!(response.status_code, Some(StatusCode::OK));
        assert!(response.headers().get(header::X_FRAME_OPTIONS).is_none());
    }

    #[tokio::test]
    async fn security_headers_deny_framing_for_regular_routes() {
        let service = Service::new(
            Router::new()
                .hoop(security_headers_middleware)
                .push(Router::with_path("login").get(ok)),
        );

        let response = TestClient::get("http://127.0.0.1:5800/login")
            .send(&service)
            .await;

        assert_eq!(
            response.headers().get(header::X_FRAME_OPTIONS).unwrap(),
            "DENY"
        );
    }

    #[tokio::test]
    async fn upstream_tls_rejects_requests_without_https_forwarding_metadata() {
        let service = Service::new(
            Router::new()
                .hoop(require_upstream_https_middleware)
                .push(Router::with_path("login").get(ok)),
        );

        let response = TestClient::get("http://127.0.0.1:5800/login")
            .send(&service)
            .await;

        assert_eq!(response.status_code, Some(StatusCode::BAD_REQUEST));
    }

    #[tokio::test]
    async fn upstream_tls_accepts_forwarded_https_requests() {
        let service = Service::new(
            Router::new()
                .hoop(require_upstream_https_middleware)
                .push(Router::with_path("login").get(ok)),
        );

        let response = TestClient::get("http://127.0.0.1:5800/login")
            .add_header("x-forwarded-proto", "https", true)
            .send(&service)
            .await;

        assert_eq!(response.status_code, Some(StatusCode::OK));
    }
}
