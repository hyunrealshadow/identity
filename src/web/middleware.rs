use http::{HeaderValue, header};
use salvo::{Depot, FlowCtrl, Request, Response, handler};

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

    use super::security_headers_middleware;

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
}
