//! Static asset caching and security response headers.

use super::*;

/// Whether a static file name carries the build's content hash
/// (`name.<16 hex>.ext`, as written by `pnpm build:error-css`).
pub(super) fn is_content_hashed(path: &str) -> bool {
    let file = path.rsplit('/').next().unwrap_or(path);
    let mut parts = file.rsplit('.');
    let (Some(_extension), Some(hash), Some(stem)) = (parts.next(), parts.next(), parts.next())
    else {
        return false;
    };
    !stem.is_empty()
        && hash.len() == 16
        && hash
            .bytes()
            .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
}

/// Cache content-hashed static files permanently: a new build gets a new
/// name. Anything else must be revalidated so a rebuilt file is not served
/// stale from a browser cache.
#[handler]
pub async fn static_cache_control(
    req: &mut Request,
    depot: &mut Depot,
    res: &mut Response,
    ctrl: &mut FlowCtrl,
) {
    let immutable = is_content_hashed(req.uri().path());
    ctrl.call_next(req, depot, res).await;
    if !res.status_code.unwrap_or(StatusCode::OK).is_success() {
        return;
    }
    let value = if immutable {
        HeaderValue::from_static("public, max-age=31536000, immutable")
    } else {
        HeaderValue::from_static("no-cache")
    };
    res.headers_mut().insert(header::CACHE_CONTROL, value);
}

#[handler]
pub async fn security_headers_middleware(
    req: &mut Request,
    depot: &mut Depot,
    res: &mut Response,
    ctrl: &mut FlowCtrl,
) {
    let allows_framing = req.uri().path() == "/openid/check_session";
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
        HeaderName::from_static("x-xss-protection"),
        HeaderValue::from_static("0"),
    );
    headers.insert(
        header::REFERRER_POLICY,
        HeaderValue::from_static("strict-origin-when-cross-origin"),
    );
    headers
        .entry(HeaderName::from_static("content-security-policy"))
        .or_insert(HeaderValue::from_static("default-src 'self'"));
    headers.insert(
        header::STRICT_TRANSPORT_SECURITY,
        HeaderValue::from_static("max-age=31536000; includeSubDomains"),
    );
}
