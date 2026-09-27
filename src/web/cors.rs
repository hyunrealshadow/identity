use async_trait::async_trait;
use http::{HeaderValue, Method, StatusCode, header};
use salvo::{Depot, FlowCtrl, Handler, Request, Response, handler};
use url::Url;

use crate::controllers::response::app_state;

const ALLOWED_HEADERS: &str = "authorization, content-type";

/// CORS for protocol endpoints accessed by browser clients. The authorization
/// endpoint deliberately does not install this handler.
pub struct ClientCors {
    methods: &'static str,
}

impl ClientCors {
    #[must_use]
    pub const fn new(methods: &'static str) -> Self {
        Self { methods }
    }
}

#[handler]
pub async fn preflight(res: &mut Response) {
    res.status_code(StatusCode::NO_CONTENT);
}

fn canonical_origin(raw: &str) -> Option<&str> {
    let url = Url::parse(raw).ok()?;
    if !matches!(url.scheme(), "http" | "https")
        || url.username() != ""
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
        || url.origin().ascii_serialization() != raw
    {
        return None;
    }
    Some(raw)
}

fn preflight_headers_allowed(raw: &str) -> bool {
    raw.split(',').all(|header| {
        matches!(
            header.trim().to_ascii_lowercase().as_str(),
            "authorization" | "content-type"
        )
    })
}

#[async_trait]
impl Handler for ClientCors {
    async fn handle(
        &self,
        req: &mut Request,
        depot: &mut Depot,
        res: &mut Response,
        ctrl: &mut FlowCtrl,
    ) {
        let origin = req
            .headers()
            .get(header::ORIGIN)
            .and_then(|value| value.to_str().ok())
            .and_then(canonical_origin)
            .map(str::to_owned);
        let allowed = origin.as_deref().is_some_and(|origin| {
            app_state(depot).is_ok_and(|state| state.settings().cors_origins().allows(origin))
        });

        if req.method() == Method::OPTIONS {
            res.headers_mut()
                .append(header::VARY, HeaderValue::from_static("Origin"));
            let requested_method = req
                .headers()
                .get(header::ACCESS_CONTROL_REQUEST_METHOD)
                .and_then(|value| value.to_str().ok());
            let method_allowed = requested_method.is_some_and(|method| {
                self.methods
                    .split(',')
                    .any(|allowed_method| allowed_method.trim() == method)
            });
            let headers_allowed = req
                .headers()
                .get(header::ACCESS_CONTROL_REQUEST_HEADERS)
                .and_then(|value| value.to_str().ok())
                .is_none_or(preflight_headers_allowed);
            if !(allowed && method_allowed && headers_allowed) {
                res.status_code(StatusCode::FORBIDDEN);
                ctrl.skip_rest();
                return;
            }
            res.headers_mut().insert(
                header::ACCESS_CONTROL_ALLOW_ORIGIN,
                HeaderValue::from_str(origin.as_deref().unwrap()).expect("validated Origin header"),
            );
            res.headers_mut().insert(
                header::ACCESS_CONTROL_ALLOW_METHODS,
                HeaderValue::from_static(self.methods),
            );
            res.headers_mut().insert(
                header::ACCESS_CONTROL_ALLOW_HEADERS,
                HeaderValue::from_static(ALLOWED_HEADERS),
            );
            res.headers_mut().insert(
                header::ACCESS_CONTROL_MAX_AGE,
                HeaderValue::from_static("30"),
            );
            res.status_code(StatusCode::NO_CONTENT);
            ctrl.skip_rest();
            return;
        }

        ctrl.call_next(req, depot, res).await;
        res.headers_mut()
            .append(header::VARY, HeaderValue::from_static("Origin"));
        if let Some(origin) = origin.as_deref().filter(|_| allowed) {
            res.headers_mut().insert(
                header::ACCESS_CONTROL_ALLOW_ORIGIN,
                HeaderValue::from_str(origin).expect("validated Origin header"),
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{canonical_origin, preflight_headers_allowed};

    #[test]
    fn accepts_only_canonical_http_origins() {
        assert_eq!(
            canonical_origin("https://client.example:8443"),
            Some("https://client.example:8443")
        );
        assert_eq!(
            canonical_origin("http://localhost:3000"),
            Some("http://localhost:3000")
        );
        for invalid in [
            "null",
            "https://client.example/",
            "https://client.example/path",
            "https://CLIENT.example",
            "https://client.example:443",
            "file://client",
        ] {
            assert!(canonical_origin(invalid).is_none(), "{invalid}");
        }
    }

    #[test]
    fn preflight_accepts_only_needed_headers() {
        assert!(preflight_headers_allowed("authorization, content-type"));
        assert!(preflight_headers_allowed("Content-Type"));
        assert!(!preflight_headers_allowed("authorization, cookie"));
    }
}
