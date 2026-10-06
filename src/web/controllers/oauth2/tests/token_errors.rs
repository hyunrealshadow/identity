use http::{StatusCode, header};
use identity_infrastructure::test_app_state_with_mock_settings;
use salvo::{
    Service,
    affix_state::inject,
    test::{ResponseExt, TestClient},
};
use serde_json::{Value, from_str};

use super::super::routes;

#[tokio::test]
async fn inspection_and_revocation_preserve_client_errors_and_endpoint_challenges() {
    let state = test_app_state_with_mock_settings().await;
    let service = Service::new(routes().hoop(inject(state)));

    for endpoint in ["introspect", "revoke"] {
        for (credentials, body, status, code) in [
            (
                "Basic !!!",
                "token=unknown",
                StatusCode::UNAUTHORIZED,
                "invalid_client",
            ),
            // A malformed client identifier remains an authentication failure.
            (
                "Basic dGVzdDpzZWNyZXQ=",
                "token=unknown",
                StatusCode::UNAUTHORIZED,
                "invalid_client",
            ),
            // Conflicting authentication methods are rejected before service dispatch.
            (
                "Basic dGVzdDpzZWNyZXQ=",
                "token=unknown&client_secret=duplicate",
                StatusCode::BAD_REQUEST,
                "invalid_request",
            ),
        ] {
            let mut response = TestClient::post(format!("http://localhost/oauth2/{endpoint}"))
                .add_header(
                    header::CONTENT_TYPE,
                    "application/x-www-form-urlencoded",
                    true,
                )
                .add_header(header::ACCEPT, "text/html", true)
                .add_header(header::AUTHORIZATION, credentials, true)
                .body(body)
                .send(&service)
                .await;

            assert_eq!(response.status_code, Some(status), "{endpoint}: {body}");
            assert_eq!(
                response.headers().get(header::CACHE_CONTROL).unwrap(),
                "no-store"
            );
            assert_eq!(response.headers().get(header::PRAGMA).unwrap(), "no-cache");
            assert!(
                response
                    .headers()
                    .get(header::CONTENT_TYPE)
                    .unwrap()
                    .to_str()
                    .unwrap()
                    .starts_with("application/json")
            );
            if status == StatusCode::UNAUTHORIZED {
                assert_eq!(
                    response
                        .headers()
                        .get(header::WWW_AUTHENTICATE)
                        .unwrap()
                        .to_str()
                        .unwrap(),
                    format!("Basic realm=\"oauth2/{endpoint}\"")
                );
            } else {
                assert!(response.headers().get(header::WWW_AUTHENTICATE).is_none());
            }
            let body: Value = from_str(&response.take_string().await.unwrap()).unwrap();
            assert_eq!(body["error"], code);
        }
    }
}
