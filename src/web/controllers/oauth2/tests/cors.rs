use http::{StatusCode, header};
use identity_infrastructure::test_app_state_with_cors_origin;
use salvo::{Service, affix_state::inject, test::TestClient};

use super::super::routes;

#[tokio::test]
async fn token_preflight_uses_cached_client_origin_but_authorization_does_not() {
    let state = test_app_state_with_cors_origin(Some("http://localhost:3000")).await;
    let service = Service::new(routes().hoop(inject(state)));

    let allowed = TestClient::options("http://127.0.0.1:5800/oauth2/token")
        .add_header(header::ORIGIN, "http://localhost:3000", true)
        .add_header(header::ACCESS_CONTROL_REQUEST_METHOD, "POST", true)
        .send(&service)
        .await;
    assert_eq!(allowed.status_code, Some(StatusCode::NO_CONTENT));
    assert_eq!(
        allowed
            .headers()
            .get(header::ACCESS_CONTROL_ALLOW_ORIGIN)
            .unwrap(),
        "http://localhost:3000"
    );
    assert!(
        allowed
            .headers()
            .get(header::ACCESS_CONTROL_ALLOW_CREDENTIALS)
            .is_none()
    );

    let actual = TestClient::post("http://127.0.0.1:5800/oauth2/token")
        .add_header(header::ORIGIN, "http://localhost:3000", true)
        .add_header(
            header::CONTENT_TYPE,
            "application/x-www-form-urlencoded",
            true,
        )
        .body("grant_type=unsupported")
        .send(&service)
        .await;
    assert_eq!(actual.status_code, Some(StatusCode::BAD_REQUEST));
    assert_eq!(
        actual
            .headers()
            .get(header::ACCESS_CONTROL_ALLOW_ORIGIN)
            .unwrap(),
        "http://localhost:3000"
    );

    let denied = TestClient::options("http://127.0.0.1:5800/oauth2/token")
        .add_header(header::ORIGIN, "https://other.example", true)
        .add_header(header::ACCESS_CONTROL_REQUEST_METHOD, "POST", true)
        .send(&service)
        .await;
    assert_eq!(denied.status_code, Some(StatusCode::FORBIDDEN));
    assert!(
        denied
            .headers()
            .get(header::ACCESS_CONTROL_ALLOW_ORIGIN)
            .is_none()
    );

    let authorize = TestClient::options("http://127.0.0.1:5800/oauth2/authorize")
        .add_header(header::ORIGIN, "http://localhost:3000", true)
        .add_header(header::ACCESS_CONTROL_REQUEST_METHOD, "GET", true)
        .send(&service)
        .await;
    assert!(
        authorize
            .headers()
            .get(header::ACCESS_CONTROL_ALLOW_ORIGIN)
            .is_none()
    );
}
