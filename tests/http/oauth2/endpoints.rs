use http::{StatusCode, header, header::CONTENT_TYPE};
use identity_infrastructure::{test_app_state_with_cors_origin, test_app_state_with_mock_settings};
use identity_web::controllers::oauth2::routes;
use salvo::{
    Service,
    affix_state::inject,
    test::{ResponseExt, TestClient},
};
use serde_json::{Value, from_str};
#[tokio::test]
async fn par_route_returns_protocol_errors_and_enforces_method_and_size() {
    let state = test_app_state_with_mock_settings().await;
    let service = Service::new(routes().hoop(inject(state)));
    for (body, status) in [
        ("client_id=".to_owned(), StatusCode::BAD_REQUEST),
        ("x".repeat(65537), StatusCode::PAYLOAD_TOO_LARGE),
    ] {
        let mut response = TestClient::post("http://localhost/oauth2/par")
            .add_header(
                header::CONTENT_TYPE,
                "application/x-www-form-urlencoded",
                true,
            )
            .text(body)
            .send(&service)
            .await;
        assert_eq!(response.status_code, Some(status));
        assert!(
            response
                .headers()
                .get(header::CACHE_CONTROL)
                .unwrap()
                .to_str()
                .unwrap()
                .contains("no-store")
        );
        let body: Value = response.take_json().await.unwrap();
        assert_eq!(body["error"], "invalid_request");
    }
    let response = TestClient::get("http://localhost/oauth2/par")
        .send(&service)
        .await;
    assert_eq!(response.status_code, Some(StatusCode::METHOD_NOT_ALLOWED));
    assert!(response.headers().contains_key(header::ALLOW));
}
#[tokio::test]
async fn device_authorization_route_requires_client_id() {
    let mut response = post_device_authorization("scope=openid".to_owned()).await;

    assert_eq!(response.status_code, Some(StatusCode::BAD_REQUEST));
    assert_eq!(
        response
            .headers()
            .get(header::CACHE_CONTROL)
            .and_then(|value| value.to_str().ok()),
        Some("no-store")
    );
    let body = response.take_string().await.unwrap();
    assert!(body.contains("\"invalid_request\""), "{body}");
}
#[tokio::test]
async fn token_route_dispatches_the_device_code_grant() {
    let app = routes().hoop(inject(test_app_state_with_mock_settings().await));
    let service = Service::new(app);
    let mut response = TestClient::post("http://127.0.0.1:5800/oauth2/token")
        .add_header(CONTENT_TYPE, "application/x-www-form-urlencoded", true)
        .body("grant_type=urn:ietf:params:oauth:grant-type:device_code&device_code=unknown")
        .send(&service)
        .await;

    assert_eq!(response.status_code, Some(StatusCode::BAD_REQUEST));
    let body = response.take_string().await.unwrap();
    assert!(body.contains("invalid_request"), "{body}");
}
#[tokio::test]
async fn introspection_route_requires_authentication_and_token() {
    let state = test_app_state_with_cors_origin(None).await;
    let service = Service::new(routes().hoop(inject(state)));
    let mut response = TestClient::post("http://127.0.0.1:5800/oauth2/introspect")
        .add_header(
            header::CONTENT_TYPE,
            "application/x-www-form-urlencoded",
            true,
        )
        .body("token=unknown&token_type_hint=unrecognized")
        .send(&service)
        .await;
    assert_eq!(response.status_code, Some(StatusCode::UNAUTHORIZED));
    assert_eq!(
        response.headers().get(header::CACHE_CONTROL).unwrap(),
        "no-store"
    );
    let json: Value = from_str(&response.take_string().await.unwrap()).unwrap();
    assert_eq!(json["error"], "invalid_client");
    let response = TestClient::post("http://127.0.0.1:5800/oauth2/introspect")
        .add_header(
            header::CONTENT_TYPE,
            "application/x-www-form-urlencoded",
            true,
        )
        .body("client_id=unknown")
        .send(&service)
        .await;
    assert_eq!(response.status_code, Some(StatusCode::BAD_REQUEST));
}
#[tokio::test]
async fn route_accepts_cors_preflight_and_returns_rfc_error_for_missing_client() {
    let state = test_app_state_with_cors_origin(Some("http://localhost:3000")).await;
    let service = Service::new(routes().hoop(inject(state)));
    let preflight = TestClient::options("http://127.0.0.1:5800/oauth2/revoke")
        .add_header(header::ORIGIN, "http://localhost:3000", true)
        .add_header(header::ACCESS_CONTROL_REQUEST_METHOD, "POST", true)
        .send(&service)
        .await;
    assert_eq!(preflight.status_code, Some(StatusCode::NO_CONTENT));
    assert_eq!(
        preflight
            .headers()
            .get(header::ACCESS_CONTROL_ALLOW_ORIGIN)
            .unwrap(),
        "http://localhost:3000"
    );

    let mut response = TestClient::post("http://127.0.0.1:5800/oauth2/revoke")
        .add_header(header::ORIGIN, "http://localhost:3000", true)
        .add_header(
            header::CONTENT_TYPE,
            "application/x-www-form-urlencoded",
            true,
        )
        .body("token=unknown&token_type_hint=refresh_token")
        .send(&service)
        .await;
    assert_eq!(response.status_code, Some(StatusCode::BAD_REQUEST));
    assert_eq!(
        response
            .headers()
            .get(header::ACCESS_CONTROL_ALLOW_ORIGIN)
            .unwrap(),
        "http://localhost:3000"
    );
    assert!(
        response
            .take_string()
            .await
            .unwrap()
            .contains("invalid_request")
    );
}

async fn post_device_authorization(body: String) -> salvo::Response {
    let service = Service::new(routes().hoop(inject(test_app_state_with_mock_settings().await)));
    TestClient::post("http://127.0.0.1:5800/oauth2/device")
        .add_header(
            header::CONTENT_TYPE,
            "application/x-www-form-urlencoded",
            true,
        )
        .body(body)
        .send(&service)
        .await
}
