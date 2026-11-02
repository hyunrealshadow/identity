use http::{StatusCode, header};
use identity_infrastructure::test_app_state_with_cors_origin;
use salvo::{
    Service,
    affix_state::inject,
    test::{ResponseExt, TestClient},
};
use serde_json::{Value, from_str};

use identity_web::controllers::oauth2::routes;

#[tokio::test]
async fn update_authentication_precedes_invalid_metadata() {
    let state = test_app_state_with_cors_origin(None).await;
    let service = Service::new(routes().hoop(inject(state)));
    let mut response =
        TestClient::put("http://localhost/oauth2/clients/11111111-1111-1111-1111-111111111111")
            .add_header(header::CONTENT_TYPE, "application/json", true)
            .body("{invalid-json")
            .send(&service)
            .await;

    assert_eq!(response.status_code, Some(StatusCode::UNAUTHORIZED));
    assert_eq!(
        response.headers().get(header::WWW_AUTHENTICATE).unwrap(),
        "Bearer error=\"invalid_token\""
    );
    let body: Value = from_str(&response.take_string().await.unwrap()).unwrap();
    assert_eq!(body["error"], "invalid_token");
}

#[tokio::test]
async fn management_routes_require_bearer_auth_and_support_preflight() {
    let state = test_app_state_with_cors_origin(Some("http://localhost:3000")).await;
    let service = Service::new(routes().hoop(inject(state)));
    let url = "http://127.0.0.1:5800/oauth2/clients/11111111-1111-1111-1111-111111111111";
    for (method, request) in [
        ("GET", TestClient::get(url)),
        ("PUT", TestClient::put(url)),
        ("DELETE", TestClient::delete(url)),
    ] {
        let mut response = request
            .add_header(header::ORIGIN, "http://localhost:3000", true)
            .send(&service)
            .await;
        assert_eq!(
            response.status_code,
            Some(StatusCode::UNAUTHORIZED),
            "{method}"
        );
        assert_eq!(
            response.headers().get(header::WWW_AUTHENTICATE).unwrap(),
            "Bearer error=\"invalid_token\""
        );
        assert_eq!(
            response
                .headers()
                .get(header::ACCESS_CONTROL_ALLOW_ORIGIN)
                .unwrap(),
            "http://localhost:3000"
        );
        let json: Value = from_str(&response.take_string().await.unwrap()).unwrap();
        assert_eq!(json["error"], "invalid_token");

        let response = TestClient::options(url)
            .add_header(header::ORIGIN, "http://localhost:3000", true)
            .add_header(header::ACCESS_CONTROL_REQUEST_METHOD, method, true)
            .add_header(
                header::ACCESS_CONTROL_REQUEST_HEADERS,
                "authorization, content-type",
                true,
            )
            .send(&service)
            .await;
        assert_eq!(
            response.status_code,
            Some(StatusCode::NO_CONTENT),
            "{method}"
        );
        assert_eq!(
            response
                .headers()
                .get(header::ACCESS_CONTROL_ALLOW_ORIGIN)
                .unwrap(),
            "http://localhost:3000"
        );
        assert!(
            response
                .headers()
                .get(header::ACCESS_CONTROL_ALLOW_METHODS)
                .unwrap()
                .to_str()
                .unwrap()
                .split(',')
                .any(|allowed| allowed.trim() == method),
            "{method}"
        );
    }
}

#[tokio::test]
async fn former_registration_management_path_is_not_routed() {
    let state = test_app_state_with_cors_origin(None).await;
    let service = Service::new(routes().hoop(inject(state)));
    let url = "http://localhost/oauth2/register/11111111-1111-1111-1111-111111111111";
    for request in [
        TestClient::get(url),
        TestClient::put(url),
        TestClient::delete(url),
    ] {
        let response = request.send(&service).await;
        assert_eq!(response.status_code, Some(StatusCode::NOT_FOUND));
    }
}
