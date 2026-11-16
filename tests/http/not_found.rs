//! Requests nothing serves are answered by the production service: HTML for
//! browsers, the JSON error body otherwise, with real correlation headers.
use http::{StatusCode, header};
use identity_infrastructure::config::AppConfig;
use salvo::test::{ResponseExt, TestClient};
use serde_json::Value;

use identity_web::router::app_router;

use super::metadata::runtime_state;

const NOT_FOUND_CODE: u64 = 10005;

fn config() -> AppConfig {
    AppConfig {
        internal: Default::default(),
        logger: Default::default(),
        server: Default::default(),
        database: Default::default(),
        health: Default::default(),
        graphql: Default::default(),
        console: Default::default(),
        observability: Default::default(),
        openid_connect: Default::default(),
        settings: Default::default(),
        install: Default::default(),
    }
}

async fn service() -> salvo::Service {
    app_router(runtime_state(None).await, &config())
}

fn content_type(response: &salvo::Response) -> &str {
    response
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default()
}

#[tokio::test]
async fn unknown_paths_answer_json_unless_html_is_accepted() {
    let service = service().await;

    let mut json = TestClient::get("http://identity.test/no/such/route")
        .add_header(header::ACCEPT, "application/json", true)
        .send(&service)
        .await;
    assert_eq!(json.status_code, Some(StatusCode::NOT_FOUND));
    assert!(content_type(&json).starts_with("application/json"));
    let request_id = json
        .headers()
        .get("x-request-id")
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned);
    assert!(request_id.is_some(), "the request middleware ran");
    let body: Value = json.take_json().await.unwrap();
    assert_eq!(body["error"]["code"], NOT_FOUND_CODE);
    assert!(
        body["error"]["message"]
            .as_str()
            .is_some_and(|message| !message.is_empty())
    );

    let mut html = TestClient::get("http://identity.test/no/such/route")
        .add_header(header::ACCEPT, "text/html,application/xhtml+xml", true)
        .add_header(header::ACCEPT_LANGUAGE, "zh-CN", true)
        .send(&service)
        .await;
    assert_eq!(html.status_code, Some(StatusCode::NOT_FOUND));
    assert!(content_type(&html).starts_with("text/html"));
    let request_id = html
        .headers()
        .get("x-request-id")
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned)
        .unwrap();
    let page = html.take_string().await.unwrap();
    assert!(page.contains("E10005"), "{page}");
    assert!(
        page.contains(&request_id),
        "the page shows this request's ID"
    );
}

#[tokio::test]
async fn the_root_path_is_not_found_for_any_method() {
    let service = service().await;

    let response = TestClient::post("http://identity.test/")
        .add_header(header::ACCEPT, "application/json", true)
        .send(&service)
        .await;

    assert_eq!(response.status_code, Some(StatusCode::NOT_FOUND));
}

#[tokio::test]
async fn missing_static_files_get_the_same_answer() {
    let service = service().await;

    let mut response = TestClient::get("http://identity.test/static/css/missing.css")
        .add_header(header::ACCEPT, "*/*", true)
        .send(&service)
        .await;

    assert_eq!(response.status_code, Some(StatusCode::NOT_FOUND));
    let body: Value = response.take_json().await.unwrap();
    assert_eq!(body["error"]["code"], NOT_FOUND_CODE);
}

#[tokio::test]
async fn a_known_path_with_another_method_stays_method_not_allowed() {
    let service = service().await;

    let response = TestClient::get("http://identity.test/oauth2/token")
        .add_header(header::ACCEPT, "application/json", true)
        .send(&service)
        .await;

    assert_eq!(response.status_code, Some(StatusCode::METHOD_NOT_ALLOWED));
}
