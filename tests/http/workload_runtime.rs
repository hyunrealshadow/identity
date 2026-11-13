use http::StatusCode;
use identity_infrastructure::{
    auth::workload::build_workload_authenticator,
    config::{AppConfig, StaticTokenConfig, WorkloadConfig, WorkloadsConfig},
};
use identity_web::router;
use salvo::{
    Service,
    test::{ResponseExt, TestClient},
};
use serde_json::{Value, json};

use super::metadata::{self, CONSOLE_CLIENT_ID};

const LOGIN_TOKEN: &str = "login-test-workload-credential-0123456789";
const CONSOLE_TOKEN: &str = "console-test-workload-credential-0123456789";

fn credentials(token: &str) -> WorkloadConfig {
    WorkloadConfig {
        static_tokens: vec![StaticTokenConfig {
            file: None,
            environment: None,
            token: Some(token.to_owned()),
        }],
        ..Default::default()
    }
}

async fn service(console_origin: Option<&str>) -> Service {
    let state = metadata::runtime_state(console_origin).await;
    let config: AppConfig = serde_json::from_value(json!({})).unwrap();
    let authenticator = build_workload_authenticator(&WorkloadsConfig {
        login: credentials(LOGIN_TOKEN),
        console: credentials(CONSOLE_TOKEN),
    })
    .unwrap();
    Service::new(router::internal_router(state, &config, authenticator))
}

#[tokio::test]
async fn console_workload_fetches_only_its_public_configuration() {
    let service = service(Some("https://login.example.com/console/")).await;
    let url = "http://localhost/internal/workloads/self/runtime-configuration";
    let mut response = TestClient::get(url)
        .add_header("Authorization", format!("Bearer {CONSOLE_TOKEN}"), true)
        .add_header("X-Request-Id", "console-startup-test", true)
        .send(&service)
        .await;
    assert_eq!(response.status_code, Some(StatusCode::OK));
    assert!(
        response
            .headers()
            .get("Cache-Control")
            .unwrap()
            .to_str()
            .unwrap()
            .contains("no-store")
    );
    assert_ne!(
        response.headers().get("X-Request-Id").unwrap(),
        "console-startup-test"
    );
    let config: Value = response.take_json().await.unwrap();
    assert_eq!(config["issuer"], "https://identity.example.com/tenant");
    assert_eq!(
        config["graphqlUrl"],
        "https://identity.example.com/tenant/graphql"
    );
    assert_eq!(
        config["redirectUri"],
        "https://login.example.com/console/callback"
    );
    assert_eq!(
        config["postLogoutRedirectUri"],
        "https://login.example.com/console/signed-out"
    );
    assert_eq!(config["accountUrl"], "https://login.example.com/account");
    assert_eq!(
        config["clientId"],
        identity_domain::openid_connect::identifier::client_id(
            uuid::Uuid::parse_str(CONSOLE_CLIENT_ID).unwrap()
        )
    );
    assert!(config.get("oauth_client").is_none());
    assert!(!config.to_string().contains("secret"));

    let response = TestClient::get("http://localhost/internal/installation/status")
        .add_header("Authorization", format!("Bearer {CONSOLE_TOKEN}"), true)
        .send(&service)
        .await;
    assert_eq!(response.status_code, Some(StatusCode::FORBIDDEN));
    let response = TestClient::post("http://localhost/internal/installation")
        .add_header("Authorization", format!("Bearer {CONSOLE_TOKEN}"), true)
        .body("{}")
        .send(&service)
        .await;
    assert_eq!(response.status_code, Some(StatusCode::FORBIDDEN));

    for token in [None, Some("wrong-token")] {
        let request = TestClient::get(url);
        let request = if let Some(token) = token {
            request.add_header("Authorization", format!("Bearer {token}"), true)
        } else {
            request
        };
        let response = request.send(&service).await;
        assert_eq!(response.status_code, Some(StatusCode::UNAUTHORIZED));
    }
    let response = TestClient::get(url)
        .add_header("Authorization", format!("Bearer {LOGIN_TOKEN}"), true)
        .send(&service)
        .await;
    assert_eq!(response.status_code, Some(StatusCode::NOT_FOUND));
}

#[tokio::test]
async fn console_bootstrap_is_unavailable_until_console_is_configured() {
    let service = service(None).await;
    let response =
        TestClient::get("http://localhost/internal/workloads/self/runtime-configuration")
            .add_header("Authorization", format!("Bearer {CONSOLE_TOKEN}"), true)
            .send(&service)
            .await;
    assert_eq!(response.status_code, Some(StatusCode::NOT_FOUND));
}
