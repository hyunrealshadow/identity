//! First-install bootstrap with real settings, credentials and client registration.
mod common;
#[path = "support/login_installer.rs"]
mod login_installer;

use std::sync::Arc;

use http::StatusCode;
use identity_application::setting::{BreachedPasswordCheckEnabledSetting, SettingChanges};
use identity_infrastructure::{
    AppContext, AppLifecycle, AppResources, AppState,
    auth::workload::build_workload_authenticator,
    config::{
        AppConfig, AppEnvironment, HealthChecksConfig, StaticTokenConfig, WorkloadConfig,
        WorkloadsConfig,
    },
    database::{repository::setting::write_settings, seed},
    services::AppServices,
    settings::AppRuntimeSettings,
    web::tera::{build_i18n, build_tera},
};
use salvo::{
    Service,
    test::{ResponseExt, TestClient},
};
use sea_orm::{ConnectionTrait, DbBackend, Statement};
use serde_json::{Value, json};

#[tokio::test]
#[ignore = "requires explicitly configured PostgreSQL test database"]
async fn installation_persists_same_origin_console_path_and_bootstraps_both_workloads() {
    common::isolated(|db| async move {
        seed::run_all(&db).await.unwrap();
        // This test exercises local installation, not the external password service.
        write_settings(&db, SettingChanges::default()
            .set::<BreachedPasswordCheckEnabledSetting>(&false).unwrap()).await.unwrap();
        let settings = Arc::new(AppRuntimeSettings::from_db(db.clone()).await.unwrap());
        let services = Arc::new(AppServices::from_db(db.clone(), settings.as_ref()).unwrap());
        let i18n = build_i18n().unwrap();
        identity_infrastructure::i18n::init_error_i18n(i18n.clone());
        let state = AppState::new(
            Arc::new(AppContext::new(AppEnvironment::Test, HealthChecksConfig::default())),
            Arc::new(AppResources::new(db.clone(), build_tera(i18n.loader()).unwrap(), i18n)),
            Arc::new(AppLifecycle::new()), settings.clone(), services.clone());
        let login_token = "installation-login-workload-test-0123456789";
        let console_token = "installation-console-workload-test-0123456789";
        let credential = |token: &str| WorkloadConfig { static_tokens: vec![StaticTokenConfig {
            token: Some(token.to_owned()), file: None, environment: None,
        }], ..Default::default() };
        let authenticator = build_workload_authenticator(&WorkloadsConfig {
            login: credential(login_token), console: credential(console_token),
        }).unwrap();
        let config: AppConfig = serde_json::from_value(json!({})).unwrap();
        let app = Service::new(identity_web::router::internal_router(state.clone(), &config, authenticator.clone()));
        let runtime = "http://localhost/internal/workloads/self/runtime-configuration";
        let mut response = TestClient::get("http://localhost/internal/installation/status")
            .add_header("Authorization", format!("Bearer {login_token}"), true).send(&app).await;
        assert_eq!(response.take_json::<Value>().await.unwrap()["installed"], false);
        for token in [login_token, console_token] {
            let response = TestClient::get(runtime)
                .add_header("Authorization", format!("Bearer {token}"), true).send(&app).await;
            assert_eq!(response.status_code, Some(StatusCode::NOT_FOUND));
        }
        let install = json!({
            "username": "installverify-owner", "email": "invalid", "password": "Local!J7pV2zR9kM4xQ6s",
            "domain": "https://identity.example.test", "application_url": "https://identity.example.test",
            "console_url": "https://identity.example.test", "key_algorithm": "ecdsa-p256",
        });
        if let Ok(node) = std::env::var("IDENTITY_TEST_LOGIN_NODE") {
            login_installer::verify(&node,
                Service::new(identity_web::router::internal_router(state, &config, authenticator)),
                login_token, &install).await;
        } else {
        let mut response = TestClient::post("http://localhost/internal/installation")
            .add_header("Authorization", format!("Bearer {login_token}"), true)
            .add_header("Accept-Language", "zh-CN", true).json(&install).send(&app).await;
        assert!(response.status_code.unwrap().is_client_error());
        let error = response.take_string().await.unwrap();
        assert!(error.contains("邮箱"));
        assert!(!services.install().is_initialized());
        let mut install = install.clone();
        install["email"] = json!("installverify-owner@example.test");
        let mut response = TestClient::post("http://localhost/internal/installation")
            .add_header("Authorization", format!("Bearer {login_token}"), true)
            .json(&install).send(&app).await;
        let status = response.status_code;
        let body = response.take_string().await.unwrap();
        assert!(status.unwrap().is_success(), "{status:?}: {body}");
        }
        let mut response = TestClient::get(runtime)
            .add_header("Authorization", format!("Bearer {console_token}"), true).send(&app).await;
        assert_eq!(response.status_code, Some(StatusCode::OK));
        let console: Value = response.take_json().await.unwrap();
        assert_eq!(console["redirectUri"], "https://identity.example.test/console/callback");
        assert_eq!(console["postLogoutRedirectUri"], "https://identity.example.test/console/signed-out");
        assert_eq!(console["accountUrl"], "https://identity.example.test/account");
        assert!(console.get("oauth_client").is_none());
        let mut response = TestClient::get(runtime)
            .add_header("Authorization", format!("Bearer {login_token}"), true).send(&app).await;
        assert_eq!(response.status_code, Some(StatusCode::OK));
        let login: Value = response.take_json().await.unwrap();
        assert_eq!(login["applications"]["console_domain"], "https://identity.example.test/console/");
        assert!(login["oauth_client"]["client_secret"].as_str().is_some());
        let client = db.query_one_raw(Statement::from_string(DbBackend::Postgres,
            "SELECT o.post_logout_redirect_uris AS logout, p.redirect_uris AS redirects \
             FROM client c JOIN client_openid_connect o ON o.client_id=c.id \
             JOIN client_openid_connect_platform p ON p.client_id=c.id \
             WHERE c.oid='00000000-0000-0000-0000-0000000000c0'".to_owned()))
            .await.unwrap().unwrap();
        assert_eq!(client.try_get::<Value>("", "logout").unwrap(), json!(["https://identity.example.test/console/signed-out"]));
        assert!(client.try_get::<Value>("", "redirects").unwrap().to_string().contains("/console/callback"));
        // Reload from persisted rows, with no process public-address config.
        let reloaded = AppRuntimeSettings::from_db(db.clone()).await.unwrap();
        let restarted = AppServices::from_db(db.clone(), &reloaded).unwrap();
        assert_eq!(serde_json::to_value(restarted.console_runtime().runtime_config("test").unwrap().unwrap()).unwrap(), console);
        let response = TestClient::post("http://localhost/internal/installation")
            .add_header("Authorization", format!("Bearer {login_token}"), true)
            .json(&install).send(&app).await;
        assert!(response.status_code.unwrap().is_client_error(), "installation cannot run twice");
    }).await;
}
