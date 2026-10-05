use crate::config::HealthChecksConfig;
use crate::database::entity::setting;
use crate::services::AppServices;
use crate::settings::AppRuntimeSettings;
use crate::web::tera::build_i18n;
use crate::web::tera::build_tera;
use chrono::Utc;
use identity_application::setting::DeviceAuthorizationSettings;
use identity_application::setting::DomainSetting;
use identity_application::setting::LoginDomainSetting;
use identity_application::setting::PasswordHashSetting;
use identity_application::setting::SettingDefinition;
use sea_orm::DatabaseBackend;
use sea_orm::MockDatabase;
use sea_orm::Value;
use std::collections::BTreeMap;
use std::sync::Arc;
extern crate identity_application as application;
extern crate identity_domain as domain;
extern crate self as infrastructure;
use crate::infrastructure::database::entity::key::Model;
use crate::infrastructure::database::entity::key_jwk::Model as KeyJwkModel;
use uuid::Uuid;

pub mod auth;
pub mod config;
pub mod context;
pub mod crypto;
pub mod database;
pub mod graphql;
pub mod i18n;
pub mod jobs;
pub mod lifecycle;
pub mod observability;
pub mod openid_connect;
pub mod resources;
pub mod services;
pub mod settings;
pub mod state;
pub mod web;

pub use context::AppContext;
pub use lifecycle::AppLifecycle;
pub use resources::AppResources;
pub use state::AppState;

#[cfg(any(test, feature = "test-support"))]
pub async fn test_app_state_with_mock_settings() -> AppState {
    test_app_state_with_cors_origin(None).await
}

#[cfg(any(test, feature = "test-support"))]
pub async fn test_app_state_with_cors_origin(cors_origin: Option<&str>) -> AppState {
    test_app_state_with_environment_and_cors_origin(config::AppEnvironment::Test, cors_origin).await
}

#[cfg(any(test, feature = "test-support"))]
pub async fn test_app_state_with_environment(environment: config::AppEnvironment) -> AppState {
    test_app_state_with_environment_and_cors_origin(environment, None).await
}

#[cfg(any(test, feature = "test-support"))]
async fn test_app_state_with_environment_and_cors_origin(
    environment: config::AppEnvironment,
    cors_origin: Option<&str>,
) -> AppState {
    let password_setting = setting::Model {
        id: 1,
        oid: Uuid::new_v4(),
        key: PasswordHashSetting::KEY.to_string(),
        value: serde_json::to_value(PasswordHashSetting::default_value()).unwrap(),
        created_at: Utc::now().into(),
        updated_at: None,
    };
    let installation_initialized_setting = setting::Model {
        id: 2,
        oid: Uuid::new_v4(),
        key: "app.installation.initialized".to_owned(),
        value: serde_json::to_value(true).unwrap(),
        created_at: Utc::now().into(),
        updated_at: None,
    };
    let domain_setting = setting::Model {
        id: 3,
        oid: Uuid::new_v4(),
        key: DomainSetting::KEY.to_string(),
        value: serde_json::to_value("identity.example.com").unwrap(),
        created_at: Utc::now().into(),
        updated_at: None,
    };
    let installation_initialized_at_setting = setting::Model {
        id: 6,
        oid: Uuid::new_v4(),
        key: "app.installation.initialized_at".to_owned(),
        value: serde_json::to_value(Utc::now()).unwrap(),
        created_at: Utc::now().into(),
        updated_at: None,
    };
    let dynamic_registration_setting = setting::Model {
        id: 7,
        oid: Uuid::new_v4(),
        key: "openid_connect.dynamic_registration.enabled".to_owned(),
        value: serde_json::to_value(false).unwrap(),
        created_at: Utc::now().into(),
        updated_at: None,
    };
    let device_authorization_setting = setting::Model {
        id: 10,
        oid: Uuid::new_v4(),
        key: "openid_connect.device_authorization".to_owned(),
        value: serde_json::to_value(DeviceAuthorizationSettings::default()).unwrap(),
        created_at: Utc::now().into(),
        updated_at: None,
    };
    let login_domain_setting = setting::Model {
        id: 12,
        oid: Uuid::new_v4(),
        key: LoginDomainSetting::KEY.to_string(),
        value: serde_json::to_value(LoginDomainSetting::default_value()).unwrap(),
        created_at: Utc::now().into(),
        updated_at: None,
    };

    let cors_rows: Vec<BTreeMap<String, Value>> = cors_origin
        .into_iter()
        .map(|origin| {
            BTreeMap::from([("origin".to_owned(), Value::String(Some(origin.to_owned())))])
        })
        .collect();
    let db = MockDatabase::new(DatabaseBackend::Postgres)
        .append_query_results([[
            installation_initialized_setting,
            domain_setting,
            installation_initialized_at_setting,
            password_setting,
            dynamic_registration_setting,
            login_domain_setting,
            device_authorization_setting,
        ]])
        .append_query_results([cors_rows])
        .append_query_results([Vec::<Model>::new(), Vec::<Model>::new()])
        .append_query_results([Vec::<KeyJwkModel>::new(), Vec::<KeyJwkModel>::new()])
        .append_query_results([[
            BTreeMap::from([("name".to_owned(), Value::String(Some("openid".to_owned())))]),
            BTreeMap::from([("name".to_owned(), Value::String(Some("profile".to_owned())))]),
        ]])
        .into_connection();
    let i18n = build_i18n().unwrap();
    let tera = build_tera(i18n.loader()).unwrap();
    let settings = Arc::new(AppRuntimeSettings::from_db(db.clone()).await.unwrap());
    let services = Arc::new(
        AppServices::from_db(db.clone(), settings.as_ref()).expect("services should build"),
    );

    AppState::new(
        Arc::new(AppContext::new(environment, HealthChecksConfig::default())),
        Arc::new(AppResources::new(db, tera, i18n)),
        Arc::new(AppLifecycle::new()),
        settings,
        services,
    )
}
