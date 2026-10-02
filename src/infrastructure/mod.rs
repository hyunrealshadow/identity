extern crate identity_application as application;
extern crate identity_domain as domain;
extern crate self as infrastructure;

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
    use std::{collections::BTreeMap, sync::Arc};

    use chrono::Utc;
    use identity_application::setting::{
        DeviceAuthorizationSettings, DomainSetting, LoginDomainSetting, PasswordHashSetting,
        SettingDefinition,
    };
    use sea_orm::{DatabaseBackend, MockDatabase, Value};

    use crate::{
        config::{AppEnvironment, HealthChecksConfig},
        database::entity::setting,
        services::AppServices,
        settings::AppRuntimeSettings,
        web::tera::{build_i18n, build_tera},
    };

    let password_setting = setting::Model {
        id: 1,
        oid: uuid::Uuid::new_v4(),
        key: PasswordHashSetting::KEY.to_string(),
        value: serde_json::to_value(PasswordHashSetting::default_value()).unwrap(),
        created_at: Utc::now().into(),
        updated_at: None,
    };
    let installation_initialized_setting = setting::Model {
        id: 2,
        oid: uuid::Uuid::new_v4(),
        key: "app.installation.initialized".to_owned(),
        value: serde_json::to_value(true).unwrap(),
        created_at: Utc::now().into(),
        updated_at: None,
    };
    let domain_setting = setting::Model {
        id: 3,
        oid: uuid::Uuid::new_v4(),
        key: DomainSetting::KEY.to_string(),
        value: serde_json::to_value("identity.example.com").unwrap(),
        created_at: Utc::now().into(),
        updated_at: None,
    };
    let installation_initialized_at_setting = setting::Model {
        id: 6,
        oid: uuid::Uuid::new_v4(),
        key: "app.installation.initialized_at".to_owned(),
        value: serde_json::to_value(Utc::now()).unwrap(),
        created_at: Utc::now().into(),
        updated_at: None,
    };
    let dynamic_registration_setting = setting::Model {
        id: 7,
        oid: uuid::Uuid::new_v4(),
        key: "openid_connect.dynamic_registration.enabled".to_owned(),
        value: serde_json::to_value(false).unwrap(),
        created_at: Utc::now().into(),
        updated_at: None,
    };
    let device_authorization_setting = setting::Model {
        id: 10,
        oid: uuid::Uuid::new_v4(),
        key: "openid_connect.device_authorization".to_owned(),
        value: serde_json::to_value(DeviceAuthorizationSettings::default()).unwrap(),
        created_at: Utc::now().into(),
        updated_at: None,
    };
    let login_domain_setting = setting::Model {
        id: 12,
        oid: uuid::Uuid::new_v4(),
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
        .append_query_results([
            Vec::<crate::infrastructure::database::entity::key::Model>::new(),
            Vec::<crate::infrastructure::database::entity::key::Model>::new(),
        ])
        .append_query_results([
            Vec::<crate::infrastructure::database::entity::key_jwk::Model>::new(),
            Vec::<crate::infrastructure::database::entity::key_jwk::Model>::new(),
        ])
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
        Arc::new(AppContext::new(
            AppEnvironment::Test,
            HealthChecksConfig::default(),
        )),
        Arc::new(AppResources::new(db, tera, i18n)),
        Arc::new(AppLifecycle::new()),
        settings,
        services,
    )
}
