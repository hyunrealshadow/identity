extern crate identity_application as application;
extern crate identity_domain as domain;
extern crate self as infrastructure;

pub mod auth;
pub mod config;
pub mod context;
pub mod crypto;
pub mod database;
pub mod i18n;
pub mod lifecycle;
pub mod mailers;
pub mod observability;
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
    use std::sync::Arc;

    use chrono::Utc;
    use identity_domain::{
        auth::password::PasswordHashSetting,
        setting::{
            dynamic_registration::DynamicClientRegistrationSetting,
            installation::{
                InstallationDomainSetting, InstallationFirstKeyOidSetting,
                InstallationFirstUserOidSetting, InstallationInitializedAtSetting,
                InstallationInitializedSetting,
            },
            model::SettingDefinition,
        },
    };
    use sea_orm::{DatabaseBackend, MockDatabase};

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
        created_at: Utc::now().naive_utc(),
        updated_at: None,
    };
    let installation_initialized_setting = setting::Model {
        id: 2,
        oid: uuid::Uuid::new_v4(),
        key: InstallationInitializedSetting::KEY.to_string(),
        value: serde_json::to_value(true).unwrap(),
        created_at: Utc::now().naive_utc(),
        updated_at: None,
    };
    let installation_domain_setting = setting::Model {
        id: 3,
        oid: uuid::Uuid::new_v4(),
        key: InstallationDomainSetting::KEY.to_string(),
        value: serde_json::to_value("identity.example.com").unwrap(),
        created_at: Utc::now().naive_utc(),
        updated_at: None,
    };
    let installation_first_user_oid_setting = setting::Model {
        id: 4,
        oid: uuid::Uuid::new_v4(),
        key: InstallationFirstUserOidSetting::KEY.to_string(),
        value: serde_json::to_value(uuid::Uuid::new_v4()).unwrap(),
        created_at: Utc::now().naive_utc(),
        updated_at: None,
    };
    let installation_first_key_oid_setting = setting::Model {
        id: 5,
        oid: uuid::Uuid::new_v4(),
        key: InstallationFirstKeyOidSetting::KEY.to_string(),
        value: serde_json::to_value(uuid::Uuid::new_v4()).unwrap(),
        created_at: Utc::now().naive_utc(),
        updated_at: None,
    };
    let installation_initialized_at_setting = setting::Model {
        id: 6,
        oid: uuid::Uuid::new_v4(),
        key: InstallationInitializedAtSetting::KEY.to_string(),
        value: serde_json::to_value(Utc::now()).unwrap(),
        created_at: Utc::now().naive_utc(),
        updated_at: None,
    };
    let dynamic_registration_setting = setting::Model {
        id: 7,
        oid: uuid::Uuid::new_v4(),
        key: DynamicClientRegistrationSetting::KEY.to_string(),
        value: serde_json::to_value(DynamicClientRegistrationSetting::default_value()).unwrap(),
        created_at: Utc::now().naive_utc(),
        updated_at: None,
    };

    let db = MockDatabase::new(DatabaseBackend::Postgres)
        .append_query_results(vec![
            vec![installation_initialized_setting],
            vec![installation_domain_setting],
            vec![installation_first_user_oid_setting],
            vec![installation_first_key_oid_setting],
            vec![installation_initialized_at_setting],
            vec![password_setting],
            vec![dynamic_registration_setting],
        ])
        .into_connection();
    let i18n = build_i18n().unwrap();
    let tera = build_tera(i18n.loader()).unwrap();
    let settings = Arc::new(AppRuntimeSettings::from_db(db.clone()).await.unwrap());
    let services = Arc::new(AppServices::from_db(db.clone(), settings.as_ref()));

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
