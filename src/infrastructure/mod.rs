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
            installation::{InstallationSetting, InstallationState},
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
    let installation_setting = setting::Model {
        id: 2,
        oid: uuid::Uuid::new_v4(),
        key: InstallationSetting::KEY.to_string(),
        value: serde_json::to_value(InstallationState {
            initialized: true,
            domain: Some("identity.example.com".to_owned()),
            first_user_oid: Some(uuid::Uuid::new_v4()),
            first_key_oid: Some(uuid::Uuid::new_v4()),
            initialized_at: Some(Utc::now()),
        })
        .unwrap(),
        created_at: Utc::now().naive_utc(),
        updated_at: None,
    };

    let db = MockDatabase::new(DatabaseBackend::Postgres)
        .append_query_results([[password_setting], [installation_setting]])
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
