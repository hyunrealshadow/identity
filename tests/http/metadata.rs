use http::StatusCode;
use salvo::{
    Service,
    affix_state::inject,
    test::{ResponseExt, TestClient},
};
use serde_json::{Value, from_str, json as json_json};

use identity_web::controllers::well_known::routes;

/// Build a test state whose scope catalog answers the production
/// `SELECT code ...` query shape.
async fn metadata_state() -> identity_infrastructure::AppState {
    runtime_state(None).await
}

pub(super) async fn runtime_state(console: Option<&str>) -> identity_infrastructure::AppState {
    use std::{collections::BTreeMap, sync::Arc};

    use chrono::Utc;
    use identity_application::setting::{
        ConsoleDomainSetting, DeviceAuthorizationSettings, DomainSetting, LoginDomainSetting,
        PasswordHashSetting, SettingDefinition,
    };
    use identity_infrastructure::{
        AppContext, AppLifecycle, AppResources, AppState,
        config::{AppEnvironment, HealthChecksConfig},
        database::entity::{key, key_jwk, setting},
        services::AppServices,
        settings::AppRuntimeSettings,
        web::tera::{build_i18n, build_tera},
    };
    use sea_orm::{DatabaseBackend, MockDatabase, Value as DbValue};
    use serde_json::to_value;
    use uuid::Uuid;

    let now = Utc::now();
    let password_setting = setting::Model {
        id: 1,
        oid: Uuid::new_v4(),
        key: PasswordHashSetting::KEY.to_string(),
        value: to_value(PasswordHashSetting::default_value()).unwrap(),
        created_at: now.into(),
        updated_at: None,
    };
    let installation_initialized_setting = setting::Model {
        id: 2,
        oid: Uuid::new_v4(),
        key: "app.installation.initialized".to_owned(),
        value: to_value(true).unwrap(),
        created_at: now.into(),
        updated_at: None,
    };
    let domain_setting = setting::Model {
        id: 3,
        oid: Uuid::new_v4(),
        key: DomainSetting::KEY.to_string(),
        value: to_value(if console.is_some() {
            "https://identity.example.com/tenant/"
        } else {
            "identity.example.com"
        })
        .unwrap(),
        created_at: now.into(),
        updated_at: None,
    };
    let installation_initialized_at_setting = setting::Model {
        id: 6,
        oid: Uuid::new_v4(),
        key: "app.installation.initialized_at".to_owned(),
        value: to_value(now).unwrap(),
        created_at: now.into(),
        updated_at: None,
    };
    let dynamic_registration_setting = setting::Model {
        id: 7,
        oid: Uuid::new_v4(),
        key: "openid_connect.dynamic_registration.enabled".to_owned(),
        value: to_value(false).unwrap(),
        created_at: now.into(),
        updated_at: None,
    };
    let device_authorization_setting = setting::Model {
        id: 10,
        oid: Uuid::new_v4(),
        key: "openid_connect.device_authorization".to_owned(),
        value: to_value(DeviceAuthorizationSettings::default()).unwrap(),
        created_at: now.into(),
        updated_at: None,
    };
    let login_domain_setting = setting::Model {
        id: 12,
        oid: Uuid::new_v4(),
        key: LoginDomainSetting::KEY.to_string(),
        value: to_value(console.map(|_| "https://login.example.com")).unwrap(),
        created_at: now.into(),
        updated_at: None,
    };

    let console_domain_setting = setting::Model {
        id: 13,
        oid: Uuid::new_v4(),
        key: ConsoleDomainSetting::KEY.to_owned(),
        value: to_value(console).unwrap(),
        created_at: now.into(),
        updated_at: None,
    };

    let db = MockDatabase::new(DatabaseBackend::Postgres)
        .append_query_results([[
            installation_initialized_setting,
            domain_setting,
            installation_initialized_at_setting,
            password_setting,
            dynamic_registration_setting,
            login_domain_setting,
            console_domain_setting,
            device_authorization_setting,
        ]])
        .append_query_results([Vec::<BTreeMap<String, DbValue>>::new()])
        .append_query_results([Vec::<key::Model>::new(), Vec::<key::Model>::new()])
        .append_query_results([Vec::<key_jwk::Model>::new(), Vec::<key_jwk::Model>::new()])
        .append_query_results([[
            BTreeMap::from([(
                "code".to_owned(),
                DbValue::String(Some("openid".to_owned())),
            )]),
            BTreeMap::from([(
                "code".to_owned(),
                DbValue::String(Some("profile".to_owned())),
            )]),
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

#[tokio::test]
async fn metadata_route_publishes_oauth_endpoints_and_omits_unset_fields() {
    let state = metadata_state().await;
    let service = Service::new(routes().hoop(inject(state)));
    let mut response =
        TestClient::get("http://127.0.0.1:5800/.well-known/oauth-authorization-server")
            .send(&service)
            .await;
    assert_eq!(response.status_code, Some(StatusCode::OK));
    let json: Value = from_str(&response.take_string().await.unwrap()).unwrap();
    assert!(
        json["introspection_endpoint"]
            .as_str()
            .unwrap()
            .ends_with("/oauth2/introspect")
    );
    assert!(
        json["revocation_endpoint"]
            .as_str()
            .unwrap()
            .ends_with("/oauth2/revoke")
    );
    assert_eq!(
        json["code_challenge_methods_supported"],
        json_json!(["S256"])
    );
    assert!(
        !json["introspection_endpoint_auth_methods_supported"]
            .as_array()
            .unwrap()
            .contains(&json_json!("none"))
    );
    assert!(json.get("registration_endpoint").is_none());
    assert!(json.get("id_token_signing_alg_values_supported").is_none());
    let response =
        TestClient::get("http://127.0.0.1:5800/.well-known/oauth-authorization-server/wrong")
            .send(&service)
            .await;
    assert_eq!(response.status_code, Some(StatusCode::NOT_FOUND));
}
