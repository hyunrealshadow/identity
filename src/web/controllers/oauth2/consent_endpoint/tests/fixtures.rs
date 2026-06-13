use std::collections::BTreeMap;
use std::sync::Arc;

use base64::Engine;
use chrono::{Duration, Utc};
use identity_domain::{
    auth::{LoginStatus, SessionOid, SessionStatus, password::PasswordHashSetting},
    client_authorization::{
        AuthorizationInteractionState, ClientAuthorizationType, ConsentState, SelectionSource,
        StoredAuthorizationRequest,
    },
    key::{
        KeyData,
        material::{SymmetricKeyAlgorithm, SymmetricKeyData},
    },
    openid_connect::{AuthorizationRequestData, OpenIdConnectClientSettings},
    setting::{
        auth_ui::AuthUiEnabledSetting,
        dynamic_registration::DynamicClientRegistrationSetting,
        installation::{
            InstallationDomainSetting, InstallationFirstKeyOidSetting,
            InstallationFirstUserOidSetting, InstallationInitializedAtSetting,
            InstallationInitializedSetting,
        },
        model::SettingDefinition,
    },
};
use identity_infrastructure::{
    AppContext, AppLifecycle, AppResources, AppState,
    config::{
        AppConfig, AppEnvironment, DatabaseConfig, HealthChecksConfig, HealthConfig, LoggerConfig,
        ServerConfig, SettingsConfig,
    },
    services::AppServices,
    settings::AppRuntimeSettings,
    web::tera::{build_i18n, build_tera},
};
use sea_orm::{DatabaseBackend, MockDatabase, MockExecResult, Value};

use crate::infrastructure::database::entity::{
    client, client_authorization, client_open_id_connect, key, login, session, setting, user,
};

pub(super) fn consent_test_config() -> AppConfig {
    AppConfig {
        logger: LoggerConfig::default(),
        server: ServerConfig::default(),
        database: DatabaseConfig::default(),
        health: HealthConfig::default(),
        settings: SettingsConfig::default(),
        install: Default::default(),
    }
}

pub(super) async fn consent_test_state() -> (AppState, String, uuid::Uuid) {
    consent_test_state_with_scope("openid profile").await
}

pub(super) async fn consent_test_state_with_scope(scope: &str) -> (AppState, String, uuid::Uuid) {
    let now = Utc::now();
    let client_oid = uuid::Uuid::new_v4();
    let authorization_oid = uuid::Uuid::new_v4();
    let login_oid = uuid::Uuid::new_v4();
    let session_oid = uuid::Uuid::new_v4();
    let user_oid = uuid::Uuid::new_v4();
    let symmetric_key_oid = uuid::Uuid::new_v4();

    let password_setting = setting::Model {
        id: 1,
        oid: uuid::Uuid::new_v4(),
        key: PasswordHashSetting::KEY.to_string(),
        value: serde_json::to_value(PasswordHashSetting::default_value()).unwrap(),
        created_at: now.naive_utc(),
        updated_at: None,
    };
    let installation_initialized_setting = setting::Model {
        id: 2,
        oid: uuid::Uuid::new_v4(),
        key: InstallationInitializedSetting::KEY.to_string(),
        value: serde_json::to_value(true).unwrap(),
        created_at: now.naive_utc(),
        updated_at: None,
    };
    let installation_domain_setting = setting::Model {
        id: 3,
        oid: uuid::Uuid::new_v4(),
        key: InstallationDomainSetting::KEY.to_string(),
        value: serde_json::to_value("identity.example.com").unwrap(),
        created_at: now.naive_utc(),
        updated_at: None,
    };
    let installation_first_user_oid_setting = setting::Model {
        id: 4,
        oid: uuid::Uuid::new_v4(),
        key: InstallationFirstUserOidSetting::KEY.to_string(),
        value: serde_json::to_value(user_oid).unwrap(),
        created_at: now.naive_utc(),
        updated_at: None,
    };
    let installation_first_key_oid_setting = setting::Model {
        id: 5,
        oid: uuid::Uuid::new_v4(),
        key: InstallationFirstKeyOidSetting::KEY.to_string(),
        value: serde_json::to_value(symmetric_key_oid).unwrap(),
        created_at: now.naive_utc(),
        updated_at: None,
    };
    let installation_initialized_at_setting = setting::Model {
        id: 6,
        oid: uuid::Uuid::new_v4(),
        key: InstallationInitializedAtSetting::KEY.to_string(),
        value: serde_json::to_value(now).unwrap(),
        created_at: now.naive_utc(),
        updated_at: None,
    };
    let dynamic_registration_setting = setting::Model {
        id: 7,
        oid: uuid::Uuid::new_v4(),
        key: DynamicClientRegistrationSetting::KEY.to_string(),
        value: serde_json::to_value(DynamicClientRegistrationSetting::default_value()).unwrap(),
        created_at: now.naive_utc(),
        updated_at: None,
    };
    let auth_ui_enabled_setting = setting::Model {
        id: 8,
        oid: uuid::Uuid::new_v4(),
        key: AuthUiEnabledSetting::KEY.to_string(),
        value: serde_json::to_value(AuthUiEnabledSetting::default_value()).unwrap(),
        created_at: now.naive_utc(),
        updated_at: None,
    };

    let active_user = user::Model {
        id: 7,
        oid: user_oid,
        name: "Ada Lovelace".to_owned(),
        name_normalized: "ada lovelace".to_owned(),
        email: "ada@example.com".to_owned(),
        email_normalized: "ada@example.com".to_owned(),
        email_verified: true,
        phone_number: None,
        phone_number_verified: None,
        nickname: None,
        given_name: None,
        family_name: None,
        middle_name: None,
        profile: None,
        picture: None,
        website: None,
        gender: None,
        birthdate: None,
        zone_info: None,
        locale: None,
        address_formatted: None,
        address_street_address: None,
        address_locality: None,
        address_region: None,
        address_postal_code: None,
        address_country: None,
        failed_attempts: 0,
        enabled: true,
        locked: false,
        locked_until: None,
        created_at: now.into(),
        updated_at: None,
    };
    let active_session = session::Model {
        id: 11,
        oid: session_oid,
        user_id: active_user.id,
        status: SessionStatus::ACTIVE.to_owned(),
        acr: None,
        acr_expires_at: None,
        device_name: None,
        device_type: None,
        os_name: None,
        os_version: None,
        browser_name: None,
        browser_version: None,
        user_agent: None,
        ip_address: None,
        country: None,
        city: None,
        last_active_at: now.into(),
        expires_at: (now + Duration::days(7)).into(),
        revoked_at: None,
        created_at: now.into(),
        updated_at: None,
    };
    let client_model = client::Model {
        id: 17,
        oid: client_oid,
        protocol: "openid_connect".to_owned(),
        name: "Conformance RP".to_owned(),
        names: None,
        description: Some("OIDC relying party".to_owned()),
        created_at: now.naive_utc(),
        updated_at: None,
    };
    let authorization_request = StoredAuthorizationRequest {
        request: AuthorizationRequestData {
            response_type: "code".to_owned(),
            response_mode: None,
            client_id: client_oid.to_string(),
            redirect_uri: "https://client.example.com/callback".to_owned(),
            scope: scope.to_owned(),
            state: "state-123".to_owned(),
            nonce: None,
            prompt: None,
            max_age: None,
            login_hint: None,
            code_challenge: None,
            code_challenge_method: None,
            acr_values: None,
            claims: None,
        },
        interaction: AuthorizationInteractionState {
            selected_session_oid: Some(SessionOid(session_oid)),
            selected_protected_session_id: None,
            selected_user_oid: Some(user_oid.to_string()),
            selection_source: Some(SelectionSource::FreshLogin),
            consent_state: ConsentState::Pending,
            consent_decided_at: None,
        },
    };
    let authorization_model = client_authorization::Model {
        id: 23,
        oid: authorization_oid,
        client_id: client_model.id,
        r#type: ClientAuthorizationType::AuthorizationRequest.to_string(),
        data: serde_json::to_value(authorization_request).unwrap(),
        expires_at: (now + Duration::minutes(10)).into(),
        completed_at: None,
        revoked_at: None,
        created_at: now.into(),
        updated_at: Some(now.into()),
    };
    let login_model = login::Model {
        id: 29,
        oid: login_oid,
        client_id: client_model.id,
        client_authorization_id: authorization_model.id,
        session_id: None,
        user_id: None,
        status: LoginStatus::CREATED.to_owned(),
        failure_reason: None,
        failed_attempts: 0,
        acr: None,
        requested_acr: None,
        created_at: now.into(),
        updated_at: None,
    };
    let oidc_metadata_model = client_open_id_connect::Model {
        id: 31,
        client_id: client_model.id,
        post_logout_redirect_uris: None,
        frontchannel_logout_uri: None,
        frontchannel_logout_session_required: None,
        backchannel_logout_uri: None,
        backchannel_logout_session_required: None,
        response_types: None,
        grant_types: None,
        contacts: None,
        logo_uri: None,
        client_uri: Some("https://client.example.com".to_owned()),
        policy_uri: None,
        tos_uri: None,
        sector_identifier_uri: None,
        subject_type: None,
        id_token_signed_response_alg: None,
        id_token_encrypted_response_alg: None,
        id_token_encrypted_response_enc: None,
        userinfo_signed_response_alg: None,
        userinfo_encrypted_response_alg: None,
        userinfo_encrypted_response_enc: None,
        request_object_signing_alg: None,
        request_object_encryption_alg: None,
        request_object_encryption_enc: None,
        token_endpoint_auth_method: None,
        token_endpoint_auth_signing_alg: None,
        default_max_age: None,
        require_auth_time: None,
        default_acr_values: None,
        initiate_login_uri: None,
        request_uris: None,
        settings: serde_json::to_value(OpenIdConnectClientSettings::default()).unwrap(),
        created_at: now.into(),
        updated_at: None,
    };
    let symmetric_key = key::Model {
        id: 37,
        oid: symmetric_key_oid,
        r#type: identity_domain::key::KeyType::Symmetric.to_string(),
        data: serde_json::to_value(KeyData::Symmetric(SymmetricKeyData {
            key: base64::engine::general_purpose::STANDARD.encode([0x42u8; 32]),
            algorithm: SymmetricKeyAlgorithm::XChaCha20Poly1305,
        }))
        .unwrap(),
        expires_at: (now + Duration::hours(1)).into(),
        revoked_at: None,
        created_at: now.naive_utc(),
        updated_at: None,
    };

    let openid_scope_row =
        BTreeMap::from([("name".to_owned(), Value::String(Some("openid".to_owned())))]);

    let db = MockDatabase::new(DatabaseBackend::Postgres)
        .append_query_results([[installation_initialized_setting]])
        .append_query_results([[installation_domain_setting]])
        .append_query_results([[installation_first_user_oid_setting]])
        .append_query_results([[installation_first_key_oid_setting]])
        .append_query_results([[installation_initialized_at_setting]])
        .append_query_results([[password_setting]])
        .append_query_results([[dynamic_registration_setting]])
        .append_query_results([[auth_ui_enabled_setting]])
        .append_query_results([[symmetric_key.clone()]])
        .append_query_results([[(active_session.clone(), active_user.clone())]])
        .append_query_results([[symmetric_key.clone()]])
        .append_query_results([[login_model.clone()]])
        .append_query_results([[client_model.clone()]])
        .append_query_results([[authorization_model.clone()]])
        .append_query_results([[(authorization_model.clone(), client_model.clone())]])
        .append_query_results([[(client_model.clone(), oidc_metadata_model.clone())]])
        .append_query_results([Vec::<
            crate::infrastructure::database::entity::client_platform::Model,
        >::new()])
        .append_query_results([[openid_scope_row.clone()]])
        .append_query_results([[(active_session.clone(), active_user.clone())]])
        .append_query_results([[symmetric_key.clone()]])
        .append_query_results([[login_model.clone()]])
        .append_query_results([[client_model.clone()]])
        .append_query_results([[authorization_model.clone()]])
        .append_query_results([[(authorization_model.clone(), client_model.clone())]])
        .append_query_results([[(client_model.clone(), oidc_metadata_model)]])
        .append_query_results([Vec::<
            crate::infrastructure::database::entity::client_platform::Model,
        >::new()])
        .append_query_results([[openid_scope_row]])
        .append_query_results([[symmetric_key]])
        .append_query_results([[login_model.clone()]])
        .append_query_results([[client_model.clone()]])
        .append_query_results([[authorization_model.clone()]])
        .append_query_results([[authorization_model]])
        .append_exec_results([MockExecResult {
            last_insert_id: 0,
            rows_affected: 1,
        }])
        .into_connection();

    let i18n = build_i18n().unwrap();
    let tera = build_tera(i18n.loader()).unwrap();
    let settings = Arc::new(AppRuntimeSettings::from_db(db.clone()).await.unwrap());
    let services = Arc::new(
        AppServices::from_db(db.clone(), settings.as_ref()).expect("services should build"),
    );

    let state = AppState::new(
        Arc::new(AppContext::new(
            AppEnvironment::Test,
            HealthChecksConfig::default(),
        )),
        Arc::new(AppResources::new(db, tera, i18n)),
        Arc::new(AppLifecycle::new()),
        settings,
        services,
    );

    let protected_login_id = state
        .services()
        .oidc_authorize()
        .encrypt_login_id(login_oid)
        .await
        .unwrap();

    (state, protected_login_id, session_oid)
}
