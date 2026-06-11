use std::{collections::BTreeMap, sync::Arc};

use base64::Engine;
use chrono::{DateTime, Duration, Utc};
use identity_domain::{
    auth::{LoginStatus, SessionOid, password::PasswordHashSetting},
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
    config::{AppEnvironment, HealthChecksConfig},
    services::AppServices,
    settings::AppRuntimeSettings,
    web::tera::{build_i18n, build_tera},
};
use sea_orm::{DatabaseBackend, MockDatabase, MockExecResult, Value};

use crate::infrastructure::database::entity::{
    client, client_authorization, client_open_id_connect, client_platform, key, login, setting,
};

#[derive(Debug, Clone)]
pub(super) struct ContinueFixture {
    pub(super) selection: Option<(uuid::Uuid, uuid::Uuid)>,
    pub(super) active_session: Option<(uuid::Uuid, uuid::Uuid)>,
    pub(super) additional_active_sessions: Vec<(uuid::Uuid, uuid::Uuid, String, String)>,
    pub(super) use_selection_as_active_session: bool,
    pub(super) selection_source: Option<SelectionSource>,
    pub(super) prompt: Option<String>,
    pub(super) login_hint: Option<String>,
    pub(super) max_age: Option<i32>,
    pub(super) consent_state: ConsentState,
    pub(super) login_status: &'static str,
    pub(super) skip_consent: bool,
    pub(super) session_created_at: Option<DateTime<Utc>>,
    pub(super) authorization_expires_at: Option<DateTime<Utc>>,
    pub(super) authorization_completed_at: Option<DateTime<Utc>>,
}

impl Default for ContinueFixture {
    fn default() -> Self {
        Self {
            selection: None,
            active_session: None,
            additional_active_sessions: Vec::new(),
            use_selection_as_active_session: true,
            selection_source: None,
            prompt: None,
            login_hint: None,
            max_age: None,
            consent_state: ConsentState::Pending,
            login_status: LoginStatus::CREATED,
            skip_consent: false,
            session_created_at: None,
            authorization_expires_at: None,
            authorization_completed_at: None,
        }
    }
}

pub(super) async fn continue_state(
    fixture: ContinueFixture,
) -> (AppState, String, Option<uuid::Uuid>) {
    let now = Utc::now();
    let should_mock_auto_selection_write = fixture.selection.is_none()
        && (fixture.active_session.is_some() || !fixture.additional_active_sessions.is_empty())
        && fixture.max_age.is_none()
        && !matches!(fixture.prompt.as_deref(), Some("login" | "select_account"));
    let client_oid = uuid::Uuid::new_v4();
    let authorization_oid = uuid::Uuid::new_v4();
    let login_oid = uuid::Uuid::new_v4();
    let symmetric_key_oid = uuid::Uuid::new_v4();
    let selected_session_oid = fixture
        .selection
        .as_ref()
        .map(|(session_oid, _)| *session_oid);
    let selected_user_oid = fixture.selection.as_ref().map(|(_, user_oid)| *user_oid);
    let active_session_selection = if fixture.use_selection_as_active_session {
        fixture.active_session.or(fixture.selection)
    } else {
        fixture.active_session
    };
    let session_created_at = fixture.session_created_at.unwrap_or(now);
    let authorization_expires_at = fixture
        .authorization_expires_at
        .unwrap_or(now + Duration::minutes(10));

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
        value: serde_json::to_value(selected_user_oid.unwrap_or_else(uuid::Uuid::new_v4)).unwrap(),
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
    let client_model = client::Model {
        id: 17,
        oid: client_oid,
        protocol: "openid_connect".to_owned(),
        name: "Continue RP".to_owned(),
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
            scope: "openid".to_owned(),
            state: "state-123".to_owned(),
            nonce: None,
            prompt: fixture.prompt,
            max_age: fixture.max_age,
            login_hint: fixture.login_hint,
            code_challenge: None,
            code_challenge_method: None,
            acr_values: None,
            claims: None,
        },
        interaction: match (selected_session_oid, selected_user_oid) {
            (Some(session_oid), Some(user_oid)) => AuthorizationInteractionState {
                selected_session_oid: Some(SessionOid(session_oid)),
                selected_protected_session_id: None,
                selected_user_oid: Some(user_oid.to_string()),
                selection_source: fixture.selection_source.or(Some(SelectionSource::Auto)),
                consent_state: fixture.consent_state,
                consent_decided_at: None,
            },
            _ => AuthorizationInteractionState {
                consent_state: fixture.consent_state,
                ..AuthorizationInteractionState::default()
            },
        },
    };
    let authorization_model = client_authorization::Model {
        id: 23,
        oid: authorization_oid,
        client_id: client_model.id,
        r#type: ClientAuthorizationType::AuthorizationRequest.to_string(),
        data: serde_json::to_value(&authorization_request).unwrap(),
        expires_at: authorization_expires_at.into(),
        completed_at: fixture.authorization_completed_at.map(Into::into),
        revoked_at: None,
        created_at: now.into(),
        updated_at: Some(now.into()),
    };
    let authorization_code_model = client_authorization::Model {
        id: 53,
        oid: uuid::Uuid::new_v4(),
        client_id: client_model.id,
        r#type: ClientAuthorizationType::AuthorizationCode.to_string(),
        data: serde_json::json!({
            "scope": "openid",
            "nonce": null,
            "code_challenge": null,
            "code_challenge_method": null,
            "user_oid": selected_user_oid.unwrap_or_else(uuid::Uuid::new_v4).to_string(),
            "session_oid": selected_session_oid.unwrap_or_else(uuid::Uuid::new_v4).to_string(),
            "acr": null,
            "redirect_uri": "https://client.example.com/callback",
            "auth_time": selected_session_oid.map(|_| now.timestamp()),
            "claims": null,
        }),
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
        status: fixture.login_status.to_owned(),
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
        settings: serde_json::to_value(OpenIdConnectClientSettings {
            skip_consent: fixture.skip_consent,
            ..OpenIdConnectClientSettings::default()
        })
        .unwrap(),
        created_at: now.into(),
        updated_at: None,
    };
    let platform_model = client_platform::Model {
        id: 37,
        client_id: client_model.id,
        platform: "web".to_owned(),
        redirect_uris: Some(serde_json::json!(["https://client.example.com/callback"])),
        created_at: now.into(),
        updated_at: None,
    };
    let symmetric_key = key::Model {
        id: 41,
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

    let mut active_session_and_users = Vec::new();
    if let Some((session_oid, user_oid)) = active_session_selection {
        active_session_and_users.push((
            crate::infrastructure::database::entity::session::Model {
                id: 43,
                oid: session_oid,
                user_id: 47,
                status: identity_domain::auth::SessionStatus::ACTIVE.to_owned(),
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
                created_at: session_created_at.into(),
                updated_at: None,
            },
            crate::infrastructure::database::entity::user::Model {
                id: 47,
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
            },
        ));
    }

    for (index, (session_oid, user_oid, user_name, user_email)) in
        fixture.additional_active_sessions.into_iter().enumerate()
    {
        let id = 100_i64 + i64::try_from(index).unwrap();
        active_session_and_users.push((
            crate::infrastructure::database::entity::session::Model {
                id,
                oid: session_oid,
                user_id: id,
                status: identity_domain::auth::SessionStatus::ACTIVE.to_owned(),
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
                created_at: session_created_at.into(),
                updated_at: None,
            },
            crate::infrastructure::database::entity::user::Model {
                id,
                oid: user_oid,
                name: user_name,
                name_normalized: "normalized".to_owned(),
                email: user_email.clone(),
                email_normalized: user_email,
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
            },
        ));
    }

    let db = MockDatabase::new(DatabaseBackend::Postgres)
        .append_query_results([[installation_initialized_setting]])
        .append_query_results([[installation_domain_setting]])
        .append_query_results([[installation_first_user_oid_setting]])
        .append_query_results([[installation_first_key_oid_setting]])
        .append_query_results([[installation_initialized_at_setting]])
        .append_query_results([[password_setting]])
        .append_query_results([[dynamic_registration_setting]])
        .append_query_results([[symmetric_key.clone()]]);

    let db = db
        .append_query_results([[symmetric_key.clone()]])
        .append_query_results([[login_model.clone()]])
        .append_query_results([[client_model.clone()]])
        .append_query_results([[authorization_model.clone()]])
        .append_query_results([[(authorization_model.clone(), client_model.clone())]])
        .append_query_results([[(client_model.clone(), Some(oidc_metadata_model))]])
        .append_query_results([[platform_model]])
        .append_query_results([[BTreeMap::from([(
            "name".to_owned(),
            Value::String(Some("openid".to_owned())),
        )])]]);

    let db = if active_session_and_users.is_empty() {
        db.append_query_results([Vec::<(
            crate::infrastructure::database::entity::session::Model,
            crate::infrastructure::database::entity::user::Model,
        )>::new()])
    } else {
        db.append_query_results([active_session_and_users])
    };

    let db = if should_mock_auto_selection_write {
        db.append_query_results([[authorization_model.clone()]])
            .append_exec_results([MockExecResult {
                last_insert_id: 0,
                rows_affected: 1,
            }])
    } else {
        db
    };

    let db = db
        .append_query_results([[symmetric_key.clone()]])
        .append_query_results([[login_model]])
        .append_query_results([[client_model.clone()]])
        .append_query_results([[authorization_model.clone()]])
        .append_query_results([[(authorization_model.clone(), client_model.clone())]])
        .append_query_results([[client_model.clone()]])
        .append_query_results([[authorization_code_model]])
        .append_query_results([[symmetric_key]])
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

    (state, protected_login_id, selected_session_oid)
}

pub(super) async fn continue_test_state() -> (AppState, String) {
    let (state, protected_login_id, _) = continue_state(ContinueFixture::default()).await;
    (state, protected_login_id)
}

pub(super) async fn continue_selected_session_state() -> (AppState, String, uuid::Uuid) {
    let session_oid = uuid::Uuid::new_v4();
    let user_oid = uuid::Uuid::new_v4();
    let (state, protected_login_id, selected_session_oid) = continue_state(ContinueFixture {
        selection: Some((session_oid, user_oid)),
        ..ContinueFixture::default()
    })
    .await;
    (state, protected_login_id, selected_session_oid.unwrap())
}

pub(super) async fn continue_selected_session_with_prompt_state(
    prompt: &str,
) -> (AppState, String, uuid::Uuid) {
    let session_oid = uuid::Uuid::new_v4();
    let user_oid = uuid::Uuid::new_v4();
    let (state, protected_login_id, selected_session_oid) = continue_state(ContinueFixture {
        selection: Some((session_oid, user_oid)),
        prompt: Some(prompt.to_owned()),
        ..ContinueFixture::default()
    })
    .await;
    (state, protected_login_id, selected_session_oid.unwrap())
}

pub(super) async fn continue_selected_session_with_consent_state(
    consent_state: ConsentState,
) -> (AppState, String, uuid::Uuid) {
    let session_oid = uuid::Uuid::new_v4();
    let user_oid = uuid::Uuid::new_v4();
    let (state, protected_login_id, selected_session_oid) = continue_state(ContinueFixture {
        selection: Some((session_oid, user_oid)),
        consent_state,
        ..ContinueFixture::default()
    })
    .await;
    (state, protected_login_id, selected_session_oid.unwrap())
}

pub(super) async fn continue_selected_session_with_fixture(
    fixture: ContinueFixture,
) -> (AppState, String, uuid::Uuid) {
    let session_oid = uuid::Uuid::new_v4();
    let user_oid = uuid::Uuid::new_v4();
    let (state, protected_login_id, selected_session_oid) = continue_state(ContinueFixture {
        selection: Some((session_oid, user_oid)),
        ..fixture
    })
    .await;
    (state, protected_login_id, selected_session_oid.unwrap())
}
