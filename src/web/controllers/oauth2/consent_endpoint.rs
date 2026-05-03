use http::{HeaderMap, StatusCode, header};
use salvo::{Depot, Request, Response, handler};
use serde::Deserialize;

use crate::{
    application::error::{AppError, codes::authorize_http::AuthorizeHttpErrorCode},
    boot::AppState,
    domain::openid_connect::ScopeSet,
    infrastructure::web,
    web::controllers::{
        response::{
            AppResponse, app_state, json_response, parse_form, parse_json, parse_query,
            redirect_to_response, render_app_error, render_html,
        },
        shared::{csrf_token, load_active_sessions},
    },
    web::views::oauth2::{
        ConsentApiResponse, ConsentDecision, ConsentDecisionForm, ConsentDecisionPayload,
        ConsentPageData, build_scope_display,
    },
};

use super::{authorize_interaction::select_active_session, inline_script_csp_header_value};

#[derive(Debug, Deserialize)]
struct ConsentQuery {
    login_id: String,
}

fn accepts_json(accept: Option<&str>) -> bool {
    accept
        .map(|value| {
            value
                .split(',')
                .map(str::trim)
                .any(|part| {
                    let mut segments = part.split(';').map(str::trim);
                    let Some(media_type) = segments.next() else {
                        return false;
                    };
                    if media_type != "application/json" {
                        return false;
                    }

                    !segments.any(|segment| {
                        segment
                            .strip_prefix("q=")
                            .and_then(|value| value.parse::<f32>().ok())
                            .is_some_and(|quality| quality <= 0.0)
                    })
                })
        })
        .unwrap_or(false)
}

fn content_type_is_json(content_type: Option<&str>) -> bool {
    content_type
        .map(|value| value.split(';').next().unwrap_or_default().trim() == "application/json")
        .unwrap_or(false)
}

fn expects_json_post(accept: Option<&str>, content_type: Option<&str>) -> bool {
    accepts_json(accept) && content_type_is_json(content_type)
}

fn login_continue_url_after_consent(login_id: &str, decision: ConsentDecision) -> String {
    let decision = match decision {
        ConsentDecision::Approve => "approve",
        ConsentDecision::Deny => "deny",
    };

    format!(
        "/login/continue?login_id={}&decision={decision}",
        urlencoding::encode(login_id),
    )
}

#[handler]
pub async fn consent_get(depot: &mut Depot, req: &mut Request) -> Result<AppResponse, AppError> {
    if accepts_json(
        req.headers()
            .get(header::ACCEPT)
            .and_then(|value| value.to_str().ok()),
    ) {
        return consent_api(depot, req).await;
    }

    consent_page(depot, req).await
}

pub async fn consent_page(depot: &mut Depot, req: &mut Request) -> Result<AppResponse, AppError> {
    let ctx = app_state(depot)?;
    let headers = req.headers().clone();
    let query: ConsentQuery = parse_query(req)?;
    let authorize_service = ctx.services().oidc_authorize();
    let active_sessions = load_active_sessions(&ctx, &headers).await?;

    if active_sessions.is_empty() {
        return Ok(redirect_to_response("/login").into());
    }

    let (_login, request, client) = authorize_service
        .load_consent_context_by_login(&query.login_id)
        .await?;

    if select_active_session(&active_sessions, request.login_hint.as_deref()).is_none() {
        return Ok(redirect_to_response("/login").into());
    }

    let data = ConsentPageData {
        login_id: query.login_id,
        client_name: client.client().name.clone(),
        client_uri: client
            .metadata()
            .client_uri
            .as_ref()
            .map(|value| value.to_string()),
        scopes: build_scope_display(&ScopeSet::parse(&request.scope).unwrap_or_default()),
        csrf_token: csrf_token(depot),
    };

    let mut response = Response::new();
    match web::tera::render_view(&ctx, &headers, "oauth2/consent.html", data) {
        Ok(body) => render_html(&mut response, StatusCode::OK, body),
        Err(error) => render_app_error(&mut response, error),
    }
    response.headers_mut().insert(
        http::header::HeaderName::from_static("content-security-policy"),
        inline_script_csp_header_value(),
    );
    Ok(response.into())
}

pub async fn consent_api(depot: &mut Depot, req: &mut Request) -> Result<AppResponse, AppError> {
    let ctx = app_state(depot)?;
    let headers = req.headers().clone();
    let query: ConsentQuery = parse_query(req)?;
    let authorize_service = ctx.services().oidc_authorize();
    let active_sessions = load_active_sessions(&ctx, &headers).await?;

    let (_login, request, client) = authorize_service
        .load_consent_context_by_login(&query.login_id)
        .await?;

    if select_active_session(&active_sessions, request.login_hint.as_deref()).is_none() {
        return Err(AppError::from_code(
            AuthorizeHttpErrorCode::ConsentSessionNotFound,
        ));
    }

    Ok(json_response(
        StatusCode::OK,
        ConsentPageData {
            login_id: query.login_id,
            client_name: client.client().name.clone(),
            client_uri: client
                .metadata()
                .client_uri
                .as_ref()
                .map(|value| value.to_string()),
            scopes: build_scope_display(&ScopeSet::parse(&request.scope).unwrap_or_default()),
            csrf_token: csrf_token(depot),
        },
    )
    .into())
}

#[handler]
pub async fn consent_post(depot: &mut Depot, req: &mut Request) -> Result<AppResponse, AppError> {
    let accept = req
        .headers()
        .get(header::ACCEPT)
        .and_then(|value| value.to_str().ok());
    let content_type = req
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok());

    if expects_json_post(accept, content_type) {
        return consent_api_submit(depot, req).await;
    }

    consent_submit(depot, req).await
}

pub async fn consent_submit(depot: &mut Depot, req: &mut Request) -> Result<AppResponse, AppError> {
    let ctx = app_state(depot)?;
    let headers = req.headers().clone();
    let form: ConsentDecisionForm = parse_form(req).await?;
    handle_consent_decision(ctx, headers, form.login_id, form.decision, true).await
}

pub async fn consent_api_submit(
    depot: &mut Depot,
    req: &mut Request,
) -> Result<AppResponse, AppError> {
    let ctx = app_state(depot)?;
    let headers = req.headers().clone();
    let payload: ConsentDecisionPayload = parse_json(req).await?;
    handle_consent_decision(ctx, headers, payload.login_id, payload.decision, false).await
}

async fn handle_consent_decision(
    ctx: AppState,
    headers: HeaderMap,
    login_id: String,
    decision: ConsentDecision,
    is_html: bool,
) -> Result<AppResponse, AppError> {
    if is_html {
        return Ok(
            redirect_to_response(&login_continue_url_after_consent(&login_id, decision)).into(),
        );
    }

    let authorize_service = ctx.services().oidc_authorize();
    let active_sessions = load_active_sessions(&ctx, &headers).await?;

    let (_login, request, _client) = authorize_service
        .load_consent_context_by_login(&login_id)
        .await?;

    let Some(session) = select_active_session(&active_sessions, request.login_hint.as_deref())
    else {
        return Ok(redirect_to_response("/login").into());
    };

    let redirect = match decision {
        ConsentDecision::Approve => {
            // Look up the session to get auth_time for the ID token
            let auth_time = ctx
                .services()
                .session()
                .select_session(session.session_oid)
                .await
                .ok()
                .map(|s| s.created_at.timestamp());
            authorize_service
                .approve_authorization_request_by_login(
                    &login_id,
                    session.session_oid,
                    session.user_oid,
                    auth_time,
                )
                .await?
        }
        ConsentDecision::Deny => {
            authorize_service
                .deny_authorization_request_by_login(&login_id)
                .await?
        }
    };

    Ok(json_response(
        StatusCode::OK,
        ConsentApiResponse {
            status: match decision {
                ConsentDecision::Approve => "approved",
                ConsentDecision::Deny => "denied",
            },
            redirect_uri: Some(redirect.to_string()),
            error: None,
        },
    )
    .into())
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::sync::Arc;

    use base64::Engine;
    use chrono::{Duration, Utc};
    use http::{StatusCode, header};
    use identity_domain::{
        auth::{LoginStatus, SessionStatus, password::PasswordHashSetting},
        client_authorization::ClientAuthorizationType,
        key::{
            KeyData,
            material::{SymmetricKeyAlgorithm, SymmetricKeyData},
        },
        openid_connect::{AuthorizationRequestData, OpenIdConnectClientSettings},
        setting::{
            installation::{InstallationSetting, InstallationState},
            model::SettingDefinition,
        },
    };
    use identity_infrastructure::{
        AppContext, AppLifecycle, AppResources, AppState,
        config::{
            AppConfig, AppEnvironment, DatabaseConfig, HealthChecksConfig, HealthConfig,
            LoggerConfig, ServerConfig, SettingsConfig,
        },
        services::AppServices,
        settings::AppRuntimeSettings,
        web::tera::{build_i18n, build_tera},
    };
    use salvo::{
        Service,
        test::{ResponseExt, TestClient},
    };
    use sea_orm::{DatabaseBackend, MockDatabase, Value};

    use crate::{
        controllers::shared::build_session_cookie,
        infrastructure::database::entity::{
            client, client_authorization, client_open_id_connect, key, login, session, setting,
            user,
        },
        router::app_router,
    };

    use crate::web::views::oauth2::ConsentDecision;

    fn consent_test_config() -> AppConfig {
        AppConfig {
            logger: LoggerConfig::default(),
            server: ServerConfig::default(),
            database: DatabaseConfig::default(),
            health: HealthConfig::default(),
            settings: SettingsConfig::default(),
        }
    }

    async fn consent_test_state() -> (AppState, String, uuid::Uuid) {
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
        let installation_setting = setting::Model {
            id: 2,
            oid: uuid::Uuid::new_v4(),
            key: InstallationSetting::KEY.to_string(),
            value: serde_json::to_value(InstallationState {
                initialized: true,
                domain: Some("identity.example.com".to_owned()),
                first_user_oid: Some(user_oid),
                first_key_oid: Some(symmetric_key_oid),
                initialized_at: Some(now),
            })
            .unwrap(),
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
        let authorization_request = AuthorizationRequestData {
            response_type: "code".to_owned(),
            response_mode: None,
            client_id: client_oid.to_string(),
            redirect_uri: "https://client.example.com/callback".to_owned(),
            scope: "openid profile".to_owned(),
            state: "state-123".to_owned(),
            nonce: None,
            prompt: None,
            login_hint: None,
            code_challenge: None,
            code_challenge_method: None,
            acr_values: None,
            claims: None,
        };
        let authorization_model = client_authorization::Model {
            id: 23,
            oid: authorization_oid,
            client_id: client_model.id,
            r#type: ClientAuthorizationType::AuthorizationRequest.to_string(),
            data: serde_json::to_value(authorization_request).unwrap(),
            expires_at: (now + Duration::minutes(10)).into(),
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

        let db = MockDatabase::new(DatabaseBackend::Postgres)
            .append_query_results([[password_setting]])
            .append_query_results([[installation_setting]])
            .append_query_results([[symmetric_key.clone()]])
            .append_query_results([[(active_session.clone(), active_user.clone())]])
            .append_query_results([[symmetric_key]])
            .append_query_results([[login_model.clone()]])
            .append_query_results([[client_model.clone()]])
            .append_query_results([[authorization_model.clone()]])
            .append_query_results([[(authorization_model.clone(), client_model.clone())]])
            .append_query_results([[(client_model.clone(), oidc_metadata_model)]])
            .append_query_results([Vec::<crate::infrastructure::database::entity::client_platform::Model>::new()])
            .append_query_results([Vec::<client_open_id_connect::Model>::new()])
            .append_query_results([[BTreeMap::from([(
                "name".to_owned(),
                Value::String(Some("openid".to_owned())),
            )])]])
            .append_query_results([[(active_session.clone(), active_user.clone())]])
            .append_query_results([[active_session.clone()]])
            .append_query_results([[(active_session, active_user)]])
            .append_query_results([[login_model.clone()]])
            .append_query_results([[authorization_model.clone()]])
            .append_query_results([[client_model.clone()]])
            .append_query_results([[authorization_model]])
            .into_connection();

        let i18n = build_i18n().unwrap();
        let tera = build_tera(i18n.loader()).unwrap();
        let settings = Arc::new(AppRuntimeSettings::from_db(db.clone()).await.unwrap());
        let services = Arc::new(AppServices::from_db(db.clone(), settings.as_ref()));

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

    #[test]
    fn login_continue_url_after_consent_approve_round_trips_to_continue() {
        assert_eq!(
            super::login_continue_url_after_consent("login-123", ConsentDecision::Approve),
            "/login/continue?login_id=login-123&decision=approve",
        );
    }

    #[test]
    fn login_continue_url_after_consent_deny_round_trips_to_continue() {
        assert_eq!(
            super::login_continue_url_after_consent("login-123", ConsentDecision::Deny),
            "/login/continue?login_id=login-123&decision=deny",
        );
    }

    #[tokio::test]
    async fn consent_get_returns_html_by_default() {
        let (state, protected_login_id, session_oid) = consent_test_state().await;
        let app = app_router(state, &consent_test_config());
        let service = Service::new(app);
        let session_cookie = build_session_cookie(&[session_oid], false);

        let response = TestClient::get(format!(
            "http://127.0.0.1:5800/oauth2/consent?login_id={protected_login_id}"
        ))
        .add_header(header::COOKIE, session_cookie, true)
        .send(&service)
        .await;

        assert_eq!(response.status_code, Some(StatusCode::OK));
        assert_eq!(
            response
                .headers()
                .get(header::CONTENT_TYPE)
                .and_then(|value| value.to_str().ok()),
            Some("text/html; charset=utf-8"),
        );
    }

    #[tokio::test]
    async fn consent_get_returns_json_when_accept_requests_json() {
        let (state, protected_login_id, session_oid) = consent_test_state().await;
        let app = app_router(state, &consent_test_config());
        let service = Service::new(app);
        let session_cookie = build_session_cookie(&[session_oid], false);

        let mut response = TestClient::get(format!(
            "http://127.0.0.1:5800/oauth2/consent?login_id={protected_login_id}"
        ))
        .add_header(header::COOKIE, session_cookie, true)
        .add_header(header::ACCEPT, "application/json", true)
        .send(&service)
        .await;

        assert_eq!(response.status_code, Some(StatusCode::OK));
        let body = response.take_string().await.unwrap();
        assert!(body.contains("\"login_id\""), "{body}");
        assert!(body.contains("\"client_name\""), "{body}");
    }

    #[test]
    fn accepts_json_rejects_zero_quality_json_media_type() {
        let result = super::accepts_json(Some("application/json;q=0"));

        assert!(!result);
    }

    #[test]
    fn accepts_json_rejects_non_exact_json_media_type() {
        let result = super::accepts_json(Some("application/json-patch+json"));

        assert!(!result);
    }

    #[test]
    fn consent_post_with_only_json_accept_still_uses_form_branch() {
        let result = super::expects_json_post(
            Some("application/json"),
            Some("application/x-www-form-urlencoded"),
        );

        assert!(!result);
    }

    #[test]
    fn consent_post_with_only_json_content_type_still_uses_form_branch() {
        let result = super::expects_json_post(Some("text/html"), Some("application/json"));

        assert!(!result);
    }

    #[test]
    fn consent_post_returns_json_only_when_accept_and_content_type_are_json() {
        let result = super::expects_json_post(Some("application/json"), Some("application/json"));

        assert!(result);
    }

    #[tokio::test]
    async fn html_consent_submit_redirects_to_login_continue_without_loading_authorize_state() {
        let result = super::handle_consent_decision(
            identity_infrastructure::test_app_state_with_mock_settings().await,
            http::HeaderMap::new(),
            "login-123".to_string(),
            ConsentDecision::Approve,
            true,
        )
        .await;

        assert!(result.is_ok());
        let response = result.unwrap().0;
        assert_eq!(response.status_code, Some(StatusCode::SEE_OTHER));
        assert_eq!(
            response.headers().get(header::LOCATION).unwrap(),
            "/login/continue?login_id=login-123&decision=approve",
        );
    }

    #[tokio::test]
    async fn consent_page_allows_inline_script_csp_for_auto_approve() {
        let (state, protected_login_id, session_oid) = consent_test_state().await;
        let app = app_router(state, &consent_test_config());
        let service = Service::new(app);
        let session_cookie = build_session_cookie(&[session_oid], false);

        let mut response = TestClient::get(format!(
            "http://127.0.0.1:5800/oauth2/consent?login_id={protected_login_id}&auto_approve=1"
        ))
        .add_header(header::COOKIE, session_cookie, true)
        .send(&service)
        .await;

        assert_eq!(response.status_code, Some(StatusCode::OK));
        let body = response.take_string().await.unwrap();
        assert!(body.contains("auto_approve"), "{body}");
        assert_eq!(
            response
                .headers()
                .get("content-security-policy")
                .and_then(|value| value.to_str().ok()),
            Some("default-src 'self'; script-src 'unsafe-inline'"),
        );
    }
}
