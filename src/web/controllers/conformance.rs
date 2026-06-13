//! Conformance test automation endpoints.
//!
//! These routes are **only mounted when `APP_ENV=conformance`** and must never
//! be reachable in production.
//!
//! Routes:
//!   GET  /conformance/auto-login  – render an auto-submit form for the fixed
//!                                    conformance credentials
//!   POST /conformance/auto-login  – authenticate, set the browser session cookie,
//!                                    and continue the authorize redirect chain

use http::{HeaderMap, StatusCode, header};
use salvo::{Depot, Request, Response, Router, handler};
use serde::{Deserialize, Serialize};

use identity_application::error::{AppError, codes::common::CommonErrorCode};
use identity_application::key::asymmetric::GenerateAsymmetricKeyInput;
use identity_domain::key::model::AsymmetricKeyAlgorithm;

use crate::{
    application::auth::login::ChallengeOutcome,
    boot::AppState,
    domain::auth::SessionOid,
    domain::client_authorization::SelectionSource,
    infrastructure::{
        database::seed::conformance::{CONFORMANCE_PASSWORD, CONFORMANCE_USERNAME},
        web,
    },
    views::oauth2::{FormPostField, FormPostPageData},
    web::controllers::shared::{
        append_set_cookie, build_selected_session_cookie, build_session_context,
        generate_csp_nonce, is_secure_cookie,
    },
};

use super::{
    oauth2::inline_script_csp_header_value,
    response::{
        WebResult, app_state, parse_query, redirect_to_response, render_app_error, render_html,
        render_json,
    },
};

pub fn routes() -> Router {
    Router::new()
        .push(
            Router::with_path("conformance/auto-login")
                .get(auto_login_page)
                .post(auto_login),
        )
        .push(Router::with_path("conformance/rotate-keys").post(rotate_keys))
}

#[derive(Debug, Deserialize)]
struct AutoLoginPageQuery {
    login_id: String,
}

#[derive(Debug, Deserialize)]
struct AutoLoginRequest {
    login_id: String,
    username: String,
    password: String,
}

#[derive(Debug, Serialize)]
struct AutoLoginError {
    error: String,
}

fn auto_login_form_data(login_id: &str, nonce: &str) -> FormPostPageData {
    FormPostPageData {
        title: "Completing sign-in".to_owned(),
        message: "Continuing the conformance browser flow.".to_owned(),
        action: "/conformance/auto-login".to_owned(),
        fields: vec![
            FormPostField {
                name: "login_id".to_owned(),
                value: login_id.to_owned(),
            },
            FormPostField {
                name: "username".to_owned(),
                value: CONFORMANCE_USERNAME.to_owned(),
            },
            FormPostField {
                name: "password".to_owned(),
                value: CONFORMANCE_PASSWORD.to_owned(),
            },
        ],
        nonce: nonce.to_owned(),
    }
}

fn auto_login_page_response(ctx: &AppState, headers: &HeaderMap, login_id: &str) -> Response {
    let nonce = generate_csp_nonce();
    let data = auto_login_form_data(login_id, &nonce);
    let mut response = Response::new();
    match web::tera::render_view(ctx, headers, "oauth2/form_post.html", data) {
        Ok(body) => render_html(&mut response, StatusCode::OK, body),
        Err(error) => render_app_error(&mut response, headers, ctx, error),
    }
    response.headers_mut().insert(
        header::HeaderName::from_static("content-security-policy"),
        inline_script_csp_header_value(&nonce),
    );
    response
}

fn auto_login_continue_url(login_id: &str) -> String {
    format!(
        "/oauth2/continue?login_id={}",
        urlencoding::encode(login_id)
    )
}

fn auto_login_success_response(login_id: &str, cookie: &str) -> Response {
    let mut response = redirect_to_response(&auto_login_continue_url(login_id));
    append_set_cookie(&mut response, cookie);
    response
}

async fn record_auto_login_selection<F, Fut>(
    login_id: &str,
    session: &identity_domain::auth::model::Session,
    record_selection: F,
) -> Result<(), AppError>
where
    F: FnOnce(String, uuid::Uuid, uuid::Uuid, SelectionSource) -> Fut,
    Fut: std::future::Future<Output = Result<(), AppError>>,
{
    record_selection(
        login_id.to_owned(),
        session.oid.into(),
        session.user_oid,
        SelectionSource::FreshLogin,
    )
    .await
}

#[handler]
async fn auto_login_page(
    depot: &mut Depot,
    req: &mut Request,
    res: &mut Response,
) -> WebResult<()> {
    let ctx = app_state(depot)?;
    let headers: HeaderMap = req.headers().clone();
    let query: AutoLoginPageQuery = parse_query(req)?;
    *res = auto_login_page_response(&ctx, &headers, &query.login_id);
    Ok(())
}

#[handler]
async fn auto_login(depot: &mut Depot, req: &mut Request, res: &mut Response) -> WebResult<()> {
    let ctx = app_state(depot)?;
    let headers: HeaderMap = req.headers().clone();
    let body: AutoLoginRequest = req
        .parse_body()
        .await
        .map_err(|_| AppError::from_code(CommonErrorCode::InvalidRequest))?;
    // Step 1: decrypt login_id → login_oid
    let login_oid = match ctx
        .services()
        .oidc_authorize()
        .decrypt_login_id(&body.login_id)
        .await
    {
        Ok(oid) => oid,
        Err(e) => {
            tracing::warn!(error = %e, "auto_login: decrypt_login_id failed");
            render_json(
                res,
                StatusCode::BAD_REQUEST,
                AutoLoginError {
                    error: "invalid_login_id".to_string(),
                },
            );
            return Ok(());
        }
    };

    // Step 2: identify
    match ctx
        .services()
        .login()
        .identify(login_oid, &body.username)
        .await
    {
        Ok(result) => result,
        Err(e) => {
            tracing::warn!(error = %e, "auto_login: identify failed");
            render_json(
                res,
                StatusCode::BAD_REQUEST,
                AutoLoginError {
                    error: e.to_string(),
                },
            );
            return Ok(());
        }
    };

    // Step 3: password challenge
    let sess_ctx = build_session_context(&headers);
    let session = match ctx
        .services()
        .login()
        .challenge(login_oid, "password", &body.password, sess_ctx)
        .await
    {
        Ok(ChallengeOutcome::Authenticated { session, .. }) => session,
        Ok(ChallengeOutcome::MfaRequired { .. }) => {
            render_json(
                res,
                StatusCode::BAD_REQUEST,
                AutoLoginError {
                    error: "mfa_required".to_string(),
                },
            );
            return Ok(());
        }
        Err(e) => {
            tracing::warn!(error = %e, "auto_login: challenge failed");
            render_json(
                res,
                StatusCode::UNAUTHORIZED,
                AutoLoginError {
                    error: e.to_string(),
                },
            );
            return Ok(());
        }
    };

    // Step 4: build the session cookie and jump back into the browser flow.
    let authorize_service = ctx.services().oidc_authorize();
    record_auto_login_selection(
        &body.login_id,
        &session,
        move |login_id, session_oid, user_oid, source| async move {
            authorize_service
                .record_selection_by_login(
                    &login_id,
                    SessionOid(session_oid),
                    user_oid,
                    None,
                    source,
                )
                .await
        },
    )
    .await?;

    let cookie =
        build_selected_session_cookie(&ctx, &headers, session.oid, is_secure_cookie(&ctx)).await?;
    *res = auto_login_success_response(&body.login_id, &cookie.header);
    Ok(())
}

#[derive(Debug, Serialize)]
struct RotateKeysResponse {
    key_oid: String,
    algorithm: String,
}

#[handler]
async fn rotate_keys(depot: &mut Depot, res: &mut Response) -> WebResult<()> {
    let ctx = app_state(depot)?;
    let key = ctx
        .services()
        .key()
        .generate_and_store(GenerateAsymmetricKeyInput {
            algorithm: AsymmetricKeyAlgorithm::Rsa { bits: 2048 },
            expires_at: None,
            certificate: None,
        })
        .await?;

    let key_oid = uuid::Uuid::from(key.oid).to_string();
    render_json(
        res,
        StatusCode::OK,
        RotateKeysResponse {
            key_oid,
            algorithm: "RS256".to_owned(),
        },
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use chrono::Utc;
    use http::{StatusCode, header};
    use identity_domain::{
        auth::{SessionOid, model::Session},
        client_authorization::SelectionSource,
    };
    use salvo::{
        Service,
        test::{ResponseExt, TestClient},
    };

    #[tokio::test]
    async fn auto_login_page_renders_auto_submit_form() {
        let app = super::routes().hoop(salvo::affix_state::inject(
            identity_infrastructure::test_app_state_with_mock_settings().await,
        ));
        let service = Service::new(app);

        let mut response =
            TestClient::get("http://127.0.0.1:5800/conformance/auto-login?login_id=login-123")
                .send(&service)
                .await;

        assert_eq!(response.status_code, Some(StatusCode::OK));
        assert_eq!(
            response
                .headers()
                .get("content-security-policy")
                .and_then(|value| value.to_str().ok()),
            response
                .headers()
                .get("content-security-policy")
                .and_then(|value| value.to_str().ok())
                .filter(|value| {
                    value.starts_with("default-src 'self'; script-src 'nonce-")
                        && value.ends_with("'")
                }),
        );

        let body = response.take_string().await.unwrap();
        assert!(body.contains("<form"), "{body}");
        assert!(
            body.contains("action=\"&#x2F;conformance&#x2F;auto-login\""),
            "{body}"
        );
        assert!(
            body.contains("name=\"login_id\" value=\"login-123\""),
            "{body}"
        );
        assert!(
            body.contains("name=\"username\" value=\"conformance-test\""),
            "{body}"
        );
        assert!(
            body.contains("name=\"password\" value=\"ConformanceTest1!\""),
            "{body}"
        );
        assert!(body.contains("submit()"), "{body}");
    }

    #[test]
    fn auto_login_success_response_redirects_back_to_oauth2_continue() {
        let response = super::auto_login_success_response(
            "login-123",
            "sessions=[\"session-123\"]; HttpOnly; SameSite=Lax; Path=/; Max-Age=42",
        );

        assert_eq!(response.status_code, Some(StatusCode::SEE_OTHER));
        assert_eq!(
            response.headers().get(header::LOCATION).unwrap(),
            "/oauth2/continue?login_id=login-123",
        );
        assert_eq!(
            response.headers().get(header::SET_COOKIE).unwrap(),
            "sessions=[\"session-123\"]; HttpOnly; SameSite=Lax; Path=/; Max-Age=42",
        );
    }

    #[tokio::test]
    async fn record_auto_login_selection_records_fresh_login_source() {
        let session = Session {
            oid: SessionOid(uuid::Uuid::new_v4()),
            user_oid: uuid::Uuid::new_v4(),
            status: "active".to_owned(),
            device_name: None,
            device_type: None,
            os_name: None,
            os_version: None,
            browser_name: None,
            browser_version: None,
            user_agent: None,
            ip_address: None,
            last_active_at: None,
            expires_at: None,
            revoked_at: None,
            created_at: Utc::now(),
            acr: Some("pwd".to_owned()),
            acr_expires_at: None,
        };
        let recorded = Arc::new(Mutex::new(None));

        super::record_auto_login_selection("login-123", &session, {
            let recorded = recorded.clone();
            move |login_id, session_oid, user_oid, source| {
                let recorded = recorded.clone();
                async move {
                    *recorded.lock().unwrap() =
                        Some((login_id.to_owned(), session_oid, user_oid, source));
                    Ok(())
                }
            }
        })
        .await
        .unwrap();

        assert_eq!(
            *recorded.lock().unwrap(),
            Some((
                "login-123".to_owned(),
                session.oid.0,
                session.user_oid,
                SelectionSource::FreshLogin,
            ))
        );
    }

    #[tokio::test]
    async fn auto_login_returns_bad_request_for_invalid_login_id() {
        let app = super::routes().hoop(salvo::affix_state::inject(
            identity_infrastructure::test_app_state_with_mock_settings().await,
        ));
        let service = Service::new(app);

        let response = TestClient::post("http://127.0.0.1:5800/conformance/auto-login")
            .raw_json(r#"{"login_id":"invalid","username":"test@example.com","password":"wrong"}"#)
            .send(&service)
            .await;

        // The mock DB cannot decrypt the login_id, so we expect 400.
        assert_eq!(response.status_code, Some(StatusCode::BAD_REQUEST));
    }
}
