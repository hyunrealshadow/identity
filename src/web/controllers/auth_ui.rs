//! Page controllers — server-rendered HTML views for the progressive login flow.
//!
//! Routes:
//!   GET  /login              – account picker + identifier entry
//!   POST /login              – process identifier submission
//!   POST /login/select       – select an existing session (account picker)
//!   GET  /login/password     – password entry
//!   POST /login/password     – process password submission
//!   GET  /login/otp          – TOTP/OTP entry
//!   POST /login/otp          – process OTP submission

use std::error::Error as StdError;

use http::{HeaderMap, StatusCode};
use salvo::{Depot, FlowCtrl, Request, Response, Router, handler};
use serde::Deserialize;

use super::response::{
    AppResponse, WebResult, app_state, parse_form, parse_query, redirect_to_response,
    render_app_error, render_html,
};
use super::shared::{
    append_set_cookie, build_selected_session_cookie, build_session_context, csrf_middleware,
    csrf_token, is_secure_cookie, load_active_session_entries, unprotect_session_id,
};
use crate::views::auth_ui::{AccountData, IdentifierPageData, OtpPageData, PasswordPageData};
use crate::{
    application::{
        auth::login::ChallengeOutcome,
        error::{AppError, codes::common::CommonErrorCode},
        setting::runtime::SettingProvider,
    },
    boot::AppState,
    domain::client_authorization::SelectionSource,
    infrastructure::{i18n::resolve_locale_from_headers, web},
};

// ─── Routes ──────────────────────────────────────────────────────────────────

pub fn routes() -> Router {
    Router::new()
        .hoop(csrf_middleware())
        .hoop(auth_ui_enabled_guard)
        .push(
            Router::with_path("login")
                .get(login_page)
                .post(identifier_post),
        )
        .push(Router::with_path("login/select").post(select_post))
        .push(
            Router::with_path("login/password")
                .get(password_page)
                .post(password_post),
        )
        .push(Router::with_path("login/otp").get(otp_page).post(otp_post))
}

// ─── Guard ────────────────────────────────────────────────────────────────────

#[handler]
async fn auth_ui_enabled_guard(
    req: &mut Request,
    depot: &mut Depot,
    res: &mut Response,
    ctrl: &mut FlowCtrl,
) {
    let Ok(ctx) = app_state(depot) else {
        ctrl.call_next(req, depot, res).await;
        return;
    };
    if *ctx.settings().auth_ui_enabled().current_value() {
        ctrl.call_next(req, depot, res).await;
    } else {
        res.status_code(StatusCode::NOT_FOUND);
        ctrl.skip_rest();
    }
}

// ─── Query param structs ──────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
struct PasswordQuery {
    login_id: Option<String>,
    identifier: Option<String>,
    name: Option<String>,
    email: Option<String>,
}

#[derive(Debug, Deserialize)]
struct OtpQuery {
    login_id: Option<String>,
    identifier: Option<String>,
    name: Option<String>,
    email: Option<String>,
}

#[derive(Debug, Deserialize)]
struct LoginQuery {
    login_id: Option<String>,
}

// ─── Form body structs ────────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
struct IdentifierForm {
    login_id: Option<String>,
    identifier: String,
}

#[derive(Debug, Deserialize)]
struct SelectForm {
    session_id: String,
    login_id: Option<String>,
}

#[derive(Debug, Deserialize)]
struct PasswordForm {
    login_id: String,
    identifier: String,
    credential: String,
}

#[derive(Debug, Deserialize)]
struct OtpForm {
    login_id: String,
    identifier: String,
    credential: String,
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

fn invalid_request_message(ctx: &AppState, headers: &HeaderMap) -> String {
    let locale = resolve_locale_from_headers(headers);
    super::response::error_message(
        ctx.resources().i18n(),
        &locale,
        &AppError::from_code(CommonErrorCode::InvalidRequest),
    )
}

async fn load_account_data(ctx: &AppState, headers: &HeaderMap) -> Vec<AccountData> {
    load_active_session_entries(ctx, headers)
        .await
        .unwrap_or_else(|_| Vec::new())
        .into_iter()
        .map(|entry| AccountData {
            id: entry.protected_session_id,
            name: entry.session.user_name,
            email: entry.session.user_email,
        })
        .collect()
}

fn render_identifier_page(
    ctx: &AppState,
    headers: &HeaderMap,
    csrf_token: String,
    accounts: Vec<AccountData>,
    identifier: Option<String>,
    login_id: Option<String>,
    error: Option<String>,
) -> Response {
    let data = IdentifierPageData {
        accounts,
        identifier,
        login_id,
        error,
        csrf_token,
    };
    let mut response = Response::new();
    match web::tera::render_view(ctx, headers, "auth/login.html", data) {
        Ok(body) => render_html(&mut response, http::StatusCode::OK, body),
        Err(error) => render_app_error(&mut response, headers, ctx, error),
    }
    response
}

fn render_password_page(
    ctx: &AppState,
    headers: &HeaderMap,
    mut data: PasswordPageData,
    csrf_token: String,
) -> Response {
    data.csrf_token = csrf_token;
    let mut response = Response::new();
    match web::tera::render_view(ctx, headers, "auth/password.html", data) {
        Ok(body) => render_html(&mut response, http::StatusCode::OK, body),
        Err(error) => render_app_error(&mut response, headers, ctx, error),
    }
    response
}

fn render_otp_page(
    ctx: &AppState,
    headers: &HeaderMap,
    mut data: OtpPageData,
    csrf_token: String,
) -> Response {
    data.csrf_token = csrf_token;
    let mut response = Response::new();
    match web::tera::render_view(ctx, headers, "auth/otp.html", data) {
        Ok(body) => render_html(&mut response, http::StatusCode::OK, body),
        Err(error) => render_app_error(&mut response, headers, ctx, error),
    }
    response
}

fn oauth2_continue_url(login_id: &str) -> String {
    format!(
        "/oauth2/continue?login_id={}",
        urlencoding::encode(login_id)
    )
}

// ─── GET Handlers ─────────────────────────────────────────────────────────────

/// `GET /login`
///
/// Renders the account picker when active sessions exist, or the identifier
/// entry form when the user has no existing sessions.
#[handler]
async fn login_page(depot: &mut Depot, req: &mut Request) -> WebResult {
    let ctx = app_state(depot)?;
    let headers = req.headers().clone();
    let q: LoginQuery = parse_query(req)?;
    let accounts = match load_active_session_entries(&ctx, &headers).await {
        Ok(list) => list
            .into_iter()
            .map(|entry| AccountData {
                id: entry.protected_session_id,
                name: entry.session.user_name,
                email: entry.session.user_email,
            })
            .collect(),
        Err(e) => {
            tracing::error!(error = %e, source = ?e.source(), "failed to load active sessions for login page");
            Vec::new()
        }
    };

    let error = if q.login_id.is_none() && accounts.is_empty() {
        Some(invalid_request_message(&ctx, &headers))
    } else {
        None
    };
    Ok(render_identifier_page(
        &ctx,
        &headers,
        csrf_token(depot),
        accounts,
        None,
        q.login_id,
        error,
    )
    .into())
}

/// `GET /login/password`
///
/// Renders the password entry form. Requires `login_id` and `identifier`
/// query parameters. Redirects back to `/login` if either is missing.
#[handler]
async fn password_page(depot: &mut Depot, req: &mut Request) -> WebResult {
    let ctx = app_state(depot)?;
    let headers = req.headers().clone();
    let q: PasswordQuery = parse_query(req)?;
    let (Some(login_id), Some(identifier)) = (q.login_id, q.identifier) else {
        return Ok(redirect_to_response("/login").into());
    };

    let data = PasswordPageData {
        login_id,
        identifier,
        user_name: q.name.unwrap_or_default(),
        masked_email: q.email.unwrap_or_default(),
        error: None,
        csrf_token: String::new(),
    };

    Ok(render_password_page(&ctx, &headers, data, csrf_token(depot)).into())
}

/// `GET /login/otp`
///
/// Renders the OTP/TOTP entry form. Requires `login_id` and `identifier`
/// query parameters. Redirects back to `/login` if either is missing.
#[handler]
async fn otp_page(depot: &mut Depot, req: &mut Request) -> WebResult {
    let ctx = app_state(depot)?;
    let headers = req.headers().clone();
    let q: OtpQuery = parse_query(req)?;
    let (Some(login_id), Some(identifier)) = (q.login_id, q.identifier) else {
        return Ok(redirect_to_response("/login").into());
    };

    let data = OtpPageData {
        login_id,
        identifier,
        user_name: q.name.unwrap_or_default(),
        masked_email: q.email.unwrap_or_default(),
        error: None,
        csrf_token: String::new(),
    };

    Ok(render_otp_page(&ctx, &headers, data, csrf_token(depot)).into())
}

// ─── POST Handlers ────────────────────────────────────────────────────────────

/// `POST /login/select`
///
/// Select an existing session from the account picker. Reorders the sessions
/// cookie so the chosen account is first, then redirects to `/`.
#[handler]
async fn select_post(depot: &mut Depot, req: &mut Request) -> WebResult {
    let ctx = app_state(depot)?;
    let headers = req.headers().clone();
    let body: SelectForm = parse_form(req).await?;

    let session_oid = unprotect_session_id(&ctx, &body.session_id).await;
    let response = match session_oid {
        Ok(session_oid) => match ctx.services().session().select_session(session_oid).await {
            Ok(session) => {
                let cookie = build_selected_session_cookie(
                    &ctx,
                    &headers,
                    session.oid,
                    is_secure_cookie(&ctx),
                )
                .await?;
                if let Some(login_id) = body.login_id.as_deref() {
                    ctx.services()
                        .oidc_authorize()
                        .record_selection_by_login(
                            login_id,
                            session.oid,
                            session.user_oid,
                            Some(cookie.protected_session_id.clone()),
                            SelectionSource::AccountPicker,
                        )
                        .await?;
                }

                let target = body
                    .login_id
                    .as_deref()
                    .map(oauth2_continue_url)
                    .unwrap_or_else(|| "/".to_string());
                let mut response = redirect_to_response(&target);
                append_set_cookie(&mut response, &cookie.header);
                response
            }
            Err(e) => {
                tracing::error!(error = %e, "select_session failed");
                redirect_to_response("/login")
            }
        },
        Err(e) => {
            tracing::error!(error = %e, "unprotect_session_id failed");
            redirect_to_response("/login")
        }
    };

    Ok(AppResponse(response))
}

/// `POST /login`
///
/// Validate the identifier. On success, redirect to the password page.
/// On failure, re-render the login page with an inline error.
#[handler]
async fn identifier_post(depot: &mut Depot, req: &mut Request) -> WebResult {
    let ctx = app_state(depot)?;
    let headers = req.headers().clone();
    let body: IdentifierForm = parse_form(req).await?;

    let Some(protected_login_id) = body.login_id else {
        let accounts = load_account_data(&ctx, &headers).await;
        return Ok(render_identifier_page(
            &ctx,
            &headers,
            csrf_token(depot),
            accounts,
            Some(body.identifier),
            None,
            Some(invalid_request_message(&ctx, &headers)),
        )
        .into());
    };

    let login_oid = match ctx
        .services()
        .oidc_authorize()
        .decrypt_login_id(&protected_login_id)
        .await
    {
        Ok(oid) => oid,
        Err(e) => {
            tracing::error!(error = %e, "decrypt_login_id failed");
            let accounts = load_account_data(&ctx, &headers).await;
            return Ok(render_identifier_page(
                &ctx,
                &headers,
                csrf_token(depot),
                accounts,
                Some(body.identifier),
                Some(protected_login_id),
                Some(invalid_request_message(&ctx, &headers)),
            )
            .into());
        }
    };

    Ok(AppResponse(
        match ctx
            .services()
            .login()
            .identify(login_oid, &body.identifier)
            .await
        {
            Ok(result) => {
                let protected_result_id = match ctx
                    .services()
                    .oidc_authorize()
                    .encrypt_login_id(result.login.oid)
                    .await
                {
                    Ok(id) => id,
                    Err(e) => {
                        tracing::error!(error = %e, "encrypt_login_id failed");
                        let accounts = load_account_data(&ctx, &headers).await;
                        return Ok(render_identifier_page(
                            &ctx,
                            &headers,
                            csrf_token(depot),
                            accounts,
                            Some(body.identifier),
                            Some(protected_login_id),
                            Some(invalid_request_message(&ctx, &headers)),
                        )
                        .into());
                    }
                };

                let identifier = urlencoding::encode(&body.identifier).into_owned();
                let name = urlencoding::encode(&result.user.name).into_owned();
                let email =
                    urlencoding::encode(&crate::views::auth::mask_email(&result.user.email))
                        .into_owned();

                let url = format!(
                    "/login/password?login_id={protected_result_id}&identifier={identifier}&name={name}&email={email}"
                );
                redirect_to_response(&url)
            }
            Err(err) => {
                let locale = resolve_locale_from_headers(&headers);
                let error_msg =
                    super::response::error_message(ctx.resources().i18n(), &locale, &err);
                let accounts = load_account_data(&ctx, &headers).await;
                render_identifier_page(
                    &ctx,
                    &headers,
                    csrf_token(depot),
                    accounts,
                    Some(body.identifier),
                    Some(protected_login_id),
                    Some(error_msg),
                )
            }
        },
    ))
}

/// `POST /login/password`
///
/// Verify the password credential.
/// - Authenticated  → set cookie, redirect to `/`
/// - MFA required   → redirect to `/login/otp?...`
/// - Error          → re-render password page with inline error
#[handler]
async fn password_post(depot: &mut Depot, req: &mut Request) -> WebResult {
    let ctx = app_state(depot)?;
    let headers = req.headers().clone();
    let body: PasswordForm = parse_form(req).await?;

    let login_oid = match ctx
        .services()
        .oidc_authorize()
        .decrypt_login_id(&body.login_id)
        .await
    {
        Ok(oid) => oid,
        Err(e) => {
            tracing::error!(error = %e, "decrypt_login_id failed");
            return Ok(render_password_page(
                &ctx,
                &headers,
                PasswordPageData {
                    login_id: body.login_id,
                    identifier: body.identifier,
                    user_name: String::new(),
                    masked_email: String::new(),
                    error: Some(invalid_request_message(&ctx, &headers)),
                    csrf_token: String::new(),
                },
                csrf_token(depot),
            )
            .into());
        }
    };

    let sess_ctx = build_session_context(&headers);

    let response = match ctx
        .services()
        .login()
        .challenge(login_oid, "password", &body.credential, sess_ctx)
        .await
    {
        Ok(ChallengeOutcome::Authenticated { session, .. }) => {
            let cookie =
                build_selected_session_cookie(&ctx, &headers, session.oid, is_secure_cookie(&ctx))
                    .await?;
            ctx.services()
                .oidc_authorize()
                .record_selection_by_login(
                    &body.login_id,
                    session.oid,
                    session.user_oid,
                    Some(cookie.protected_session_id.clone()),
                    SelectionSource::FreshLogin,
                )
                .await?;
            let mut response = redirect_to_response(&oauth2_continue_url(&body.login_id));
            append_set_cookie(&mut response, &cookie.header);
            response
        }
        Ok(ChallengeOutcome::MfaRequired { login }) => {
            let protected_mfa_id = match ctx
                .services()
                .oidc_authorize()
                .encrypt_login_id(login.oid)
                .await
            {
                Ok(id) => id,
                Err(e) => {
                    tracing::error!(error = %e, "encrypt_login_id failed");
                    return Ok(render_password_page(
                        &ctx,
                        &headers,
                        PasswordPageData {
                            login_id: body.login_id,
                            identifier: body.identifier,
                            user_name: String::new(),
                            masked_email: String::new(),
                            error: Some(invalid_request_message(&ctx, &headers)),
                            csrf_token: String::new(),
                        },
                        csrf_token(depot),
                    )
                    .into());
                }
            };
            let identifier = urlencoding::encode(&body.identifier).into_owned();
            let url = format!("/login/otp?login_id={protected_mfa_id}&identifier={identifier}");
            redirect_to_response(&url)
        }
        Err(err) => {
            let locale = resolve_locale_from_headers(&headers);
            let error_msg = super::response::error_message(ctx.resources().i18n(), &locale, &err);
            render_password_page(
                &ctx,
                &headers,
                PasswordPageData {
                    login_id: body.login_id,
                    identifier: body.identifier,
                    user_name: String::new(),
                    masked_email: String::new(),
                    error: Some(error_msg),
                    csrf_token: String::new(),
                },
                csrf_token(depot),
            )
        }
    };

    Ok(AppResponse(response))
}

/// `POST /login/otp`
///
/// Verify the TOTP code.
/// - Authenticated → set cookie, redirect to `/`
/// - Error         → re-render OTP page with inline error
#[handler]
async fn otp_post(depot: &mut Depot, req: &mut Request) -> WebResult {
    let ctx = app_state(depot)?;
    let headers = req.headers().clone();
    let body: OtpForm = parse_form(req).await?;

    let login_oid = match ctx
        .services()
        .oidc_authorize()
        .decrypt_login_id(&body.login_id)
        .await
    {
        Ok(oid) => oid,
        Err(e) => {
            tracing::error!(error = %e, "decrypt_login_id failed");
            return Ok(render_otp_page(
                &ctx,
                &headers,
                OtpPageData {
                    login_id: body.login_id,
                    identifier: body.identifier,
                    user_name: String::new(),
                    masked_email: String::new(),
                    error: Some(invalid_request_message(&ctx, &headers)),
                    csrf_token: String::new(),
                },
                csrf_token(depot),
            )
            .into());
        }
    };

    let sess_ctx = build_session_context(&headers);

    let response = match ctx
        .services()
        .login()
        .challenge(login_oid, "otp", &body.credential, sess_ctx)
        .await
    {
        Ok(ChallengeOutcome::Authenticated { session, .. }) => {
            let cookie =
                build_selected_session_cookie(&ctx, &headers, session.oid, is_secure_cookie(&ctx))
                    .await?;
            ctx.services()
                .oidc_authorize()
                .record_selection_by_login(
                    &body.login_id,
                    session.oid,
                    session.user_oid,
                    Some(cookie.protected_session_id.clone()),
                    SelectionSource::FreshLogin,
                )
                .await?;
            let mut response = redirect_to_response(&oauth2_continue_url(&body.login_id));
            append_set_cookie(&mut response, &cookie.header);
            response
        }
        Ok(ChallengeOutcome::MfaRequired { .. }) => {
            tracing::warn!("otp challenge returned MfaRequired unexpectedly");
            redirect_to_response("/login")
        }
        Err(err) => {
            let locale = resolve_locale_from_headers(&headers);
            let error_msg = super::response::error_message(ctx.resources().i18n(), &locale, &err);
            render_otp_page(
                &ctx,
                &headers,
                OtpPageData {
                    login_id: body.login_id,
                    identifier: body.identifier,
                    user_name: String::new(),
                    masked_email: String::new(),
                    error: Some(error_msg),
                    csrf_token: String::new(),
                },
                csrf_token(depot),
            )
        }
    };

    Ok(AppResponse(response))
}

#[cfg(test)]
mod tests {
    use http::{StatusCode, header};
    use salvo::{Service, test::TestClient};

    #[test]
    fn oauth2_continue_url_only_contains_login_id() {
        assert_eq!(
            super::oauth2_continue_url("login-123"),
            "/oauth2/continue?login_id=login-123"
        );
    }

    #[tokio::test]
    async fn login_continue_route_is_removed() {
        let app = super::routes().hoop(salvo::affix_state::inject(
            identity_infrastructure::test_app_state_with_mock_settings().await,
        ));
        let service = Service::new(app);

        let response = TestClient::get("http://127.0.0.1:5800/login/continue")
            .send(&service)
            .await;

        assert_eq!(response.status_code, Some(StatusCode::NOT_FOUND));
    }

    #[tokio::test]
    async fn login_page_sets_csrf_cookie_for_form_submission() {
        let app = super::routes().hoop(salvo::affix_state::inject(
            identity_infrastructure::test_app_state_with_mock_settings().await,
        ));
        let service = Service::new(app);

        let response = TestClient::get("http://127.0.0.1:5800/login?login_id=test-login")
            .send(&service)
            .await;

        assert_eq!(response.status_code, Some(StatusCode::OK));
        let csrf_cookie = response
            .headers()
            .get(header::SET_COOKIE)
            .and_then(|value| value.to_str().ok());
        assert!(
            csrf_cookie.is_some_and(|value| value.contains("salvo.csrf=")),
            "expected csrf cookie, got {csrf_cookie:?}",
        );
    }
}
