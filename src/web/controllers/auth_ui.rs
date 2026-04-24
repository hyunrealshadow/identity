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

use http::HeaderMap;
use salvo::{Depot, Request, Response, Router, handler};
use serde::Deserialize;
use uuid::Uuid;

use super::response::{
    AppResponse, app_state, parse_form, parse_query, redirect_to_response, render_app_error,
    render_html,
};
use super::shared::{
    append_set_cookie, build_selected_session_cookie, build_session_context, csrf_hoop, csrf_token,
    is_secure_cookie, load_active_sessions,
};
use crate::web::views::auth_ui::{AccountData, IdentifierPageData, OtpPageData, PasswordPageData};
use crate::{
    application::{
        auth::login::ChallengeOutcome,
        error::{AppError, codes::common::CommonErrorCode},
    },
    boot::AppState,
    infrastructure::{i18n::resolve_locale_from_headers, web},
};

// ─── Routes ──────────────────────────────────────────────────────────────────

pub fn routes() -> Router {
    Router::new()
        .hoop(csrf_hoop())
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
    session_id: Uuid,
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
    load_active_sessions(ctx, headers)
        .await
        .unwrap_or_else(|_| Vec::new())
        .into_iter()
        .map(|account| AccountData {
            id: account.session_oid,
            name: account.user_name,
            email: account.user_email,
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
        Err(error) => render_app_error(&mut response, error),
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
        Err(error) => render_app_error(&mut response, error),
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
        Err(error) => render_app_error(&mut response, error),
    }
    response
}

// ─── GET Handlers ─────────────────────────────────────────────────────────────

/// `GET /login`
///
/// Renders the account picker when active sessions exist, or the identifier
/// entry form when the user has no existing sessions.
#[handler]
async fn login_page(depot: &mut Depot, req: &mut Request) -> Result<AppResponse, AppError> {
    let ctx = app_state(depot)?;
    let headers = req.headers().clone();
    let q: LoginQuery = parse_query(req)?;
    let accounts = match load_active_sessions(&ctx, &headers).await {
        Ok(list) => list
            .into_iter()
            .map(|account| AccountData {
                id: account.session_oid,
                name: account.user_name,
                email: account.user_email,
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
async fn password_page(depot: &mut Depot, req: &mut Request) -> Result<AppResponse, AppError> {
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
async fn otp_page(depot: &mut Depot, req: &mut Request) -> Result<AppResponse, AppError> {
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
async fn select_post(depot: &mut Depot, req: &mut Request) -> Result<AppResponse, AppError> {
    let ctx = app_state(depot)?;
    let headers = req.headers().clone();
    let body: SelectForm = parse_form(req).await?;

    Ok(AppResponse(
        match ctx
            .services()
            .session()
            .select_session(body.session_id)
            .await
        {
            Ok(session) => {
                let cookie =
                    build_selected_session_cookie(&headers, session.oid, is_secure_cookie(&ctx));
                let target = body
                    .login_id
                    .map(|value| {
                        format!(
                            "/oauth2/authorize/consent?login_id={}",
                            urlencoding::encode(&value)
                        )
                    })
                    .unwrap_or_else(|| "/".to_string());
                let mut response = redirect_to_response(&target);
                append_set_cookie(&mut response, &cookie);
                response
            }
            Err(e) => {
                tracing::error!(error = %e, "select_session failed");
                redirect_to_response("/login")
            }
        },
    ))
}

/// `POST /login`
///
/// Validate the identifier. On success, redirect to the password page.
/// On failure, re-render the login page with an inline error.
#[handler]
async fn identifier_post(depot: &mut Depot, req: &mut Request) -> Result<AppResponse, AppError> {
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
            Some(invalid_request_message(&ctx, &headers).into()),
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
                Some(invalid_request_message(&ctx, &headers).into()),
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
                            Some(invalid_request_message(&ctx, &headers).into()),
                        )
                        .into());
                    }
                };

                let identifier = urlencoding::encode(&body.identifier).into_owned();
                let name = urlencoding::encode(&result.user.name).into_owned();
                let email =
                    urlencoding::encode(&crate::web::views::auth::mask_email(&result.user.email))
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
async fn password_post(depot: &mut Depot, req: &mut Request) -> Result<AppResponse, AppError> {
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
                    error: Some(invalid_request_message(&ctx, &headers).into()),
                    csrf_token: String::new(),
                },
                csrf_token(depot),
            )
            .into());
        }
    };

    let sess_ctx = build_session_context(&headers);

    Ok(AppResponse(
        match ctx
            .services()
            .login()
            .challenge(login_oid, "password", &body.credential, sess_ctx)
            .await
        {
            Ok(ChallengeOutcome::Authenticated { session, .. }) => {
                let cookie =
                    build_selected_session_cookie(&headers, session.oid, is_secure_cookie(&ctx));
                let target = format!(
                    "/oauth2/authorize/consent?login_id={}",
                    urlencoding::encode(&body.login_id)
                );
                let mut response = redirect_to_response(&target);
                append_set_cookie(&mut response, &cookie);
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
                                error: Some(invalid_request_message(&ctx, &headers).into()),
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
                let error_msg =
                    super::response::error_message(ctx.resources().i18n(), &locale, &err);
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
        },
    ))
}

/// `POST /login/otp`
///
/// Verify the TOTP code.
/// - Authenticated → set cookie, redirect to `/`
/// - Error         → re-render OTP page with inline error
#[handler]
async fn otp_post(depot: &mut Depot, req: &mut Request) -> Result<AppResponse, AppError> {
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
                    error: Some(invalid_request_message(&ctx, &headers).into()),
                    csrf_token: String::new(),
                },
                csrf_token(depot),
            )
            .into());
        }
    };

    let sess_ctx = build_session_context(&headers);

    Ok(AppResponse(
        match ctx
            .services()
            .login()
            .challenge(login_oid, "otp", &body.credential, sess_ctx)
            .await
        {
            Ok(ChallengeOutcome::Authenticated { session, .. }) => {
                let cookie =
                    build_selected_session_cookie(&headers, session.oid, is_secure_cookie(&ctx));
                let target = format!(
                    "/oauth2/authorize/consent?login_id={}",
                    urlencoding::encode(&body.login_id)
                );
                let mut response = redirect_to_response(&target);
                append_set_cookie(&mut response, &cookie);
                response
            }
            Ok(ChallengeOutcome::MfaRequired { .. }) => {
                tracing::warn!("otp challenge returned MfaRequired unexpectedly");
                redirect_to_response("/login")
            }
            Err(err) => {
                let locale = resolve_locale_from_headers(&headers);
                let error_msg =
                    super::response::error_message(ctx.resources().i18n(), &locale, &err);
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
        },
    ))
}
