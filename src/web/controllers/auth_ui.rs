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

use axum::{
    Router,
    extract::{Form, Query, State},
    http::{HeaderMap, header},
    response::{IntoResponse, Redirect, Response},
    routing::{get, post},
};
use serde::Deserialize;
use uuid::Uuid;

use super::shared::{
    append_set_cookie, build_selected_session_cookie, build_session_context, ensure_csrf_token,
    is_secure_cookie, load_active_sessions, validate_csrf,
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

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/login", get(login_page).post(identifier_post))
        .route("/login/select", post(select_post))
        .route("/login/password", get(password_page).post(password_post))
        .route("/login/otp", get(otp_page).post(otp_post))
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

// ─── Form body structs ────────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
struct IdentifierForm {
    identifier: String,
    csrf_token: String,
}

#[derive(Debug, Deserialize)]
struct SelectForm {
    session_id: Uuid,
    csrf_token: String,
}

#[derive(Debug, Deserialize)]
struct PasswordForm {
    login_id: Uuid,
    identifier: String,
    credential: String,
    csrf_token: String,
}

#[derive(Debug, Deserialize)]
struct OtpForm {
    login_id: Uuid,
    identifier: String,
    credential: String,
    csrf_token: String,
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
    accounts: Vec<AccountData>,
    identifier: Option<String>,
    error: Option<String>,
) -> Response {
    let (csrf_token, csrf_cookie) = ensure_csrf_token(headers, is_secure_cookie(ctx));
    let data = IdentifierPageData {
        accounts,
        identifier,
        error,
        csrf_token,
    };
    let mut response = web::render_view(ctx, headers, "auth/login.html", data);
    if let Some(cookie) = csrf_cookie {
        append_set_cookie(&mut response, &cookie);
    }
    response
}

fn render_password_page(
    ctx: &AppState,
    headers: &HeaderMap,
    mut data: PasswordPageData,
) -> Response {
    let (csrf_token, csrf_cookie) = ensure_csrf_token(headers, is_secure_cookie(ctx));
    data.csrf_token = csrf_token;
    let mut response = web::render_view(ctx, headers, "auth/password.html", data);
    if let Some(cookie) = csrf_cookie {
        append_set_cookie(&mut response, &cookie);
    }
    response
}

fn render_otp_page(ctx: &AppState, headers: &HeaderMap, mut data: OtpPageData) -> Response {
    let (csrf_token, csrf_cookie) = ensure_csrf_token(headers, is_secure_cookie(ctx));
    data.csrf_token = csrf_token;
    let mut response = web::render_view(ctx, headers, "auth/otp.html", data);
    if let Some(cookie) = csrf_cookie {
        append_set_cookie(&mut response, &cookie);
    }
    response
}

// ─── GET Handlers ─────────────────────────────────────────────────────────────

/// `GET /login`
///
/// Renders the account picker when active sessions exist, or the identifier
/// entry form when the user has no existing sessions.
#[axum::debug_handler]
async fn login_page(State(ctx): State<AppState>, headers: HeaderMap) -> Response {
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

    render_identifier_page(&ctx, &headers, accounts, None, None)
}

/// `GET /login/password`
///
/// Renders the password entry form. Requires `login_id` and `identifier`
/// query parameters. Redirects back to `/login` if either is missing.
#[axum::debug_handler]
async fn password_page(
    State(ctx): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<PasswordQuery>,
) -> Response {
    let (Some(login_id_str), Some(identifier)) = (q.login_id, q.identifier) else {
        return Redirect::to("/login").into_response();
    };
    let Ok(login_id) = login_id_str.parse::<Uuid>() else {
        return Redirect::to("/login").into_response();
    };

    let data = PasswordPageData {
        login_id,
        identifier,
        user_name: q.name.unwrap_or_default(),
        masked_email: q.email.unwrap_or_default(),
        error: None,
        csrf_token: String::new(),
    };

    render_password_page(&ctx, &headers, data)
}

/// `GET /login/otp`
///
/// Renders the OTP/TOTP entry form. Requires `login_id` and `identifier`
/// query parameters. Redirects back to `/login` if either is missing.
#[axum::debug_handler]
async fn otp_page(
    State(ctx): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<OtpQuery>,
) -> Response {
    let (Some(login_id_str), Some(identifier)) = (q.login_id, q.identifier) else {
        return Redirect::to("/login").into_response();
    };
    let Ok(login_id) = login_id_str.parse::<Uuid>() else {
        return Redirect::to("/login").into_response();
    };

    let data = OtpPageData {
        login_id,
        identifier,
        user_name: q.name.unwrap_or_default(),
        masked_email: q.email.unwrap_or_default(),
        error: None,
        csrf_token: String::new(),
    };

    render_otp_page(&ctx, &headers, data)
}

// ─── POST Handlers ────────────────────────────────────────────────────────────

/// `POST /login/select`
///
/// Select an existing session from the account picker. Reorders the sessions
/// cookie so the chosen account is first, then redirects to `/`.
#[axum::debug_handler]
async fn select_post(
    State(ctx): State<AppState>,
    headers: HeaderMap,
    Form(body): Form<SelectForm>,
) -> Response {
    if validate_csrf(&headers, Some(&body.csrf_token)).is_err() {
        return Redirect::to("/login").into_response();
    }

    match ctx
        .services()
        .session()
        .select_session(body.session_id)
        .await
    {
        Ok(session) => {
            let cookie =
                build_selected_session_cookie(&headers, session.oid, is_secure_cookie(&ctx));
            ([(header::SET_COOKIE, cookie)], Redirect::to("/")).into_response()
        }
        Err(e) => {
            tracing::error!(error = %e, "select_session failed");
            Redirect::to("/login").into_response()
        }
    }
}

/// `POST /login`
///
/// Validate the identifier. On success, redirect to the password page.
/// On failure, re-render the login page with an inline error.
#[axum::debug_handler]
async fn identifier_post(
    State(ctx): State<AppState>,
    headers: HeaderMap,
    Form(body): Form<IdentifierForm>,
) -> Response {
    if validate_csrf(&headers, Some(&body.csrf_token)).is_err() {
        let accounts = load_account_data(&ctx, &headers).await;
        return render_identifier_page(
            &ctx,
            &headers,
            accounts,
            Some(body.identifier),
            Some(invalid_request_message(&ctx, &headers)),
        );
    }

    match ctx.services().login().identify(&body.identifier).await {
        Ok(result) => {
            // Redirect to the password page carrying the login context as
            // query parameters so the GET handler can render the form.
            let login_id = result.login.oid;
            let identifier = urlencoding::encode(&body.identifier).into_owned();
            let name = urlencoding::encode(&result.user.name).into_owned();
            let email =
                urlencoding::encode(&crate::web::views::auth::mask_email(&result.user.email))
                    .into_owned();

            let url = format!(
                "/login/password?login_id={login_id}&identifier={identifier}&name={name}&email={email}"
            );
            Redirect::to(&url).into_response()
        }
        Err(err) => {
            let locale = resolve_locale_from_headers(&headers);
            let error_msg = super::response::error_message(ctx.resources().i18n(), &locale, &err);
            let accounts = load_account_data(&ctx, &headers).await;
            render_identifier_page(
                &ctx,
                &headers,
                accounts,
                Some(body.identifier),
                Some(error_msg),
            )
        }
    }
}

/// `POST /login/password`
///
/// Verify the password credential.
/// - Authenticated  → set cookie, redirect to `/`
/// - MFA required   → redirect to `/login/otp?...`
/// - Error          → re-render password page with inline error
#[axum::debug_handler]
async fn password_post(
    State(ctx): State<AppState>,
    headers: HeaderMap,
    Form(body): Form<PasswordForm>,
) -> Response {
    if validate_csrf(&headers, Some(&body.csrf_token)).is_err() {
        return render_password_page(
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
        );
    }

    let sess_ctx = build_session_context(&headers);

    match ctx
        .services()
        .login()
        .challenge(body.login_id, "password", &body.credential, sess_ctx)
        .await
    {
        Ok(ChallengeOutcome::Authenticated { session, .. }) => {
            let cookie =
                build_selected_session_cookie(&headers, session.oid, is_secure_cookie(&ctx));
            ([(header::SET_COOKIE, cookie)], Redirect::to("/")).into_response()
        }
        Ok(ChallengeOutcome::MfaRequired { login }) => {
            // Redirect to OTP page, carrying the login context.
            let login_id = login.oid;
            let identifier = urlencoding::encode(&body.identifier).into_owned();
            let url = format!("/login/otp?login_id={login_id}&identifier={identifier}");
            Redirect::to(&url).into_response()
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
            )
        }
    }
}

/// `POST /login/otp`
///
/// Verify the TOTP code.
/// - Authenticated → set cookie, redirect to `/`
/// - Error         → re-render OTP page with inline error
#[axum::debug_handler]
async fn otp_post(
    State(ctx): State<AppState>,
    headers: HeaderMap,
    Form(body): Form<OtpForm>,
) -> Response {
    if validate_csrf(&headers, Some(&body.csrf_token)).is_err() {
        return render_otp_page(
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
        );
    }

    let sess_ctx = build_session_context(&headers);

    match ctx
        .services()
        .login()
        .challenge(body.login_id, "otp", &body.credential, sess_ctx)
        .await
    {
        Ok(ChallengeOutcome::Authenticated { session, .. }) => {
            let cookie =
                build_selected_session_cookie(&headers, session.oid, is_secure_cookie(&ctx));
            ([(header::SET_COOKIE, cookie)], Redirect::to("/")).into_response()
        }
        Ok(ChallengeOutcome::MfaRequired { .. }) => {
            // Should never happen for OTP challenge — treat as error.
            tracing::warn!("otp challenge returned MfaRequired unexpectedly");
            Redirect::to("/login").into_response()
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
            )
        }
    }
}
