//! Authentication controller handlers.
//!
//! All handlers follow the progressive login flow:
//! 1. `GET  /api/auth/sessions/active`  – list active accounts from cookie
//! 2. `POST /api/auth/login/select`     – select an existing session
//! 3. `POST /api/auth/login/identifier` – validate identifier, create login
//! 4. `POST /api/auth/login/challenge`  – verify credential, create session

use axum::{
    Router,
    extract::State,
    http::{HeaderMap, StatusCode, header},
    response::{IntoResponse, Response},
    routing::{get, post},
};

use super::{
    response::AppJson,
    shared::{
        CSRF_HEADER_NAME, append_set_cookie, build_selected_session_cookie, build_session_context,
        ensure_csrf_token, is_secure_cookie, load_active_sessions, validate_csrf,
    },
};
use crate::web::views::auth::{
    AccountItem, ActiveAccountsResponse, ChallengeRequest, ChallengeResponse, IdentifierRequest,
    IdentifierResponse, SelectAccountRequest, SelectAccountResponse, SessionInfo, UserDisplayInfo,
    mask_email,
};
use crate::{application::auth::login::ChallengeOutcome, boot::AppState};

// ─── Routes ──────────────────────────────────────────────────────────────────

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/api/auth/sessions/active", get(active_sessions))
        .route("/api/auth/login/select", post(select_account))
        .route("/api/auth/login/identifier", post(identifier))
        .route("/api/auth/login/challenge", post(challenge))
}

// ─── Handlers ────────────────────────────────────────────────────────────────

/// `GET /api/auth/sessions/active`
///
/// Read the `sessions` cookie and return the list of active accounts.
#[axum::debug_handler]
async fn active_sessions(State(ctx): State<AppState>, headers: HeaderMap) -> Response {
    let accounts = match load_active_sessions(&ctx, &headers).await {
        Ok(accounts) => accounts,
        Err(error) => {
            return super::response::error_response_from_headers(
                ctx.resources().i18n(),
                &headers,
                error,
            );
        }
    };
    let items: Vec<AccountItem> = accounts
        .into_iter()
        .map(|a| AccountItem {
            id: a.session_oid,
            name: a.user_name,
            email: a.user_email,
            last_active_at: a.last_active_at,
        })
        .collect();

    let (_, csrf_cookie) = ensure_csrf_token(&headers, is_secure_cookie(&ctx));
    let mut response = AppJson(ActiveAccountsResponse { accounts: items }).into_response();
    if let Some(cookie) = csrf_cookie {
        append_set_cookie(&mut response, &cookie);
    }

    response
}

/// `POST /api/auth/login/select`
///
/// Select an existing session by its OID, reorder the cookie so it becomes
/// the active (first) session, and touch `last_active_at`.
#[axum::debug_handler]
async fn select_account(
    State(ctx): State<AppState>,
    headers: HeaderMap,
    AppJson(body): AppJson<SelectAccountRequest>,
) -> Response {
    if let Err(error) = validate_csrf(
        &headers,
        headers
            .get(CSRF_HEADER_NAME)
            .and_then(|value| value.to_str().ok()),
    ) {
        return super::response::error_response_from_headers(
            ctx.resources().i18n(),
            &headers,
            error,
        );
    }

    let session = match ctx.services().session().select_session(body.id).await {
        Ok(session) => session,
        Err(error) => {
            return super::response::error_response_from_headers(
                ctx.resources().i18n(),
                &headers,
                error,
            );
        }
    };
    let cookie = build_selected_session_cookie(&headers, session.oid, is_secure_cookie(&ctx));

    let resp = SelectAccountResponse {
        status: "ok",
        session: SessionInfo {
            id: session.oid,
            expires_at: session.expires_at,
        },
    };

    ([(header::SET_COOKIE, cookie)], AppJson(resp)).into_response()
}

/// `POST /api/auth/login/identifier`
///
/// Validate the user identifier (email or username), create a login record,
/// and return credential types + masked user info.
#[axum::debug_handler]
async fn identifier(
    State(ctx): State<AppState>,
    headers: HeaderMap,
    AppJson(body): AppJson<IdentifierRequest>,
) -> Response {
    if let Err(error) = validate_csrf(
        &headers,
        headers
            .get(CSRF_HEADER_NAME)
            .and_then(|value| value.to_str().ok()),
    ) {
        return super::response::error_response_from_headers(
            ctx.resources().i18n(),
            &headers,
            error,
        );
    }

    let result = match ctx.services().login().identify(&body.identifier).await {
        Ok(result) => result,
        Err(error) => {
            return super::response::error_response_from_headers(
                ctx.resources().i18n(),
                &headers,
                error,
            );
        }
    };
    let resp = IdentifierResponse {
        id: result.login.oid,
        status: "identifier_verified",
        credential_types: result.credential_types,
        user: UserDisplayInfo {
            email: mask_email(&result.user.email),
            name: result.user.name.clone(),
        },
    };

    AppJson(resp).into_response()
}

/// `POST /api/auth/login/challenge`
///
/// Verify the credential (password), create a session, and set the session
/// cookie.
#[axum::debug_handler]
async fn challenge(
    State(ctx): State<AppState>,
    headers: HeaderMap,
    AppJson(body): AppJson<ChallengeRequest>,
) -> Response {
    if let Err(error) = validate_csrf(
        &headers,
        headers
            .get(CSRF_HEADER_NAME)
            .and_then(|value| value.to_str().ok()),
    ) {
        return super::response::error_response_from_headers(
            ctx.resources().i18n(),
            &headers,
            error,
        );
    }

    let session_ctx = build_session_context(&headers);

    let outcome = match ctx
        .services()
        .login()
        .challenge(
            body.id,
            &body.credential_type,
            &body.credential,
            session_ctx,
        )
        .await
    {
        Ok(outcome) => outcome,
        Err(error) => {
            return super::response::error_response_from_headers(
                ctx.resources().i18n(),
                &headers,
                error,
            );
        }
    };

    match outcome {
        ChallengeOutcome::MfaRequired { .. } => {
            // No session yet — return 200 so the client knows to call again
            // with credential_type = "otp".
            let resp = ChallengeResponse {
                status: "mfa_required",
                session: None,
                acr: None,
            };
            AppJson(resp).into_response()
        }
        ChallengeOutcome::Authenticated { session, .. } => {
            let cookie =
                build_selected_session_cookie(&headers, session.oid, is_secure_cookie(&ctx));

            let acr = session.acr.clone();
            let resp = ChallengeResponse {
                status: "authenticated",
                session: Some(SessionInfo {
                    id: session.oid,
                    expires_at: session.expires_at,
                }),
                acr,
            };

            (
                StatusCode::CREATED,
                [(header::SET_COOKIE, cookie)],
                AppJson(resp),
            )
                .into_response()
        }
    }
}
