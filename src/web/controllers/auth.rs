//! Authentication controller handlers.
//!
//! All handlers follow the progressive login flow:
//! 1. `GET  /api/auth/sessions/active`  – list active accounts from cookie
//! 2. `POST /api/auth/login/select`     – select an existing session
//! 3. `POST /api/auth/login/identifier` – validate identifier, create login
//! 4. `POST /api/auth/login/challenge`  – verify credential, create session

use axum::{
    Router,
    extract::{Path, State},
    http::{HeaderMap, StatusCode, header},
    response::{IntoResponse, Response},
    routing::{get, post},
};

use crate::application::error::AppError;

use super::{
    response::AppJson,
    shared::{
        CSRF_HEADER_NAME, append_set_cookie, build_selected_session_cookie, build_session_context,
        ensure_csrf_token, is_secure_cookie, load_active_sessions, validate_csrf,
    },
};
use crate::web::views::auth::{
    AccountItem, ActiveAccountsResponse, ChallengeRequest, ChallengeResponse, IdentifierRequest,
    IdentifierResponse, LoginStatusResponse, SelectAccountRequest, SelectAccountResponse,
    SessionInfo, UserDisplayInfo, mask_email,
};
use crate::{
    application::auth::login::ChallengeOutcome, boot::AppState, domain::user::model::UserOid,
};

// ─── Routes ──────────────────────────────────────────────────────────────────

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/api/auth/sessions/active", get(active_sessions))
        .route("/api/auth/login/{id}", get(login_status))
        .route("/api/auth/login/select", post(select_account))
        .route("/api/auth/login/identifier", post(identifier))
        .route("/api/auth/login/challenge", post(challenge))
}

// ─── Handlers ────────────────────────────────────────────────────────────────

/// `GET /api/auth/sessions/active`
///
/// Read the `sessions` cookie and return the list of active accounts.
#[axum::debug_handler]
async fn active_sessions(
    State(ctx): State<AppState>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let accounts = load_active_sessions(&ctx, &headers).await?;
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

    Ok(response)
}

#[axum::debug_handler]
async fn login_status(
    State(ctx): State<AppState>,
    Path(id): Path<String>,
) -> Result<Response, AppError> {
    let login_oid = ctx
        .services()
        .oidc_authorize()
        .decrypt_login_id(&id)
        .await?;
    let login = ctx.services().login().get(login_oid).await?;

    let user = match login.user_oid {
        Some(user_oid) => ctx
            .services()
            .login()
            .get_user(UserOid::from(user_oid))
            .await
            .map(|user| UserDisplayInfo {
                email: mask_email(&user.email),
                name: user.name,
            }),
        None => None,
    };

    Ok(AppJson(LoginStatusResponse {
        id,
        status: login.status,
        user,
    })
    .into_response())
}

#[axum::debug_handler]
async fn select_account(
    State(ctx): State<AppState>,
    headers: HeaderMap,
    AppJson(body): AppJson<SelectAccountRequest>,
) -> Result<Response, AppError> {
    validate_csrf(
        &headers,
        headers
            .get(CSRF_HEADER_NAME)
            .and_then(|value| value.to_str().ok()),
    )?;

    let session = ctx.services().session().select_session(body.id).await?;
    let cookie = build_selected_session_cookie(&headers, session.oid, is_secure_cookie(&ctx));

    let resp = SelectAccountResponse {
        status: "ok",
        session: SessionInfo {
            id: session.oid,
            expires_at: session.expires_at,
        },
    };

    Ok(([(header::SET_COOKIE, cookie)], AppJson(resp)).into_response())
}

#[axum::debug_handler]
async fn identifier(
    State(ctx): State<AppState>,
    headers: HeaderMap,
    AppJson(body): AppJson<IdentifierRequest>,
) -> Result<Response, AppError> {
    validate_csrf(
        &headers,
        headers
            .get(CSRF_HEADER_NAME)
            .and_then(|value| value.to_str().ok()),
    )?;

    let login_oid = ctx
        .services()
        .oidc_authorize()
        .decrypt_login_id(&body.id)
        .await?;
    let result = ctx
        .services()
        .login()
        .identify(login_oid, &body.identifier)
        .await?;
    let protected_id = ctx
        .services()
        .oidc_authorize()
        .encrypt_login_id(result.login.oid)
        .await?;

    let resp = IdentifierResponse {
        id: protected_id,
        status: "identifier_verified",
        credential_types: result.credential_types,
        user: UserDisplayInfo {
            email: mask_email(&result.user.email),
            name: result.user.name.clone(),
        },
    };

    Ok(AppJson(resp).into_response())
}

#[axum::debug_handler]
async fn challenge(
    State(ctx): State<AppState>,
    headers: HeaderMap,
    AppJson(body): AppJson<ChallengeRequest>,
) -> Result<Response, AppError> {
    validate_csrf(
        &headers,
        headers
            .get(CSRF_HEADER_NAME)
            .and_then(|value| value.to_str().ok()),
    )?;

    let session_ctx = build_session_context(&headers);
    let login_oid = ctx
        .services()
        .oidc_authorize()
        .decrypt_login_id(&body.id)
        .await?;

    let outcome = ctx
        .services()
        .login()
        .challenge(
            login_oid,
            &body.credential_type,
            &body.credential,
            session_ctx,
        )
        .await?;

    match outcome {
        ChallengeOutcome::MfaRequired { .. } => Ok(AppJson(ChallengeResponse {
            status: "mfa_required",
            session: None,
            acr: None,
        })
        .into_response()),
        ChallengeOutcome::Authenticated { session, .. } => {
            let cookie =
                build_selected_session_cookie(&headers, session.oid, is_secure_cookie(&ctx));
            let acr = session.acr.clone();

            Ok((
                StatusCode::CREATED,
                [(header::SET_COOKIE, cookie)],
                AppJson(ChallengeResponse {
                    status: "authenticated",
                    session: Some(SessionInfo {
                        id: session.oid,
                        expires_at: session.expires_at,
                    }),
                    acr,
                }),
            )
                .into_response())
        }
    }
}
