//! Authentication controller handlers.
//!
//! All handlers follow the progressive login flow:
//! 1. `GET  /api/auth/sessions/active`  – list active accounts from cookie
//! 2. `POST /api/auth/login/select`     – select an existing session
//! 3. `POST /api/auth/login/identifier` – validate identifier, create login
//! 4. `POST /api/auth/login/challenge`  – verify credential, create session

use http::{HeaderMap, StatusCode};
use salvo::{Depot, Request, Response, Router, handler};

use super::{
    response::{app_state, parse_json, parse_param, render_json, JsonWebResult},
    shared::{
        append_set_cookie, build_selected_session_cookie, build_session_context, csrf_middleware,
        csrf_token, is_secure_cookie, load_active_session_entries, unprotect_session_id,
    },
};
use crate::views::auth::{
    AccountItem, ActiveAccountsResponse, ChallengeRequest, ChallengeResponse, IdentifierRequest,
    IdentifierResponse, LoginStatusResponse, SelectAccountRequest, SelectAccountResponse,
    SessionInfo, UserDisplayInfo, mask_email,
};
use crate::{application::auth::login::ChallengeOutcome, domain::user::model::UserOid};

// ─── Routes ──────────────────────────────────────────────────────────────────

pub fn routes() -> Router {
    Router::new()
        .hoop(csrf_middleware())
        .push(Router::with_path("api/auth/sessions/active").get(active_sessions))
        .push(Router::with_path("api/auth/login/{id}").get(login_status))
        .push(Router::with_path("api/auth/login/select").post(select_account))
        .push(Router::with_path("api/auth/login/identifier").post(identifier))
        .push(Router::with_path("api/auth/login/challenge").post(challenge))
}

// ─── Handlers ────────────────────────────────────────────────────────────────

/// `GET /api/auth/sessions/active`
///
/// Read the `sessions` cookie and return the list of active accounts.
#[handler]
async fn active_sessions(
    depot: &mut Depot,
    req: &mut Request,
    res: &mut Response,
) -> JsonWebResult<()> {
    let ctx = app_state(depot)?;
    let headers = req.headers().clone();
    let accounts = load_active_session_entries(&ctx, &headers).await?;
    let items: Vec<AccountItem> = accounts
        .into_iter()
        .map(|entry| AccountItem {
            id: entry.protected_session_id,
            name: entry.session.user_name,
            email: entry.session.user_email,
            last_active_at: entry.session.last_active_at,
        })
        .collect();

    render_json(
        res,
        StatusCode::OK,
        ActiveAccountsResponse {
            accounts: items,
            csrf_token: csrf_token(depot),
        },
    );

    Ok(())
}

#[handler]
async fn login_status(depot: &mut Depot, req: &mut Request, res: &mut Response) -> JsonWebResult<()> {
    let ctx = app_state(depot)?;
    let id: String = parse_param(req, "id")?;
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
            })
            .map(Some)?,
        None => None,
    };

    render_json(
        res,
        StatusCode::OK,
        LoginStatusResponse {
            id,
            status: login.status,
            user,
        },
    );
    Ok(())
}

#[handler]
async fn select_account(depot: &mut Depot, req: &mut Request, res: &mut Response) -> JsonWebResult<()> {
    let ctx = app_state(depot)?;
    let headers: HeaderMap = req.headers().clone();
    let body: SelectAccountRequest = parse_json(req).await?;

    let session_oid = unprotect_session_id(&ctx, &body.id).await?;
    let session = ctx.services().session().select_session(session_oid).await?;
    let cookie =
        build_selected_session_cookie(&ctx, &headers, session.oid, is_secure_cookie(&ctx)).await?;

    let resp = SelectAccountResponse {
        status: "ok",
        session: SessionInfo {
            id: cookie.protected_session_id.clone(),
            expires_at: session.expires_at,
        },
    };

    render_json(res, StatusCode::OK, resp);
    append_set_cookie(res, &cookie.header);
    Ok(())
}

#[handler]
async fn identifier(depot: &mut Depot, req: &mut Request, res: &mut Response) -> JsonWebResult<()> {
    let ctx = app_state(depot)?;
    let body: IdentifierRequest = parse_json(req).await?;

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

    render_json(res, StatusCode::OK, resp);
    Ok(())
}

#[handler]
async fn challenge(depot: &mut Depot, req: &mut Request, res: &mut Response) -> JsonWebResult<()> {
    let ctx = app_state(depot)?;
    let headers: HeaderMap = req.headers().clone();
    let body: ChallengeRequest = parse_json(req).await?;

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
        ChallengeOutcome::MfaRequired { .. } => {
            render_json(
                res,
                StatusCode::OK,
                ChallengeResponse {
                    status: "mfa_required",
                    session: None,
                    acr: None,
                },
            );
        }
        ChallengeOutcome::Authenticated { session, .. } => {
            let cookie =
                build_selected_session_cookie(&ctx, &headers, session.oid, is_secure_cookie(&ctx))
                    .await?;
            let acr = session.acr.clone();

            render_json(
                res,
                StatusCode::CREATED,
                ChallengeResponse {
                    status: "authenticated",
                    session: Some(SessionInfo {
                        id: cookie.protected_session_id.clone(),
                        expires_at: session.expires_at,
                    }),
                    acr,
                },
            );
            append_set_cookie(res, &cookie.header);
        }
    }
    Ok(())
}
