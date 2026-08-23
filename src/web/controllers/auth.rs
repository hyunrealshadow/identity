//! Authentication controller handlers.
//!
//! All handlers follow the progressive login flow:
//! 1. `GET  /api/auth/sessions/active`  – list active accounts from `X-Sessions`
//! 2. `POST /api/auth/login/select`     – select an existing session
//! 3. `POST /api/auth/login/identifier` – validate identifier, create login
//! 4. `POST /api/auth/login/challenge`  – verify credential, create session

use http::{HeaderMap, StatusCode};
use salvo::{Depot, Request, Response, Router, handler};

use super::{
    response::{JsonWebResult, app_state, parse_json, parse_param, render_json},
    shared::{
        api_csrf_middleware, build_selected_session_state, build_session_context, csrf_token,
        load_active_session_entries, protocol_continue_uri, unprotect_session_id,
    },
};
use crate::views::auth::{
    AccountItem, ActiveAccountsResponse, ChallengeRequest, ChallengeResponse, IdentifierRequest,
    IdentifierResponse, LoginStatusResponse, SelectAccountRequest, SelectAccountResponse,
    SessionInfo, UserDisplayInfo,
};
use crate::{
    application::{
        auth::login::ChallengeOutcome,
        error::{AppError, code::AppErrorCode, codes::auth::AuthErrorCode},
        openid_connect::authorize::stored_request_has_prompt,
    },
    domain::{
        client_authorization::SelectionSource,
        user::model::{CredentialType, UserOid},
    },
    middleware::resolved_client_ip,
};

// ─── Routes ──────────────────────────────────────────────────────────────────

pub fn routes() -> Router {
    Router::new()
        .hoop(api_csrf_middleware())
        .push(Router::with_path("api/auth/sessions/active").get(active_sessions))
        .push(Router::with_path("api/auth/login/{id}").get(login_status))
        .push(Router::with_path("api/auth/login/select").post(select_account))
        .push(Router::with_path("api/auth/login/identifier").post(identifier))
        .push(Router::with_path("api/auth/login/challenge").post(challenge))
}

// ─── Handlers ────────────────────────────────────────────────────────────────

/// `GET /api/auth/sessions/active`
///
/// Read `X-Sessions` and return the list of active accounts.
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
            picture: entry.session.user_picture,
            last_active_at: entry.session.last_active_at,
        })
        .collect();

    render_json(
        res,
        StatusCode::OK,
        ActiveAccountsResponse {
            sessions: items.iter().map(|item| item.id.clone()).collect(),
            accounts: items,
            csrf_token: csrf_token(depot),
        },
    );

    Ok(())
}

#[handler]
async fn login_status(
    depot: &mut Depot,
    req: &mut Request,
    res: &mut Response,
) -> JsonWebResult<()> {
    let ctx = app_state(depot)?;
    let id: String = parse_param(req, "id")?;
    let login_oid = ctx
        .services()
        .oidc_authorize()
        .decrypt_login_id(&id)
        .await?;
    let login = ctx.services().login().get(login_oid).await?;

    let (user, credential_types) = match login.user_oid {
        Some(user_oid) => {
            let user_oid = UserOid::from(user_oid);
            let credential_types = ctx.services().login().credential_types(user_oid).await?;
            let user = ctx.services().login().get_user(user_oid).await?;
            (
                Some(UserDisplayInfo {
                    email: user.email,
                    name: user.name,
                    picture: user.picture,
                }),
                credential_types,
            )
        }
        None => (None, Vec::new()),
    };

    let (prompt, requires_reauthentication, ui_locales) = match ctx
        .services()
        .oidc_authorize()
        .load_continue_context_by_login(&id)
        .await
    {
        Ok(c) => (
            c.stored
                .request
                .prompt
                .unwrap_or_else(|| "select_account".to_string()),
            c.stored.interaction.selection_source == Some(SelectionSource::Reauthentication),
            c.stored.request.ui_locales,
        ),
        Err(_) => ("select_account".to_string(), false, None),
    };

    let continue_uri = if login.status == identity_domain::auth::LoginStatus::AUTHENTICATED {
        Some(protocol_continue_uri(&ctx, &id)?)
    } else {
        None
    };
    let challenge_uri = if user.is_some()
        && (stored_request_has_prompt(Some(prompt.as_str()), "login") || requires_reauthentication)
    {
        let credential_type =
            if requires_reauthentication && credential_types.contains(&CredentialType::Otp) {
                CredentialType::Otp
            } else if credential_types.contains(&CredentialType::Password) {
                CredentialType::Password
            } else {
                credential_types
                    .first()
                    .cloned()
                    .unwrap_or(CredentialType::Password)
            };
        Some(login_challenge_uri(
            &id,
            &credential_type.to_string(),
            ui_locales.as_deref(),
        ))
    } else {
        None
    };

    render_json(
        res,
        StatusCode::OK,
        LoginStatusResponse {
            id,
            status: login.status,
            user,
            credential_types,
            prompt,
            requires_reauthentication,
            challenge_uri,
            ui_locales,
            continue_uri,
        },
    );
    Ok(())
}

fn login_challenge_uri(
    login_id: &str,
    credential_type: &str,
    ui_locales: Option<&[String]>,
) -> String {
    let mut query = url::form_urlencoded::Serializer::new(String::new());
    query.append_pair("login_id", login_id);
    query.append_pair("credential_type", credential_type);
    if let Some(ui_locales) = ui_locales.filter(|values| !values.is_empty()) {
        query.append_pair("ui_locales", &ui_locales.join(" "));
    }
    format!("/login/challenge?{}", query.finish())
}

#[handler]
async fn select_account(
    depot: &mut Depot,
    req: &mut Request,
    res: &mut Response,
) -> JsonWebResult<()> {
    let ctx = app_state(depot)?;
    let headers: HeaderMap = req.headers().clone();
    let body: SelectAccountRequest = parse_json(req).await?;

    // A forced login or AAL elevation is bound to the original subject. It
    // must never become an account-selection flow.
    let continue_context = ctx
        .services()
        .oidc_authorize()
        .load_continue_context_by_login(&body.login_id)
        .await?;
    if stored_request_has_prompt(continue_context.stored.request.prompt.as_deref(), "login")
        || continue_context.stored.interaction.selection_source
            == Some(SelectionSource::Reauthentication)
    {
        return Err(AppError::from_code(AuthErrorCode::InvalidLoginState).into());
    }

    let session_oid = unprotect_session_id(&ctx, &body.id).await?;
    let session = ctx.services().session().select_session(session_oid).await?;
    let selected = build_selected_session_state(&ctx, &headers, session.oid).await?;
    ctx.services()
        .oidc_authorize()
        .record_selection_by_login(
            &body.login_id,
            session.oid,
            session.user_oid,
            Some(selected.protected_session_id.clone()),
            SelectionSource::AccountPicker,
        )
        .await?;

    let resp = SelectAccountResponse {
        status: "ok",
        session: SessionInfo {
            id: selected.protected_session_id.clone(),
            expires_at: session.expires_at,
        },
        sessions: selected.protected_session_ids,
        continue_uri: protocol_continue_uri(&ctx, &body.login_id)?,
    };

    render_json(res, StatusCode::OK, resp);
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
        .await
        .map_err(identifier_form_error)?;
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
            email: result.user.email.clone(),
            name: result.user.name.clone(),
            picture: result.user.picture.clone(),
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

    let session_ctx = build_session_context(&headers, resolved_client_ip(depot));
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
        .await
        .map_err(challenge_form_error)?;

    match outcome {
        ChallengeOutcome::MfaRequired { .. } => {
            render_json(
                res,
                StatusCode::OK,
                ChallengeResponse {
                    status: "mfa_required",
                    session: None,
                    acr: None,
                    continue_uri: None,
                    sessions: None,
                },
            );
        }
        ChallengeOutcome::Authenticated { session, .. } => {
            let selected = build_selected_session_state(&ctx, &headers, session.oid).await?;
            ctx.services()
                .oidc_authorize()
                .record_selection_by_login(
                    &body.id,
                    session.oid,
                    session.user_oid,
                    Some(selected.protected_session_id.clone()),
                    SelectionSource::FreshLogin,
                )
                .await?;
            let acr = session.acr.clone();
            let continue_uri = Some(protocol_continue_uri(&ctx, &body.id)?);

            render_json(
                res,
                StatusCode::CREATED,
                ChallengeResponse {
                    status: "authenticated",
                    session: Some(SessionInfo {
                        id: selected.protected_session_id.clone(),
                        expires_at: session.expires_at,
                    }),
                    acr,
                    continue_uri,
                    sessions: Some(selected.protected_session_ids),
                },
            );
        }
    }
    Ok(())
}

fn identifier_form_error(error: AppError) -> AppError {
    let code = error.code();
    if code == AuthErrorCode::UserNotFound.code()
        || code == AuthErrorCode::IdentifierRequired.code()
    {
        error.with_field("identifier")
    } else {
        error
    }
}

fn challenge_form_error(error: AppError) -> AppError {
    let code = error.code();
    if code == AuthErrorCode::InvalidCredential.code() || code == AuthErrorCode::InvalidOtp.code() {
        error.with_field("credential")
    } else {
        error
    }
}

#[cfg(test)]
mod form_error_tests {
    use super::{challenge_form_error, identifier_form_error};
    use crate::application::error::{
        AppError,
        codes::{auth::AuthErrorCode, common::CommonErrorCode},
        kind::ErrorKind,
    };

    #[test]
    fn identifier_errors_are_attached_to_identifier_field() {
        let error = identifier_form_error(AppError::from_code(AuthErrorCode::IdentifierRequired));

        assert_eq!(error.kind(), ErrorKind::Validation);
        let fields = error.validation().expect("field details").fields();
        assert_eq!(fields.len(), 1);
        assert_eq!(fields[0].field(), "identifier");
        assert_eq!(fields[0].code(), 11012);
    }

    #[test]
    fn invalid_credentials_keep_unauthorized_status_and_attach_field() {
        let error = challenge_form_error(AppError::from_code(AuthErrorCode::InvalidCredential));

        assert_eq!(error.kind(), ErrorKind::Unauthorized);
        let fields = error.validation().expect("field details").fields();
        assert_eq!(fields.len(), 1);
        assert_eq!(fields[0].field(), "credential");
        assert_eq!(fields[0].code(), 11001);
    }

    #[test]
    fn login_state_errors_remain_page_level() {
        let error = identifier_form_error(AppError::from_code(CommonErrorCode::InternalError));

        assert!(error.validation().is_none());
    }
}
