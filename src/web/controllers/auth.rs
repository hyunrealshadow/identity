//! Authentication controller handlers.
//!
//! All handlers follow the progressive login flow:
//! 1. `GET  /api/auth/sessions/active`  – list active accounts from `X-Sessions`
//! 2. `POST /api/auth/login/select`     – select an existing session
//! 3. `POST /api/auth/login/identifier` – validate identifier, create login
//! 4. `POST /api/auth/login/email-code` – email a sign-in code and link
//!    (optional first factor)
//!    `POST /api/auth/login/password-reset[/check|/confirm]` – email a link
//!    that replaces a forgotten password, then set the new one
//! 5. `POST /api/auth/login/challenge`  – verify credential, create session
//! 6. `POST /api/auth/login/mfa-enrollment[/confirm]` – enroll a missing
//!    second factor when the request requires `aal2`
//! 7. `POST /api/auth/login/passkey-enrollment[/confirm]` – register a passkey
//!    when the request requires `phr`

use http::{HeaderMap, StatusCode};
use identity_domain::auth::LoginStatus;
use salvo::{Depot, Request, Response, Router, handler};
use url::form_urlencoded::Serializer;
use urlencoding::encode;

use super::{
    response::{JsonWebResult, app_state, parse_json, parse_param, render_json},
    shared::{
        api_csrf_middleware, build_selected_session_state, build_session_context, csrf_token,
        load_active_session_entries, parse_session_header, protocol_continue_uri,
        unprotect_session_id,
    },
};
use crate::{
    application::{
        authentication::{login, login::ChallengeOutcome},
        error::{AppError, code::AppErrorCode, codes::auth::AuthErrorCode},
        openid_connect::authorize::stored_request_has_prompt,
        user::CredentialType,
    },
    domain::{
        client_authorization::SelectionSource, openid_connect::PromptValue, user::model::UserOid,
    },
    middleware::resolved_client_ip,
    views::auth::{
        AccountItem, ActiveAccountsResponse, ChallengeRequest, ChallengeResponse,
        EmailCodeRequest as EmailCodeRequestBody, EmailCodeResponse, IdentifierRequest,
        IdentifierResponse, LoginClientDisplay, LoginStatusResponse, MfaEnrollmentAlgorithmRequest,
        MfaEnrollmentConfirmRequest, MfaEnrollmentRequest, MfaEnrollmentResponse,
        PasskeyEnrollmentConfirmRequest, PasskeyEnrollmentResponse, PasswordResetCheckRequest,
        PasswordResetConfirmRequest, PasswordResetStatusResponse, RequiredPasswordChangeRequest,
        RestartLoginRequest, RestartLoginResponse, SelectAccountRequest, SelectAccountResponse,
        SessionInfo, SwitchLoginRequest, SwitchLoginResponse, UserDisplayInfo,
    },
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
        .push(Router::with_path("api/auth/login/email-code").post(email_code))
        .push(Router::with_path("api/auth/login/password-reset").post(password_reset))
        .push(Router::with_path("api/auth/login/password-change").post(required_password_change))
        .push(Router::with_path("api/auth/login/password-reset/check").post(check_password_reset))
        .push(
            Router::with_path("api/auth/login/password-reset/confirm").post(confirm_password_reset),
        )
        .push(Router::with_path("api/auth/login/passkey/options").post(passkey_options))
        .push(Router::with_path("api/auth/login/restart").post(restart_login))
        .push(Router::with_path("api/auth/login/switch").post(switch_login))
        .push(Router::with_path("api/auth/login/mfa-enrollment").post(mfa_enrollment))
        .push(
            Router::with_path("api/auth/login/mfa-enrollment/algorithm")
                .post(change_mfa_enrollment_algorithm),
        )
        .push(
            Router::with_path("api/auth/login/mfa-enrollment/confirm").post(confirm_mfa_enrollment),
        )
        .push(Router::with_path("api/auth/login/passkey-enrollment").post(passkey_enrollment))
        .push(
            Router::with_path("api/auth/login/passkey-enrollment/confirm")
                .post(confirm_passkey_enrollment),
        )
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
    let login = ctx.services().login().prepare_challenge(login_oid).await?;

    let concealed_identifier = login.concealed_identifier().map(str::to_owned);
    let (user, credential_types, mfa_preference) = match login.user_oid {
        _ if concealed_identifier.is_some() => (
            None,
            ctx.services().login().concealed_credential_types(),
            Default::default(),
        ),
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
                user.preferred_mfa_method,
            )
        }
        None => (None, Vec::new(), Default::default()),
    };

    let (prompt, requires_reauthentication, login_hint, ui_locales, client) = match ctx
        .services()
        .oidc_authorize()
        .load_continue_context_by_login(&id)
        .await
    {
        Ok(c) => (
            c.stored
                .request
                .prompt
                .unwrap_or_else(|| [PromptValue::SelectAccount].into_iter().collect()),
            c.stored.interaction.selection_source == Some(SelectionSource::Reauthentication),
            c.stored.request.login_hint,
            c.stored.request.ui_locales,
            Some(LoginClientDisplay {
                name: c.client.client().name.clone(),
                logo_uri: c
                    .client
                    .metadata()
                    .logo_uri
                    .as_ref()
                    .map(ToString::to_string),
                policy_uri: c
                    .client
                    .metadata()
                    .policy_uri
                    .as_ref()
                    .map(ToString::to_string),
                tos_uri: c
                    .client
                    .metadata()
                    .tos_uri
                    .as_ref()
                    .map(ToString::to_string),
            }),
        ),
        Err(_) => (
            [PromptValue::SelectAccount].into_iter().collect(),
            false,
            None,
            None,
            None,
        ),
    };

    let is_device = ctx
        .services()
        .oidc_device_authorization()
        .login_request(&login)
        .await?
        .is_some();
    let continue_uri = if login.status == LoginStatus::AUTHENTICATED {
        Some(if is_device {
            format!("/device?login_id={}", encode(&id))
        } else {
            protocol_continue_uri(&ctx, &id)?
        })
    } else {
        None
    };
    let email_code_resend_available_at = ctx
        .services()
        .login()
        .email_code_resend_available_at(&login)
        .await?;
    let password_reset_available = ctx
        .services()
        .login()
        .password_reset_offered(&login)
        .await?;
    let password_reset_resend_available_at = ctx
        .services()
        .login()
        .password_reset_resend_available_at(&login)
        .await?;
    let preferred_credential_type =
        login::preferred_credential_type(&login, &credential_types, mfa_preference);
    let credential_types = login::challenge_credential_types(&login, &credential_types);
    let enrollment_method = (login.status == LoginStatus::MFA_ENROLLMENT_REQUIRED)
        .then(|| login::enrollment_method(&login));
    let challenge_uri = if login.status == LoginStatus::PASSWORD_CHANGE_REQUIRED {
        Some(login_password_change_uri(&id, ui_locales.as_deref()))
    } else if let Some(method) = enrollment_method.filter(|_| user.is_some()) {
        Some(login_enrollment_uri(&id, method, ui_locales.as_deref()))
    } else if user.is_some()
        && (stored_request_has_prompt(Some(&prompt), PromptValue::Login)
            || requires_reauthentication)
        && preferred_credential_type.is_some()
    {
        let credential_type = preferred_credential_type.unwrap();
        Some(login_challenge_uri(
            &id,
            credential_type.as_ref(),
            ui_locales.as_deref(),
        ))
    } else {
        None
    };

    render_json(
        res,
        StatusCode::OK,
        LoginStatusResponse {
            client,
            id,
            status: login.status,
            user,
            identifier: concealed_identifier,
            credential_types,
            preferred_credential_type,
            prompt: {
                let mut values = prompt.iter().map(AsRef::as_ref).collect::<Vec<_>>();
                values.sort_unstable();
                values.join(" ")
            },
            requires_reauthentication,
            login_hint,
            challenge_uri,
            enrollment_method,
            ui_locales,
            email_code_resend_available_at,
            password_reset_available,
            password_reset_resend_available_at,
            continue_uri,
        },
    );
    Ok(())
}

fn login_enrollment_uri(
    login_id: &str,
    method: CredentialType,
    ui_locales: Option<&[String]>,
) -> String {
    let page = match method {
        CredentialType::Passkey => "passkey-setup",
        _ => "mfa-setup",
    };
    let mut query = Serializer::new(String::new());
    query.append_pair("login_id", login_id);
    if let Some(ui_locales) = ui_locales.filter(|values| !values.is_empty()) {
        query.append_pair("ui_locales", &ui_locales.join(" "));
    }
    format!("/login/{page}?{}", query.finish())
}

fn login_challenge_uri(
    login_id: &str,
    credential_type: &str,
    ui_locales: Option<&[String]>,
) -> String {
    let mut query = Serializer::new(String::new());
    query.append_pair("login_id", login_id);
    if let Some(ui_locales) = ui_locales.filter(|values| !values.is_empty()) {
        query.append_pair("ui_locales", &ui_locales.join(" "));
    }
    let method = match credential_type {
        "recovery_code" => "recovery-code",
        method => method,
    };
    format!("/login/{}?{}", encode(method), query.finish())
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

    let device_login = ctx
        .services()
        .oidc_authorize()
        .load_login_by_protected_id(&body.login_id)
        .await?;
    let is_device = ctx
        .services()
        .oidc_device_authorization()
        .login_request(&device_login)
        .await?
        .is_some();
    // A forced login or AAL elevation is bound to the original subject. It
    // must never become an account-selection flow.
    if !is_device {
        let continue_context = ctx
            .services()
            .oidc_authorize()
            .load_continue_context_by_login(&body.login_id)
            .await?;
        if stored_request_has_prompt(
            continue_context.stored.request.prompt.as_ref(),
            PromptValue::Login,
        ) || continue_context.stored.interaction.selection_source
            == Some(SelectionSource::Reauthentication)
        {
            return Err(AppError::from_code(AuthErrorCode::InvalidLoginState).into());
        }
    }

    let session_oid = unprotect_session_id(&ctx, &body.id).await?;
    let session = ctx.services().session().select_session(session_oid).await?;
    let selected = build_selected_session_state(&ctx, &headers, session.oid).await?;
    if is_device {
        ctx.services()
            .oidc_device_authorization()
            .complete_login(&device_login, session.oid)
            .await?;
    } else {
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
    }

    let resp = SelectAccountResponse {
        status: "ok",
        session: SessionInfo {
            id: selected.protected_session_id.clone(),
            expires_at: session.expires_at,
        },
        sessions: selected.protected_session_ids,
        continue_uri: if is_device {
            format!("/device?login_id={}", encode(&body.login_id))
        } else {
            protocol_continue_uri(&ctx, &body.login_id)?
        },
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
        status: LoginStatus::IdentifierVerified,
        credential_types: result.credential_types,
        preferred_credential_type: result.preferred_credential_type,
        identifier: result.login.concealed_identifier().map(str::to_owned),
        user: result.user.map(|user| UserDisplayInfo {
            email: user.email,
            name: user.name,
            picture: user.picture,
        }),
    };

    render_json(res, StatusCode::OK, resp);
    Ok(())
}

#[handler]
async fn restart_login(
    depot: &mut Depot,
    req: &mut Request,
    res: &mut Response,
) -> JsonWebResult<()> {
    let ctx = app_state(depot)?;
    let body: RestartLoginRequest = parse_json(req).await?;
    let id = ctx
        .services()
        .oidc_authorize()
        .restart_login_flow(&body.id)
        .await?;

    render_json(res, StatusCode::CREATED, RestartLoginResponse { id });
    Ok(())
}

#[handler]
async fn switch_login(
    depot: &mut Depot,
    req: &mut Request,
    res: &mut Response,
) -> JsonWebResult<()> {
    let ctx = app_state(depot)?;
    let body: SwitchLoginRequest = parse_json(req).await?;
    let id = ctx
        .services()
        .oidc_authorize()
        .switch_login_account(&body.id)
        .await?;

    render_json(res, StatusCode::OK, SwitchLoginResponse { id });
    Ok(())
}

#[handler]
async fn passkey_options(
    depot: &mut Depot,
    req: &mut Request,
    res: &mut Response,
) -> JsonWebResult<()> {
    #[derive(serde::Deserialize)]
    struct Input {
        id: String,
    }
    let ctx = app_state(depot)?;
    let body: Input = parse_json(req).await?;
    let login_oid = ctx
        .services()
        .oidc_authorize()
        .decrypt_login_id(&body.id)
        .await?;
    let options = ctx.services().login().passkey_options(login_oid).await?;
    render_json(res, StatusCode::OK, options);
    Ok(())
}

/// `POST /api/auth/login/email-code`
///
/// Email a one-time code and a sign-in link for a login waiting for its
/// first factor. While the login conceals whether an account exists, the
/// answer is the same whether or not anything was sent.
#[handler]
async fn email_code(depot: &mut Depot, req: &mut Request, res: &mut Response) -> JsonWebResult<()> {
    let ctx = app_state(depot)?;
    let body: EmailCodeRequestBody = parse_json(req).await?;
    let login_oid = ctx
        .services()
        .oidc_authorize()
        .decrypt_login_id(&body.id)
        .await?;
    let (application_name, ui_locales) = match ctx
        .services()
        .oidc_authorize()
        .load_continue_context_by_login(&body.id)
        .await
    {
        Ok(context) => (
            Some(context.client.client().name.clone()),
            context.stored.request.ui_locales,
        ),
        Err(_) => (None, None),
    };
    let link_prefix = login_link_prefix(&ctx, "login/email", &body.id, ui_locales.as_deref())?;
    let mut locales = ui_locales.unwrap_or_default();
    locales.extend(body.locales);
    let sent = ctx
        .services()
        .login()
        .send_email_code(login::EmailCodeRequest {
            login_oid,
            locales,
            application_name,
            link_prefix,
        })
        .await?;
    render_json(
        res,
        StatusCode::OK,
        EmailCodeResponse {
            status: "sent",
            expires_at: sent.expires_at,
            resend_available_at: sent.resend_available_at,
        },
    );
    Ok(())
}

/// The login application page `route` for `login_id`, ending where an
/// emailed link token is appended.
fn login_link_prefix(
    ctx: &crate::boot::AppState,
    route: &str,
    login_id: &str,
    ui_locales: Option<&[String]>,
) -> Result<String, AppError> {
    use crate::application::setting::SettingsSource as _;
    let login_domain = ctx
        .settings()
        .store()
        .snapshot()
        .section::<crate::application::setting::AppSettings>()
        .login_domain
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| {
            AppError::from_code(
                crate::application::error::codes::authorize_http::AuthorizeHttpErrorCode::LoginDomainNotConfigured,
            )
            .with_param("route", route.to_owned())
        })?;
    let mut url = url::Url::parse(login_domain.trim())
        .and_then(|base| base.join(route))
        .map_err(|error| {
            AppError::from_code(
                crate::application::error::codes::authorize_http::AuthorizeHttpErrorCode::LoginDomainNotConfigured,
            )
            .with_param("route", route.to_owned())
            .with_source(error)
        })?;
    {
        let mut query = url.query_pairs_mut();
        query.append_pair("login_id", login_id);
        if let Some(ui_locales) = ui_locales.filter(|values| !values.is_empty()) {
            query.append_pair("ui_locales", &ui_locales.join(" "));
        }
    }
    // The token is base64url, so it needs no further encoding.
    Ok(format!("{url}&token="))
}

/// `POST /api/auth/login/password-reset`
///
/// Email a link that replaces a forgotten password, for a login waiting for
/// its first factor. While the login conceals whether an account exists, the
/// answer is the same whether or not anything was sent.
#[handler]
async fn password_reset(
    depot: &mut Depot,
    req: &mut Request,
    res: &mut Response,
) -> JsonWebResult<()> {
    let ctx = app_state(depot)?;
    let body: EmailCodeRequestBody = parse_json(req).await?;
    let login_oid = ctx
        .services()
        .oidc_authorize()
        .decrypt_login_id(&body.id)
        .await?;
    let (application_name, ui_locales) = match ctx
        .services()
        .oidc_authorize()
        .load_continue_context_by_login(&body.id)
        .await
    {
        Ok(context) => (
            Some(context.client.client().name.clone()),
            context.stored.request.ui_locales,
        ),
        Err(_) => (None, None),
    };
    let link_prefix = login_link_prefix(
        &ctx,
        "login/reset-password",
        &body.id,
        ui_locales.as_deref(),
    )?;
    let mut locales = ui_locales.unwrap_or_default();
    locales.extend(body.locales);
    let sent = ctx
        .services()
        .login()
        .send_password_reset(login::PasswordResetRequest {
            login_oid,
            locales,
            application_name,
            link_prefix,
        })
        .await?;
    render_json(
        res,
        StatusCode::OK,
        EmailCodeResponse {
            status: "sent",
            expires_at: sent.expires_at,
            resend_available_at: sent.resend_available_at,
        },
    );
    Ok(())
}

/// `POST /api/auth/login/password-reset/check`
///
/// Whether a reset link can still be used, without using it.
#[handler]
async fn check_password_reset(
    depot: &mut Depot,
    req: &mut Request,
    res: &mut Response,
) -> JsonWebResult<()> {
    let ctx = app_state(depot)?;
    let body: PasswordResetCheckRequest = parse_json(req).await?;
    let login_oid = ctx
        .services()
        .oidc_authorize()
        .decrypt_login_id(&body.id)
        .await?;
    ctx.services()
        .login()
        .check_password_reset_link(login_oid, &body.token)
        .await?;
    render_json(
        res,
        StatusCode::OK,
        PasswordResetStatusResponse { status: "valid" },
    );
    Ok(())
}

/// `POST /api/auth/login/password-reset/confirm`
///
/// Replace the password with a reset link. The login returns to its password
/// step; every session of the account ends.
#[handler]
async fn confirm_password_reset(
    depot: &mut Depot,
    req: &mut Request,
    res: &mut Response,
) -> JsonWebResult<()> {
    let ctx = app_state(depot)?;
    let body: PasswordResetConfirmRequest = parse_json(req).await?;
    let login_oid = ctx
        .services()
        .oidc_authorize()
        .decrypt_login_id(&body.id)
        .await?;
    ctx.services()
        .login()
        .reset_password(login_oid, &body.token, &body.new_password)
        .await?;
    render_json(
        res,
        StatusCode::OK,
        PasswordResetStatusResponse {
            status: "password_reset",
        },
    );
    Ok(())
}

#[handler]
async fn challenge(depot: &mut Depot, req: &mut Request, res: &mut Response) -> JsonWebResult<()> {
    let ctx = app_state(depot)?;
    let headers: HeaderMap = req.headers().clone();
    let body: ChallengeRequest = parse_json(req).await?;

    let mut session_ctx = build_session_context(&headers, resolved_client_ip(depot));
    session_ctx.browser_session_oids = parse_session_header(&ctx, &headers)
        .await
        .into_iter()
        .map(|entry| entry.session_oid)
        .collect();
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
            body.credential_type,
            &body.credential,
            session_ctx,
        )
        .await
        .map_err(challenge_form_error)?;

    match outcome {
        ChallengeOutcome::MfaRequired { login } => {
            let mut pending = login;
            pending.status = LoginStatus::MFA_REQUIRED;
            let user = ctx
                .services()
                .login()
                .get_user(
                    pending
                        .user_oid
                        .ok_or_else(|| AppError::from_code(AuthErrorCode::InvalidLoginState))?
                        .into(),
                )
                .await?;
            let credentials = ctx.services().login().credential_types(user.oid).await?;
            let next_method =
                login::preferred_credential_type(&pending, &credentials, user.preferred_mfa_method);
            render_json(
                res,
                StatusCode::OK,
                ChallengeResponse {
                    preferred_credential_type: next_method,
                    status: LoginStatus::MfaRequired,
                    enrollment_method: None,
                    session: None,
                    acr: None,
                    continue_uri: None,
                    sessions: None,
                },
            );
        }
        ChallengeOutcome::MfaEnrollmentRequired { login: pending } => {
            render_json(
                res,
                StatusCode::OK,
                ChallengeResponse {
                    preferred_credential_type: None,
                    status: LoginStatus::MfaEnrollmentRequired,
                    enrollment_method: Some(login::enrollment_method(&pending)),
                    session: None,
                    acr: None,
                    continue_uri: None,
                    sessions: None,
                },
            );
        }
        ChallengeOutcome::Authenticated { session, .. } => {
            render_authenticated(&ctx, &headers, &body.id, &session, res).await?;
        }
        ChallengeOutcome::PasswordChangeRequired { .. } => {
            render_password_change_required(&body.id, res);
        }
    }
    Ok(())
}

/// The login application page where a sign-in replaces the password its
/// account must change.
fn login_password_change_uri(login_id: &str, ui_locales: Option<&[String]>) -> String {
    let mut query = Serializer::new(String::new());
    query.append_pair("login_id", login_id);
    if let Some(ui_locales) = ui_locales.filter(|values| !values.is_empty()) {
        query.append_pair("ui_locales", &ui_locales.join(" "));
    }
    format!("/login/change-password?{}", query.finish())
}

/// Answer a sign-in held at a required password change. `continue_uri` leads
/// to the change, so every step that follows it reaches the change unchanged.
fn render_password_change_required(login_id: &str, res: &mut Response) {
    render_json(
        res,
        StatusCode::OK,
        ChallengeResponse {
            preferred_credential_type: None,
            status: LoginStatus::PasswordChangeRequired,
            enrollment_method: None,
            session: None,
            acr: None,
            continue_uri: Some(login_password_change_uri(login_id, None)),
            sessions: None,
        },
    );
}

/// `POST /api/auth/login/password-change`
///
/// Replace the password a sign-in requires, then finish the sign-in.
#[handler]
async fn required_password_change(
    depot: &mut Depot,
    req: &mut Request,
    res: &mut Response,
) -> JsonWebResult<()> {
    let ctx = app_state(depot)?;
    let headers: HeaderMap = req.headers().clone();
    let body: RequiredPasswordChangeRequest = parse_json(req).await?;
    let mut session_ctx = build_session_context(&headers, resolved_client_ip(depot));
    session_ctx.browser_session_oids = parse_session_header(&ctx, &headers)
        .await
        .into_iter()
        .map(|entry| entry.session_oid)
        .collect();
    let login_oid = ctx
        .services()
        .oidc_authorize()
        .decrypt_login_id(&body.id)
        .await?;
    match ctx
        .services()
        .login()
        .complete_required_password_change(login_oid, &body.new_password, session_ctx)
        .await?
    {
        ChallengeOutcome::Authenticated { session, .. } => {
            render_authenticated(&ctx, &headers, &body.id, &session, res).await
        }
        _ => Err(AppError::from_code(AuthErrorCode::InvalidLoginState).into()),
    }
}

/// Record the established session on the interaction and answer with where
/// the browser continues.
async fn render_authenticated(
    ctx: &crate::boot::AppState,
    headers: &HeaderMap,
    login_id: &str,
    session: &identity_domain::auth::model::Session,
    res: &mut Response,
) -> JsonWebResult<()> {
    let selected = build_selected_session_state(ctx, headers, session.oid).await?;
    let login = ctx
        .services()
        .oidc_authorize()
        .load_login_by_protected_id(login_id)
        .await?;
    let is_device = ctx
        .services()
        .oidc_device_authorization()
        .login_request(&login)
        .await?
        .is_some();
    if is_device {
        ctx.services()
            .oidc_device_authorization()
            .complete_login(&login, session.oid)
            .await?;
    } else {
        ctx.services()
            .oidc_authorize()
            .record_selection_by_login(
                login_id,
                session.oid,
                session.user_oid,
                Some(selected.protected_session_id.clone()),
                SelectionSource::FreshLogin,
            )
            .await?;
    }
    let continue_uri = Some(if is_device {
        format!("/device?login_id={}", encode(login_id))
    } else {
        protocol_continue_uri(ctx, login_id)?
    });

    render_json(
        res,
        StatusCode::CREATED,
        ChallengeResponse {
            preferred_credential_type: None,
            status: LoginStatus::Authenticated,
            enrollment_method: None,
            session: Some(SessionInfo {
                id: selected.protected_session_id.clone(),
                expires_at: session.expires_at,
            }),
            acr: session.acr.map(|acr| acr.to_string()),
            continue_uri,
            sessions: Some(selected.protected_session_ids),
        },
    );
    Ok(())
}

fn enrollment_response(enrollment: login::LoginTotpEnrollment) -> MfaEnrollmentResponse {
    MfaEnrollmentResponse {
        secret: enrollment.secret,
        otp_auth_uri: enrollment.otp_auth_uri,
        recovery_codes: enrollment.recovery_codes,
        algorithm: enrollment.algorithm,
        expires_at: enrollment.expires_at,
    }
}

fn enrollment_issuer(ctx: &crate::boot::AppState) -> Result<String, AppError> {
    let issuer = ctx.services().oidc().issuer()?;
    Ok(issuer.host_str().unwrap_or("Identity").to_owned())
}

/// `POST /api/auth/login/mfa-enrollment`
///
/// Begin or resume the TOTP enrollment bound to an AAL2 login whose user has
/// no second factor yet.
#[handler]
async fn mfa_enrollment(
    depot: &mut Depot,
    req: &mut Request,
    res: &mut Response,
) -> JsonWebResult<()> {
    let ctx = app_state(depot)?;
    let body: MfaEnrollmentRequest = parse_json(req).await?;
    let login_oid = ctx
        .services()
        .oidc_authorize()
        .decrypt_login_id(&body.id)
        .await?;
    let issuer = enrollment_issuer(&ctx)?;
    let enrollment = ctx
        .services()
        .login()
        .mfa_enrollment(login_oid, &issuer)
        .await?;
    render_json(res, StatusCode::OK, enrollment_response(enrollment));
    Ok(())
}

/// `POST /api/auth/login/mfa-enrollment/algorithm`
#[handler]
async fn change_mfa_enrollment_algorithm(
    depot: &mut Depot,
    req: &mut Request,
    res: &mut Response,
) -> JsonWebResult<()> {
    let ctx = app_state(depot)?;
    let body: MfaEnrollmentAlgorithmRequest = parse_json(req).await?;
    let login_oid = ctx
        .services()
        .oidc_authorize()
        .decrypt_login_id(&body.id)
        .await?;
    let issuer = enrollment_issuer(&ctx)?;
    let enrollment = ctx
        .services()
        .login()
        .change_mfa_enrollment_algorithm(login_oid, &issuer, body.algorithm)
        .await?;
    render_json(res, StatusCode::OK, enrollment_response(enrollment));
    Ok(())
}

/// `POST /api/auth/login/mfa-enrollment/confirm`
///
/// Confirm the pending authenticator; the verified code completes AAL2
/// authentication exactly like an OTP challenge.
#[handler]
async fn confirm_mfa_enrollment(
    depot: &mut Depot,
    req: &mut Request,
    res: &mut Response,
) -> JsonWebResult<()> {
    let ctx = app_state(depot)?;
    let headers: HeaderMap = req.headers().clone();
    let body: MfaEnrollmentConfirmRequest = parse_json(req).await?;

    let mut session_ctx = build_session_context(&headers, resolved_client_ip(depot));
    session_ctx.browser_session_oids = parse_session_header(&ctx, &headers)
        .await
        .into_iter()
        .map(|entry| entry.session_oid)
        .collect();
    let login_oid = ctx
        .services()
        .oidc_authorize()
        .decrypt_login_id(&body.id)
        .await?;
    let outcome = ctx
        .services()
        .login()
        .confirm_mfa_enrollment(login_oid, &body.code, session_ctx)
        .await?;
    match outcome {
        ChallengeOutcome::Authenticated { session, .. } => {
            render_authenticated(&ctx, &headers, &body.id, &session, res).await
        }
        ChallengeOutcome::PasswordChangeRequired { .. } => {
            render_password_change_required(&body.id, res);
            Ok(())
        }
        ChallengeOutcome::MfaRequired { .. } | ChallengeOutcome::MfaEnrollmentRequired { .. } => {
            Err(AppError::from_code(AuthErrorCode::InvalidLoginState).into())
        }
    }
}

/// `POST /api/auth/login/passkey-enrollment`
///
/// Registration options for a `phr` login whose user verified a second factor
/// other than a passkey, with recovery codes to save first.
#[handler]
async fn passkey_enrollment(
    depot: &mut Depot,
    req: &mut Request,
    res: &mut Response,
) -> JsonWebResult<()> {
    let ctx = app_state(depot)?;
    let body: MfaEnrollmentRequest = parse_json(req).await?;
    let login_oid = ctx
        .services()
        .oidc_authorize()
        .decrypt_login_id(&body.id)
        .await?;
    let enrollment = ctx.services().login().passkey_enrollment(login_oid).await?;
    render_json(
        res,
        StatusCode::OK,
        PasskeyEnrollmentResponse {
            options: enrollment.options,
            recovery_codes: enrollment.recovery_codes,
        },
    );
    Ok(())
}

/// `POST /api/auth/login/passkey-enrollment/confirm`
///
/// Store the new passkey. The login then asks for an assertion with it, which
/// establishes `phr`; registration alone authenticates nothing.
#[handler]
async fn confirm_passkey_enrollment(
    depot: &mut Depot,
    req: &mut Request,
    res: &mut Response,
) -> JsonWebResult<()> {
    let ctx = app_state(depot)?;
    let body: PasskeyEnrollmentConfirmRequest = parse_json(req).await?;
    let login_oid = ctx
        .services()
        .oidc_authorize()
        .decrypt_login_id(&body.id)
        .await?;
    ctx.services()
        .login()
        .confirm_passkey_enrollment(
            login_oid,
            body.registration.challenge_id,
            &body.name,
            body.registration.credential,
        )
        .await?;
    render_json(
        res,
        StatusCode::OK,
        ChallengeResponse {
            preferred_credential_type: Some(CredentialType::Passkey),
            status: LoginStatus::MfaRequired,
            enrollment_method: None,
            session: None,
            acr: None,
            continue_uri: None,
            sessions: None,
        },
    );
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
    if code == AuthErrorCode::InvalidCredential.code()
        || code == AuthErrorCode::InvalidAccountOrPassword.code()
        || code == AuthErrorCode::InvalidOtp.code()
    {
        error.with_field("credential")
    } else {
        error
    }
}

#[cfg(test)]
mod form_error_tests {
    use super::{challenge_form_error, identifier_form_error, login_challenge_uri};
    use crate::application::error::{
        AppError,
        codes::{auth::AuthErrorCode, common::CommonErrorCode},
        kind::ErrorKind,
    };

    #[test]
    fn challenge_destinations_use_method_paths_and_preserve_context() {
        let locales = vec!["zh-CN".to_owned(), "en-US".to_owned()];
        for (credential, method) in [
            ("password", "password"),
            ("passkey", "passkey"),
            ("otp", "otp"),
            ("recovery_code", "recovery-code"),
        ] {
            assert_eq!(
                login_challenge_uri("rp+login/id", credential, Some(&locales)),
                format!("/login/{method}?login_id=rp%2Blogin%2Fid&ui_locales=zh-CN+en-US"),
            );
        }
    }

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
