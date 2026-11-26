//! Account selection and the first sign-in steps: identifier, passkey options and email codes.

use super::*;

/// `GET /api/auth/sessions/active`
///
/// Read `X-Sessions` and return the list of active accounts.
#[handler]
pub(super) async fn active_sessions(
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
pub(super) async fn login_status(
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
    let registration_available = ctx.services().login().registration_offered(&login);
    let registration_resend_available_at = ctx
        .services()
        .login()
        .registration_resend_available_at(&login)
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
            registration_available,
            registration_resend_available_at,
            continue_uri,
        },
    );
    Ok(())
}

pub(super) fn login_enrollment_uri(
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

pub(super) fn login_challenge_uri(
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
pub(super) async fn select_account(
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
        ctx.services()
            .oidc_authorize()
            .ensure_account_selection_allowed(&body.login_id)
            .await?;
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
pub(super) async fn identifier(
    depot: &mut Depot,
    req: &mut Request,
    res: &mut Response,
) -> JsonWebResult<()> {
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
pub(super) async fn restart_login(
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
pub(super) async fn switch_login(
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
pub(super) async fn passkey_options(
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
pub(super) async fn email_code(
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
pub(super) fn login_link_prefix(
    ctx: &crate::infrastructure::AppState,
    route: &str,
    login_id: &str,
    ui_locales: Option<&[String]>,
) -> Result<String, AppError> {
    let login_domain = ctx
        .services()
        .settings()
        .snapshot()
        .section::<crate::application::setting::AppSettings>()
        .login_domain
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| authorize_http::error::LoginDomainNotConfigured::new(route).into_error())?;
    let mut url = url::Url::parse(login_domain.trim())
        .and_then(|base| base.join(route))
        .map_err(|error| {
            authorize_http::error::LoginDomainNotConfigured::new(route).with_source(error)
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
