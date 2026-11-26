//! Credential challenges, required password changes and completing a sign-in.

use super::*;

#[handler]
pub(super) async fn challenge(
    depot: &mut Depot,
    req: &mut Request,
    res: &mut Response,
) -> JsonWebResult<()> {
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
        .await?;

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
                        .ok_or_else(|| auth::error::InvalidLoginState.into_error())?
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
pub(super) fn login_password_change_uri(login_id: &str, ui_locales: Option<&[String]>) -> String {
    let mut query = Serializer::new(String::new());
    query.append_pair("login_id", login_id);
    if let Some(ui_locales) = ui_locales.filter(|values| !values.is_empty()) {
        query.append_pair("ui_locales", &ui_locales.join(" "));
    }
    format!("/login/change-password?{}", query.finish())
}

/// Answer a sign-in held at a required password change. `continue_uri` leads
/// to the change, so every step that follows it reaches the change unchanged.
pub(super) fn render_password_change_required(login_id: &str, res: &mut Response) {
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
pub(super) async fn required_password_change(
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
        _ => Err(auth::error::InvalidLoginState.into_error().into()),
    }
}

/// Record the established session on the interaction and answer with where
/// the browser continues.
pub(super) async fn render_authenticated(
    ctx: &crate::infrastructure::AppState,
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
