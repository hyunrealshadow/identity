//! Self-registration and forgotten-password reset.

use super::*;

/// `POST /api/auth/login/password-reset`
///
/// Email a link that replaces a forgotten password, for a login waiting for
/// its first factor. While the login conceals whether an account exists, the
/// answer is the same whether or not anything was sent.
#[handler]
pub(super) async fn password_reset(
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

/// `POST /api/auth/login/registration`
///
/// Email a link that continues creating an account, for a login at its
/// identifier step. An address that already has an account receives a
/// notice instead; the answer is the same either way.
#[handler]
pub(super) async fn registration(
    depot: &mut Depot,
    req: &mut Request,
    res: &mut Response,
) -> JsonWebResult<()> {
    let ctx = app_state(depot)?;
    let body: RegistrationRequestBody = parse_json(req).await?;
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
    let link_prefix = login_link_prefix(&ctx, "login/register", &body.id, ui_locales.as_deref())?;
    let mut locales = ui_locales.unwrap_or_default();
    locales.extend(body.locales);
    let sent = ctx
        .services()
        .login()
        .send_registration(login::RegistrationRequest {
            login_oid,
            email: body.email,
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

/// `POST /api/auth/login/registration/check`
///
/// The address a registration link verifies, without using the link.
#[handler]
pub(super) async fn check_registration(
    depot: &mut Depot,
    req: &mut Request,
    res: &mut Response,
) -> JsonWebResult<()> {
    let ctx = app_state(depot)?;
    let body: RegistrationCheckRequest = parse_json(req).await?;
    let login_oid = ctx
        .services()
        .oidc_authorize()
        .decrypt_login_id(&body.id)
        .await?;
    let link = ctx
        .services()
        .login()
        .check_registration_link(login_oid, &body.token)
        .await?;
    render_json(
        res,
        StatusCode::OK,
        RegistrationCheckResponse {
            status: "valid",
            email: link.email,
        },
    );
    Ok(())
}

/// `POST /api/auth/login/registration/confirm`
///
/// Create the account of a registration link. The login continues at its
/// password step with the new account.
#[handler]
pub(super) async fn confirm_registration(
    depot: &mut Depot,
    req: &mut Request,
    res: &mut Response,
) -> JsonWebResult<()> {
    let ctx = app_state(depot)?;
    let body: RegistrationConfirmRequest = parse_json(req).await?;
    let login_oid = ctx
        .services()
        .oidc_authorize()
        .decrypt_login_id(&body.id)
        .await?;
    ctx.services()
        .login()
        .complete_registration(login_oid, &body.token, &body.username, &body.new_password)
        .await?;
    render_json(
        res,
        StatusCode::OK,
        PasswordResetStatusResponse {
            status: "registered",
        },
    );
    Ok(())
}

/// `POST /api/auth/login/password-reset/check`
///
/// Whether a reset link can still be used, without using it.
#[handler]
pub(super) async fn check_password_reset(
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
pub(super) async fn confirm_password_reset(
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
