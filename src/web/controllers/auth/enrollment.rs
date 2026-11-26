//! Enrolling an authenticator that the sign-in requires.

use super::*;

pub(super) fn enrollment_response(enrollment: login::LoginTotpEnrollment) -> MfaEnrollmentResponse {
    MfaEnrollmentResponse {
        secret: enrollment.secret,
        otp_auth_uri: enrollment.otp_auth_uri,
        recovery_codes: enrollment.recovery_codes,
        algorithm: enrollment.algorithm,
        expires_at: enrollment.expires_at,
    }
}

pub(super) fn enrollment_issuer(ctx: &crate::infrastructure::AppState) -> Result<String, AppError> {
    let issuer = ctx.services().oidc().issuer()?;
    Ok(issuer.host_str().unwrap_or("Identity").to_owned())
}

/// `POST /api/auth/login/mfa-enrollment`
///
/// Begin or resume the TOTP enrollment bound to an AAL2 login whose user has
/// no second factor yet.
#[handler]
pub(super) async fn mfa_enrollment(
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
pub(super) async fn change_mfa_enrollment_algorithm(
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
pub(super) async fn confirm_mfa_enrollment(
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
            Err(auth::error::InvalidLoginState.into_error().into())
        }
    }
}

/// `POST /api/auth/login/passkey-enrollment`
///
/// Registration options for a `phr` login whose user verified a second factor
/// other than a passkey, with recovery codes to save first.
#[handler]
pub(super) async fn passkey_enrollment(
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
pub(super) async fn confirm_passkey_enrollment(
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
