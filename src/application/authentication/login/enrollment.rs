//! Progressive second-factor enrollment inside a login interaction.
//!
//! When the authorization request requires AAL2 and the user verified a
//! password but has no second factor, the interaction enters
//! `mfa_enrollment_required`. The only way forward is to enroll a TOTP
//! authenticator; confirming it with a valid code is the second factor that
//! completes AAL2 authentication. The pending enrollment is bound to the
//! login record so a reload or a rejected code resumes the same secret.

use super::{ChallengeOutcome, LoginService, SessionContext};
use crate::{
    authentication::{
        challenge::ChallengeRepository,
        mfa::{BeginTotpEnrollment, MfaService},
    },
    error::{AppError, code::AppErrorCode as _, codes::auth::AuthErrorCode},
    user::model::{CredentialType, OtpAlgorithm, User},
};
use chrono::{DateTime, Utc};
use identity_domain::auth::{
    ACR_AAL2, AMR_MFA, AMR_OTP, AMR_PASSWORD, LoginFailureReason, LoginStatus, MAX_OTP_ATTEMPTS,
    challenge::{
        AuthenticationChallenge, ChallengeBinding, ChallengeContext, ChallengeMethod,
        ChallengePurpose,
    },
    model::Login,
};
use serde_json::json;
use std::sync::Arc;
use tracing::error;
use uuid::Uuid;

const ENROLLMENT_TOKEN: &str = "enrollment_token";

/// Collaborators needed to enroll a second factor during sign-in.
pub struct LoginMfaEnrollmentDependencies {
    pub mfa: Arc<MfaService>,
    pub challenges: Arc<dyn ChallengeRepository>,
}

/// What the sign-in page presents for a pending TOTP enrollment. The
/// protected enrollment token stays on the server.
#[derive(Debug, Clone)]
pub struct LoginTotpEnrollment {
    pub secret: String,
    pub otp_auth_uri: String,
    /// Shown before confirmation; empty when the user already has codes.
    pub recovery_codes: Vec<String>,
    pub algorithm: OtpAlgorithm,
    pub expires_at: DateTime<Utc>,
}

impl LoginService {
    /// Begin, or resume, the TOTP enrollment bound to this login.
    #[tracing::instrument(skip_all, name = "authentication.mfa_enrollment.prepare")]
    pub async fn mfa_enrollment(
        &self,
        login_oid: Uuid,
        issuer: &str,
    ) -> Result<LoginTotpEnrollment, AppError> {
        let enrollment = self.enrollment_dependencies()?;
        let (login, user) = self.enrollment_login(login_oid).await?;
        let context = enrollment_context(&login, &user);
        if let Some(challenge) = enrollment.challenges.latest(context).await?
            && let Ok(token) = enrollment_token(&challenge)
            && let Ok(resumed) = enrollment
                .mfa
                .resume_totp_enrollment(user.oid, &token, issuer, &user.email)
                .await
        {
            return Ok(resumed.into());
        }

        let begun = enrollment
            .mfa
            .begin_totp_enrollment(user.oid, issuer, &user.email)
            .await?;
        store_enrollment(enrollment, context, &login, &begun).await?;
        Ok(begun.into())
    }

    /// Switch the pending secret to another HMAC algorithm for authenticator
    /// apps that ignore the default one. The secret itself is unchanged.
    #[tracing::instrument(skip_all, name = "authentication.mfa_enrollment.change_algorithm")]
    pub async fn change_mfa_enrollment_algorithm(
        &self,
        login_oid: Uuid,
        issuer: &str,
        algorithm: OtpAlgorithm,
    ) -> Result<LoginTotpEnrollment, AppError> {
        let enrollment = self.enrollment_dependencies()?;
        let (login, user) = self.enrollment_login(login_oid).await?;
        let context = enrollment_context(&login, &user);
        let challenge = enrollment
            .challenges
            .latest(context)
            .await?
            .ok_or_else(|| AppError::from_code(AuthErrorCode::InvalidTotpEnrollment))?;
        let token = enrollment_token(&challenge)?;
        let changed = enrollment
            .mfa
            .change_totp_enrollment_algorithm(user.oid, &token, issuer, &user.email, algorithm)
            .await?;
        enrollment.challenges.take(context, challenge.id).await?;
        store_enrollment(enrollment, context, &login, &changed).await?;
        Ok(changed.into())
    }

    /// Confirm the pending authenticator with a current code. The verified
    /// code is the second factor: the login completes at AAL2.
    #[tracing::instrument(skip_all, name = "authentication.mfa_enrollment.confirm")]
    pub async fn confirm_mfa_enrollment(
        &self,
        login_oid: Uuid,
        code: &str,
        ctx: SessionContext,
    ) -> Result<ChallengeOutcome, AppError> {
        let result = self
            .confirm_mfa_enrollment_inner(login_oid, code, ctx)
            .await;
        self.record_authentication_result(login_oid, CredentialType::Otp, &result);
        result
    }

    async fn confirm_mfa_enrollment_inner(
        &self,
        login_oid: Uuid,
        code: &str,
        ctx: SessionContext,
    ) -> Result<ChallengeOutcome, AppError> {
        let enrollment = self.enrollment_dependencies()?;
        let (login, user) = self.enrollment_login(login_oid).await?;
        if login.failed_attempts >= MAX_OTP_ATTEMPTS {
            self.fail_login_for_too_many_otp_attempts(login.oid).await;
            return Err(AppError::from_code(AuthErrorCode::TooManyAttempts));
        }
        let challenge = enrollment
            .challenges
            .latest(enrollment_context(&login, &user))
            .await?
            .ok_or_else(|| AppError::from_code(AuthErrorCode::InvalidTotpEnrollment))?;
        let token = enrollment_token(&challenge)?;

        match enrollment
            .mfa
            .confirm_totp_enrollment(user.oid, &token, code)
            .await
        {
            Ok(_) => {}
            Err(error) => {
                if error.code() == AuthErrorCode::InvalidOtp.code() {
                    let attempts = self
                        .login_repo
                        .increment_failed_attempts(login.oid, Some(LoginFailureReason::InvalidOtp))
                        .await?;
                    if attempts >= MAX_OTP_ATTEMPTS {
                        self.fail_login_for_too_many_otp_attempts(login.oid).await;
                        return Err(AppError::from_code(AuthErrorCode::TooManyAttempts));
                    }
                }
                return Err(error);
            }
        }

        // The authenticator is now enrolled. If completing the session fails,
        // the next attempt is routed to an ordinary OTP challenge.
        let session = self
            .complete_session(
                &login,
                user.oid.into(),
                ctx,
                ACR_AAL2,
                &[
                    AMR_PASSWORD.to_owned(),
                    AMR_OTP.to_owned(),
                    AMR_MFA.to_owned(),
                ],
            )
            .await?;
        if let Err(e) = self
            .login_repo
            .update_status(
                login.oid,
                LoginStatus::AUTHENTICATED,
                Some(session.oid),
                Some(ACR_AAL2),
            )
            .await
        {
            error!(error = %e, "failed to update login status to authenticated");
        }
        Ok(ChallengeOutcome::Authenticated {
            login,
            session: Box::new(session),
        })
    }

    fn enrollment_dependencies(&self) -> Result<&LoginMfaEnrollmentDependencies, AppError> {
        self.mfa_enrollment
            .as_ref()
            .ok_or_else(|| AppError::from_code(AuthErrorCode::InvalidLoginState))
    }

    async fn enrollment_login(&self, login_oid: Uuid) -> Result<(Login, User), AppError> {
        let login = self.prepare_challenge(login_oid).await?;
        if login.expires_at <= Utc::now() {
            if let Err(e) = self
                .login_repo
                .update_status(login.oid, LoginStatus::EXPIRED, None, None)
                .await
            {
                error!(error = %e, "failed to update login status on expiry");
            }
            return Err(AppError::from_code(AuthErrorCode::LoginExpired));
        }
        if login.status != LoginStatus::MFA_ENROLLMENT_REQUIRED {
            return Err(AppError::from_code(AuthErrorCode::InvalidLoginState));
        }
        let user_oid = login
            .user_oid
            .ok_or_else(|| AppError::from_code(AuthErrorCode::InvalidLoginState))?;
        let user = self.get_user(user_oid.into()).await?;
        self.ensure_user_can_authenticate(&user).await?;
        Ok((login, user))
    }
}

impl From<BeginTotpEnrollment> for LoginTotpEnrollment {
    fn from(enrollment: BeginTotpEnrollment) -> Self {
        Self {
            secret: enrollment.secret,
            otp_auth_uri: enrollment.otp_auth_uri,
            recovery_codes: enrollment.recovery_codes,
            algorithm: enrollment.algorithm,
            expires_at: enrollment.expires_at,
        }
    }
}

async fn store_enrollment(
    enrollment: &LoginMfaEnrollmentDependencies,
    context: ChallengeContext,
    login: &Login,
    pending: &BeginTotpEnrollment,
) -> Result<(), AppError> {
    enrollment
        .challenges
        .store(
            context,
            AuthenticationChallenge {
                id: Uuid::new_v4(),
                state: json!({ ENROLLMENT_TOKEN: pending.enrollment_token }),
                expires_at: pending.expires_at.min(login.expires_at),
            },
        )
        .await
        // The owning login left the enrollment phase concurrently.
        .map_err(|_| AppError::from_code(AuthErrorCode::InvalidLoginState))
}

fn enrollment_context(login: &Login, user: &User) -> ChallengeContext {
    ChallengeContext {
        user_oid: user.oid.into(),
        binding: ChallengeBinding::Login(login.oid),
        method: ChallengeMethod::Totp,
        purpose: ChallengePurpose::CredentialRegistration,
    }
}

fn enrollment_token(challenge: &AuthenticationChallenge) -> Result<String, AppError> {
    challenge
        .state
        .get(ENROLLMENT_TOKEN)
        .and_then(|value| value.as_str())
        .map(ToOwned::to_owned)
        .ok_or_else(|| AppError::from_code(AuthErrorCode::InvalidTotpEnrollment))
}
