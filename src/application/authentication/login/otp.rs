use super::{
    ChallengeOutcome, LoginService, SessionContext, can_challenge_second_factor,
    failed_attempt_lock_until,
};
use crate::{
    error::{AppError, codes::auth::AuthErrorCode},
    user::model::{CredentialData, CredentialType, OtpCredentialData},
};
use identity_domain::auth::{
    ACR_AAL2, AMR_MFA, AMR_OTP, AMR_PASSWORD, LoginFailureReason, LoginStatus, MAX_FAILED_ATTEMPTS,
    MAX_OTP_ATTEMPTS, model::Login,
};
use tracing::error;
use uuid::Uuid;

impl LoginService {
    pub(super) async fn challenge_otp(
        &self,
        login: Login,
        code: &str,
        ctx: SessionContext,
    ) -> Result<ChallengeOutcome, AppError> {
        // A second factor may follow a password challenge, or it may directly
        // elevate an authorization interaction that is bound to an existing
        // session. Never accept OTP as a password replacement for an unbound
        // login.
        if !can_challenge_second_factor(&login) {
            return Err(AppError::from_code(AuthErrorCode::InvalidLoginState));
        }

        if login.failed_attempts >= MAX_OTP_ATTEMPTS {
            self.fail_login_for_too_many_otp_attempts(login.oid).await;
            return Err(AppError::from_code(AuthErrorCode::TooManyAttempts));
        }

        // Resolve user from the login record — no identifier string needed.
        let user = self
            .user_repo
            .find_by_oid(
                login
                    .user_oid
                    .ok_or_else(|| AppError::from_code(AuthErrorCode::InvalidLoginState))?
                    .into(),
            )
            .await?
            .ok_or_else(|| AppError::from_code(AuthErrorCode::UserNotFound))?;
        self.ensure_user_can_authenticate(&user).await?;

        // Load the OTP credential.
        let otp_credentials = self
            .credential_repo
            .find_by_user_oid_and_type(user.oid, CredentialType::Otp)
            .await?;

        let otp_cred = otp_credentials
            .into_iter()
            .find(|c| c.r#type == CredentialType::Otp)
            .ok_or_else(|| {
                AppError::from_code(AuthErrorCode::CredentialTypeUnsupported)
                    .with_param("credential_type", "otp")
            })?;

        let otp_credential_oid = otp_cred.oid;
        let otp_data: OtpCredentialData = match otp_cred.data {
            CredentialData::Otp(o) => o,
            _ => {
                return Err(
                    AppError::from_code(AuthErrorCode::CredentialTypeUnsupported)
                        .with_param("credential_type", "otp"),
                );
            }
        };

        // Verify and atomically consume the matching TOTP time-step. The
        // conditional JSONB update prevents concurrent replay across nodes.
        let valid = match self.totp_verifier.verify(&otp_data, code)? {
            Some(counter) => {
                self.credential_repo
                    .consume_totp_counter(otp_credential_oid, counter)
                    .await?
            }
            None => false,
        };

        if !valid {
            let login_attempts = self
                .login_repo
                .increment_failed_attempts(login.oid, Some(LoginFailureReason::InvalidOtp))
                .await?;
            let user_attempts = self
                .user_repo
                .increment_failed_attempts(
                    user.oid,
                    MAX_FAILED_ATTEMPTS,
                    failed_attempt_lock_until(),
                )
                .await?;

            if login_attempts >= MAX_OTP_ATTEMPTS || user_attempts >= MAX_FAILED_ATTEMPTS {
                self.fail_login_for_too_many_otp_attempts(login.oid).await;
                return Err(AppError::from_code(AuthErrorCode::TooManyAttempts));
            }
            return Err(AppError::from_code(AuthErrorCode::InvalidOtp));
        }

        self.user_repo.reset_failed_attempts(user.oid).await?;
        // Complete AAL2 authentication, reusing a bound session when this
        // login interaction was created for forced reauthentication.
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

    pub(super) async fn fail_login_for_too_many_otp_attempts(&self, login_oid: Uuid) {
        if let Err(e) = self
            .login_repo
            .update_status(login_oid, LoginStatus::FAILED, None, None)
            .await
        {
            error!(error = %e, "failed to update login status after too many OTP attempts");
        }
    }
}
