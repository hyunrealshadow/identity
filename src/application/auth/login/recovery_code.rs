use super::{
    ChallengeOutcome, LoginService, SessionContext, can_challenge_second_factor,
    failed_attempt_lock_until,
};
use crate::{
    auth::mfa::recovery_code_hash,
    error::{AppError, codes::auth::AuthErrorCode},
    user::model::{CredentialData, CredentialType, RecoveryCodeCredentialData},
};
use identity_domain::auth::{
    ACR_AAL2, AMR_MFA, AMR_PASSWORD, AMR_RECOVERY_CODE, LoginFailureReason, LoginStatus,
    MAX_FAILED_ATTEMPTS, MAX_OTP_ATTEMPTS, model::Login,
};
use subtle::ConstantTimeEq;
use tracing::error;
use uuid::Uuid;

impl LoginService {
    pub(super) async fn challenge_recovery_code(
        &self,
        login: Login,
        code: &str,
        ctx: SessionContext,
    ) -> Result<ChallengeOutcome, AppError> {
        if !can_challenge_second_factor(&login) {
            return Err(AppError::from_code(AuthErrorCode::InvalidLoginState));
        }
        if login.failed_attempts >= MAX_OTP_ATTEMPTS {
            self.fail_login_for_too_many_otp_attempts(login.oid).await;
            return Err(AppError::from_code(AuthErrorCode::TooManyAttempts));
        }
        let user_oid = login
            .user_oid
            .ok_or_else(|| AppError::from_code(AuthErrorCode::InvalidLoginState))?
            .into();
        let user = self
            .user_repo
            .find_by_oid(user_oid)
            .await?
            .ok_or_else(|| AppError::from_code(AuthErrorCode::UserNotFound))?;
        self.ensure_user_can_authenticate(&user).await?;
        let expected_hash = recovery_code_hash(code);
        let credentials = self
            .credential_repo
            .find_by_user_oid_and_type(user_oid, CredentialType::RecoveryCode)
            .await?;
        let matched = credentials.into_iter().find(|credential| {
            let CredentialData::RecoveryCode(RecoveryCodeCredentialData { hash }) =
                &credential.data
            else {
                return false;
            };
            bool::from(ConstantTimeEq::ct_eq(
                hash.as_bytes(),
                expected_hash.as_bytes(),
            ))
        });
        let Some(matched) = matched else {
            let login_attempts = self
                .login_repo
                .increment_failed_attempts(login.oid, Some(LoginFailureReason::InvalidOtp))
                .await?;
            let user_attempts = self
                .user_repo
                .increment_failed_attempts(
                    user_oid,
                    MAX_FAILED_ATTEMPTS,
                    failed_attempt_lock_until(),
                )
                .await?;
            if login_attempts >= MAX_OTP_ATTEMPTS || user_attempts >= MAX_FAILED_ATTEMPTS {
                self.fail_login_for_too_many_otp_attempts(login.oid).await;
                return Err(AppError::from_code(AuthErrorCode::TooManyAttempts));
            }
            return Err(AppError::from_code(AuthErrorCode::InvalidOtp));
        };
        if !self
            .credential_repo
            .consume_recovery_code_by_oid(matched.oid)
            .await?
        {
            return Err(AppError::from_code(AuthErrorCode::InvalidOtp));
        }
        self.user_repo.reset_failed_attempts(user_oid).await?;
        let session = self
            .complete_session(
                &login,
                Uuid::from(user_oid),
                ctx,
                ACR_AAL2,
                &[
                    AMR_PASSWORD.to_owned(),
                    AMR_RECOVERY_CODE.to_owned(),
                    AMR_MFA.to_owned(),
                ],
            )
            .await?;
        if let Err(error) = self
            .login_repo
            .update_status(
                login.oid,
                LoginStatus::AUTHENTICATED,
                Some(session.oid),
                Some(ACR_AAL2),
            )
            .await
        {
            error!(%error, "failed to authenticate recovery-code login");
        }
        Ok(ChallengeOutcome::Authenticated {
            login,
            session: Box::new(session),
        })
    }
}
