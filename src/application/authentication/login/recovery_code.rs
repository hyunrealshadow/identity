use super::{
    ChallengeOutcome, LoginService, SessionContext, can_challenge_second_factor, combine_amr,
};
use crate::{
    authentication::mfa::recovery_code_hash,
    error::{AppError, codes::auth},
    user::model::{CredentialData, CredentialType, RecoveryCodeCredentialData},
};
use identity_domain::auth::{
    AMR_MFA, AMR_RECOVERY_CODE, LoginFailureReason, MAX_OTP_ATTEMPTS, model::Login,
};
use subtle::ConstantTimeEq;
use uuid::Uuid;

impl LoginService {
    pub(super) async fn challenge_recovery_code(
        &self,
        login: Login,
        code: &str,
        ctx: SessionContext,
    ) -> Result<ChallengeOutcome, AppError> {
        if !can_challenge_second_factor(&login) {
            return Err(auth::error::InvalidLoginState.into());
        }
        if login.failed_attempts >= MAX_OTP_ATTEMPTS {
            self.fail_login_for_too_many_otp_attempts(login.oid).await;
            return Err(auth::error::TooManyAttempts.into());
        }
        let user_oid = login.user_oid.ok_or(auth::error::InvalidLoginState)?.into();
        let user = self
            .user_repo
            .find_by_oid(user_oid)
            .await?
            .ok_or(auth::error::UserNotFound)?;
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
                .increment_failed_attempts(login.oid, Some(LoginFailureReason::InvalidRecoveryCode))
                .await?;
            let max_failed_attempts = self.max_failed_attempts();
            let user_attempts = self
                .user_repo
                .increment_failed_attempts(
                    user_oid,
                    max_failed_attempts,
                    self.failed_attempt_lock_until(),
                )
                .await?;
            if login_attempts >= MAX_OTP_ATTEMPTS || user_attempts >= max_failed_attempts {
                self.fail_login_for_too_many_otp_attempts(login.oid).await;
                return Err(auth::error::TooManyAttempts.into());
            }
            return Err(auth::error::InvalidOtp.into());
        };
        if !self
            .credential_repo
            .consume_recovery_code_by_oid(matched.oid)
            .await?
        {
            return Err(auth::error::InvalidOtp.into());
        }
        self.user_repo.reset_failed_attempts(user_oid).await?;
        let amr = combine_amr(&login, &[AMR_RECOVERY_CODE, AMR_MFA], true);
        self.complete_second_factor(login, Uuid::from(user_oid), ctx, &amr)
            .await
    }
}
