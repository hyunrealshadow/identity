use super::{
    ChallengeOutcome, LoginService, SessionContext, failed_attempt_lock_until,
    validate_passkey_login,
};
use crate::error::{AppError, codes::auth::AuthErrorCode};
use identity_domain::auth::{
    ACR_AAL2, AMR_MFA, AMR_PASSWORD, LoginFailureReason, LoginStatus, MAX_FAILED_ATTEMPTS,
    model::Login,
};
use uuid::Uuid;

impl LoginService {
    /// Account-bound challenges are unavailable until identifier verification.
    pub async fn passkey_options(
        &self,
        login_oid: Uuid,
    ) -> Result<crate::auth::passkey::PasskeyOptions, AppError> {
        let login = self.get(login_oid).await?;
        validate_passkey_login(&login)?;
        let user = self
            .get_user(
                login
                    .user_oid
                    .ok_or_else(|| AppError::from_code(AuthErrorCode::InvalidLoginState))?
                    .into(),
            )
            .await?;
        self.ensure_user_can_authenticate(&user).await?;
        self.passkeys
            .as_ref()
            .ok_or_else(|| AppError::from_code(AuthErrorCode::CredentialTypeUnsupported))?
            .begin_authentication(user.oid, login_oid)
            .await
    }

    // ── Private helpers ──────────────────────────────────────────────────────

    pub(super) async fn challenge_passkey(
        &self,
        login: Login,
        assertion: &str,
        ctx: SessionContext,
    ) -> Result<ChallengeOutcome, AppError> {
        validate_passkey_login(&login)?;
        let user = self
            .get_user(
                login
                    .user_oid
                    .ok_or_else(|| AppError::from_code(AuthErrorCode::InvalidLoginState))?
                    .into(),
            )
            .await?;
        self.ensure_user_can_authenticate(&user).await?;
        let result = self
            .passkeys
            .as_ref()
            .ok_or_else(|| AppError::from_code(AuthErrorCode::CredentialTypeUnsupported))?
            .authenticate(user.oid, login.oid, assertion)
            .await;
        if let Err(error) = result {
            self.login_repo
                .increment_failed_attempts(login.oid, Some(LoginFailureReason::InvalidCredential))
                .await?;
            self.user_repo
                .increment_failed_attempts(
                    user.oid,
                    MAX_FAILED_ATTEMPTS,
                    failed_attempt_lock_until(),
                )
                .await?;
            return Err(error);
        }
        self.user_repo.reset_failed_attempts(user.oid).await?;
        let mut amr = vec!["passkey".to_owned(), AMR_MFA.to_owned()];
        if login.status == LoginStatus::MFA_REQUIRED {
            amr.push(AMR_PASSWORD.to_owned());
        }
        let session = self
            .complete_session(&login, user.oid.into(), ctx, ACR_AAL2, &amr)
            .await?;
        self.login_repo
            .update_status(
                login.oid,
                LoginStatus::AUTHENTICATED,
                Some(session.oid),
                Some(ACR_AAL2),
            )
            .await?;
        Ok(ChallengeOutcome::Authenticated {
            login,
            session: Box::new(session),
        })
    }
}
