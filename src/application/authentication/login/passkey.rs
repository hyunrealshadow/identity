use super::{ChallengeOutcome, LoginService, SessionContext, combine_amr};
use crate::{
    authentication::passkey::PasskeyOptions,
    error::{AppError, codes::auth},
};
use identity_domain::auth::{
    AMR_MFA, AMR_PASSKEY, AuthenticationContextClass, LoginFailureReason, LoginStatus, model::Login,
};
use uuid::Uuid;

impl LoginService {
    /// Account-bound challenges are unavailable until identifier verification.
    pub async fn passkey_options(&self, login_oid: Uuid) -> Result<PasskeyOptions, AppError> {
        let login = self.prepare_challenge(login_oid).await?;
        self.validate_passkey_login(&login)?;
        let user = self
            .get_user(login.user_oid.ok_or(auth::error::InvalidLoginState)?.into())
            .await?;
        self.ensure_user_can_authenticate(&user).await?;
        self.passkeys
            .as_ref()
            .ok_or_else(|| auth::error::CredentialTypeUnsupported::new("passkey"))?
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
        self.validate_passkey_login(&login)?;
        let user = self
            .get_user(login.user_oid.ok_or(auth::error::InvalidLoginState)?.into())
            .await?;
        self.ensure_user_can_authenticate(&user).await?;
        let result = self
            .passkeys
            .as_ref()
            .ok_or_else(|| auth::error::CredentialTypeUnsupported::new("passkey"))?
            .authenticate(user.oid, login.oid, assertion)
            .await;
        if let Err(error) = result {
            self.login_repo
                .increment_failed_attempts(login.oid, Some(LoginFailureReason::InvalidCredential))
                .await?;
            self.user_repo
                .increment_failed_attempts(
                    user.oid,
                    self.max_failed_attempts(),
                    self.failed_attempt_lock_until(),
                )
                .await?;
            return Err(error);
        }
        self.user_repo.reset_failed_attempts(user.oid).await?;
        // A user-verified passkey is multi-factor and phishing resistant on
        // its own; a preceding password is recorded but adds no class.
        let mut amr = vec![AMR_PASSKEY.to_owned(), AMR_MFA.to_owned()];
        if login.status == LoginStatus::MFA_REQUIRED {
            for method in combine_amr(&login, &[], true) {
                if !amr.contains(&method) {
                    amr.push(method);
                }
            }
        }
        self.complete_authentication(
            login,
            user.oid.into(),
            ctx,
            AuthenticationContextClass::PhishingResistant,
            &amr,
        )
        .await
    }
}
