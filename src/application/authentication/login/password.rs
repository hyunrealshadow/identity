use super::{
    ChallengeOutcome, LoginService, SessionContext, failed_attempt_lock_until,
    requires_second_factor,
};
use crate::{
    authentication::password::{HashOptions, VerifyResult, run_password_hashing},
    error::{AppError, codes::auth::AuthErrorCode},
    user::{
        UserCredentialOid,
        model::{CredentialData, CredentialType, Password, User},
    },
};
use identity_domain::auth::{
    AMR_PASSWORD, AuthenticationContextClass, LoginFailureReason, LoginStatus, MAX_FAILED_ATTEMPTS,
    model::Login,
};
use std::sync::Arc;
use tracing::error;

impl LoginService {
    pub(super) async fn challenge_password(
        &self,
        login: Login,
        credential: &str,
        hash_options: &HashOptions,
        ctx: SessionContext,
    ) -> Result<ChallengeOutcome, AppError> {
        // Password challenge is only valid when the login is in
        // `identifier_verified` state.
        if login.status != LoginStatus::IDENTIFIER_VERIFIED {
            return Err(AppError::from_code(AuthErrorCode::InvalidLoginState));
        }
        if login.concealed_identifier().is_some() {
            return self
                .challenge_concealed_password(login, credential, hash_options, ctx)
                .await;
        }

        // Re-fetch the user by OID (to get the latest failed_attempts / lock
        // state). The OID comes from the login record itself — no identifier
        // string needed from the client.
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

        let (credential_oid, stored_password) =
            self.stored_password(&user).await?.ok_or_else(|| {
                AppError::from_code(AuthErrorCode::CredentialTypeUnsupported)
                    .with_param("credential_type", "password")
            })?;
        let verify_result = self
            .verify_password(credential, &stored_password, hash_options)
            .await?;

        match verify_result {
            VerifyResult::Failure => {
                self.login_repo
                    .increment_failed_attempts(
                        login.oid,
                        Some(LoginFailureReason::InvalidCredential),
                    )
                    .await?;

                let new_attempts = self
                    .user_repo
                    .increment_failed_attempts(
                        user.oid,
                        MAX_FAILED_ATTEMPTS,
                        failed_attempt_lock_until(),
                    )
                    .await?;

                if new_attempts >= MAX_FAILED_ATTEMPTS {
                    return Err(AppError::from_code(AuthErrorCode::UserLocked));
                }
                Err(AppError::from_code(AuthErrorCode::InvalidCredential))
            }
            VerifyResult::Success | VerifyResult::NeedsRehash => {
                self.password_verified(
                    login,
                    &user,
                    credential_oid,
                    &stored_password,
                    verify_result,
                    credential,
                    hash_options,
                    ctx,
                )
                .await
            }
        }
    }

    /// The password step of an interaction that conceals whether the account
    /// exists. A missing account or password costs the same hashing work and
    /// fails with the same error as a wrong password; a locked or disabled
    /// account is disclosed only after its correct password.
    async fn challenge_concealed_password(
        &self,
        login: Login,
        credential: &str,
        hash_options: &HashOptions,
        ctx: SessionContext,
    ) -> Result<ChallengeOutcome, AppError> {
        let user = match login.user_oid {
            Some(user_oid) => self.user_repo.find_by_oid(user_oid.into()).await?,
            None => None,
        };
        let stored = match &user {
            Some(user) => self.stored_password(user).await?,
            None => None,
        };
        let Some((user, (credential_oid, stored_password))) = user.zip(stored) else {
            let password_hasher = Arc::clone(&self.password_hasher);
            let credential = credential.to_owned();
            let hash_options = hash_options.clone();
            let _ = run_password_hashing(move || password_hasher.hash(&credential, &hash_options))
                .await;
            self.login_repo
                .increment_failed_attempts(login.oid, Some(LoginFailureReason::InvalidCredential))
                .await?;
            return Err(AppError::from_code(AuthErrorCode::InvalidAccountOrPassword));
        };

        // Evaluated before verification so an expired lock is lifted and the
        // failure below counts towards a new one.
        let admission = self.ensure_user_can_authenticate(&user).await;
        let verify_result = self
            .verify_password(credential, &stored_password, hash_options)
            .await?;
        if verify_result == VerifyResult::Failure {
            self.login_repo
                .increment_failed_attempts(login.oid, Some(LoginFailureReason::InvalidCredential))
                .await?;
            if admission.is_ok() {
                self.user_repo
                    .increment_failed_attempts(
                        user.oid,
                        MAX_FAILED_ATTEMPTS,
                        failed_attempt_lock_until(),
                    )
                    .await?;
            }
            return Err(AppError::from_code(AuthErrorCode::InvalidAccountOrPassword));
        }
        admission?;
        self.password_verified(
            login,
            &user,
            credential_oid,
            &stored_password,
            verify_result,
            credential,
            hash_options,
            ctx,
        )
        .await
    }

    /// The user's stored password credential, if one is enrolled.
    async fn stored_password(
        &self,
        user: &User,
    ) -> Result<Option<(UserCredentialOid, Password)>, AppError> {
        let credentials = self
            .credential_repo
            .find_by_user_oid_and_type(user.oid, CredentialType::Password)
            .await?;
        Ok(credentials
            .into_iter()
            .find_map(|credential| match credential.data {
                CredentialData::Password(password) => Some((credential.oid, password)),
                _ => None,
            }))
    }

    async fn verify_password(
        &self,
        credential: &str,
        stored_password: &Password,
        hash_options: &HashOptions,
    ) -> Result<VerifyResult, AppError> {
        let password_hasher = Arc::clone(&self.password_hasher);
        let credential = credential.to_owned();
        let stored_password = stored_password.clone();
        let hash_options = hash_options.clone();
        run_password_hashing(move || {
            password_hasher.verify(&credential, &stored_password, &hash_options)
        })
        .await
    }

    /// Continue after a correct password: rehash when due, then require a
    /// second factor, its enrollment, or complete authentication.
    #[allow(clippy::too_many_arguments)]
    async fn password_verified(
        &self,
        login: Login,
        user: &User,
        credential_oid: UserCredentialOid,
        stored_password: &Password,
        verify_result: VerifyResult,
        credential: &str,
        hash_options: &HashOptions,
        ctx: SessionContext,
    ) -> Result<ChallengeOutcome, AppError> {
        // Transparently rehash if needed.
        if verify_result == VerifyResult::NeedsRehash {
            let password_hasher = Arc::clone(&self.password_hasher);
            let hash_options = hash_options.clone();
            let credential = credential.to_owned();
            let rehash =
                run_password_hashing(move || password_hasher.hash(&credential, &hash_options))
                    .await;

            match rehash {
                Ok(new_password) => {
                    if let Err(error) = self
                        .credential_repo
                        .update_password_by_oid(credential_oid, stored_password, &new_password)
                        .await
                    {
                        error!(
                            error = %error,
                            "failed to persist rehashed password"
                        );
                    }
                }
                Err(error) => {
                    error!(error = %error, "failed to rehash password");
                }
            }
        }

        self.first_factor_verified(login, user, AMR_PASSWORD, ctx)
            .await
    }

    /// Continue after a first factor succeeds: require a second factor, its
    /// enrollment, or complete authentication at the single-factor class.
    pub(super) async fn first_factor_verified(
        &self,
        login: Login,
        user: &User,
        amr: &str,
        ctx: SessionContext,
    ) -> Result<ChallengeOutcome, AppError> {
        if amr != AMR_PASSWORD {
            self.login_repo.record_first_factor(login.oid, amr).await?;
        }
        // Check if the user has an OTP credential.
        let otp_credentials = self
            .credential_repo
            .find_by_user_oid_and_type(user.oid, CredentialType::Otp)
            .await?;

        let has_passkeys = if let Some(passkeys) = &self.passkeys {
            !passkeys.list(user.oid).await?.is_empty()
        } else {
            false
        };
        if otp_credentials.is_empty() && !has_passkeys && requires_second_factor(&login) {
            self.user_repo.reset_failed_attempts(user.oid).await?;
            if let Err(e) = self
                .login_repo
                .update_status(login.oid, LoginStatus::MFA_ENROLLMENT_REQUIRED, None, None)
                .await
            {
                error!(error = %e, "failed to update login status to mfa_enrollment_required");
                return Err(AppError::from_code(AuthErrorCode::InvalidLoginState));
            }
            if let Err(e) = self.login_repo.reset_failed_attempts(login.oid).await {
                error!(error = %e, "failed to reset login failed attempts for MFA enrollment");
            }
            Ok(ChallengeOutcome::MfaEnrollmentRequired { login })
        } else if otp_credentials.is_empty() && !has_passkeys {
            self.user_repo.reset_failed_attempts(user.oid).await?;
            self.complete_authentication(
                login,
                user.oid.into(),
                ctx,
                AuthenticationContextClass::SingleFactor,
                &[amr.to_owned()],
            )
            .await
        } else {
            // MFA required — do NOT create a session yet.
            if let Err(e) = self
                .login_repo
                .update_status(login.oid, LoginStatus::MFA_REQUIRED, None, None)
                .await
            {
                error!(error = %e, "failed to update login status to mfa_required");
            }
            if let Err(e) = self.login_repo.reset_failed_attempts(login.oid).await {
                error!(error = %e, "failed to reset login failed attempts for MFA");
            }

            Ok(ChallengeOutcome::MfaRequired { login })
        }
    }
}
