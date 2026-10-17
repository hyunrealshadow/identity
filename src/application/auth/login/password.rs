use super::{ChallengeOutcome, LoginService, SessionContext, failed_attempt_lock_until};
use crate::{
    auth::password::{HashOptions, VerifyResult, run_password_hashing},
    error::{AppError, codes::auth::AuthErrorCode},
    user::model::{CredentialData, CredentialType, Password},
};
use identity_domain::auth::{
    ACR_AAL1, AMR_PASSWORD, LoginFailureReason, LoginStatus, MAX_FAILED_ATTEMPTS, model::Login,
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

        // Load the password credential.
        let credentials = self
            .credential_repo
            .find_by_user_oid_and_type(user.oid, CredentialType::Password)
            .await?;

        let password_cred = credentials.into_iter().next().ok_or_else(|| {
            AppError::from_code(AuthErrorCode::CredentialTypeUnsupported)
                .with_param("credential_type", "password")
        })?;

        let stored_password: Password = match password_cred.data {
            CredentialData::Password(p) => p,
            _ => {
                return Err(
                    AppError::from_code(AuthErrorCode::CredentialTypeUnsupported)
                        .with_param("credential_type", "password"),
                );
            }
        };

        // Verify the password.
        let password_hasher = Arc::clone(&self.password_hasher);
        let credential = credential.to_owned();
        let verify_password = credential.clone();
        let verify_stored_password = stored_password.clone();
        let hash_options = hash_options.clone();
        let verify_hash_options = hash_options.clone();
        let verify_result = run_password_hashing(move || {
            password_hasher.verify(
                &verify_password,
                &verify_stored_password,
                &verify_hash_options,
            )
        })
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
                // Transparently rehash if needed.
                if verify_result == VerifyResult::NeedsRehash {
                    let password_hasher = Arc::clone(&self.password_hasher);
                    let hash_options = hash_options.clone();
                    let rehash = run_password_hashing(move || {
                        password_hasher.hash(&credential, &hash_options)
                    })
                    .await;

                    match rehash {
                        Ok(new_password) => {
                            if let Err(error) = self
                                .credential_repo
                                .update_password_by_oid(
                                    password_cred.oid,
                                    &stored_password,
                                    &new_password,
                                )
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
                if otp_credentials.is_empty() && !has_passkeys {
                    self.user_repo.reset_failed_attempts(user.oid).await?;
                    // Complete AAL1 authentication. A forced
                    // reauthentication upgrades the bound session in place.
                    let session = self
                        .complete_session(
                            &login,
                            user.oid.into(),
                            ctx,
                            ACR_AAL1,
                            &[AMR_PASSWORD.to_owned()],
                        )
                        .await?;

                    if let Err(e) = self
                        .login_repo
                        .update_status(
                            login.oid,
                            LoginStatus::AUTHENTICATED,
                            Some(session.oid),
                            Some(ACR_AAL1),
                        )
                        .await
                    {
                        error!(error = %e, "failed to update login status to authenticated");
                    }

                    Ok(ChallengeOutcome::Authenticated {
                        login,
                        session: Box::new(session),
                    })
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
    }
}
