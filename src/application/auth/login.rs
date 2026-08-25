use std::sync::Arc;

use chrono::Utc;
use uuid::Uuid;

use crate::{
    error::{AppError, codes::auth::AuthErrorCode},
    setting::runtime::SettingProvider,
};
use identity_domain::{
    auth::{
        ACR_AAL1, ACR_AAL2, AMR_MFA, AMR_OTP, AMR_PASSWORD, AMR_RECOVERY_CODE,
        ELEVATED_AUTHENTICATION_TTL, LOCK_DURATION, LOGIN_EXPIRY, LoginFailureReason, LoginStatus,
        MAX_FAILED_ATTEMPTS, MAX_OTP_ATTEMPTS, SESSION_EXPIRY,
        model::{Login, Session},
        password::{HashOptions, PasswordHashSetting, PasswordHasher, VerifyResult},
        repository::{CreateSessionInput, LoginRepository, SessionRepository},
        totp::TotpVerifier,
    },
    user::{
        model::{
            CredentialData, CredentialType, OtpCredentialData, Password,
            RecoveryCodeCredentialData, User,
        },
        repository::{UserCredentialRepository, UserRepository},
    },
};

// ─── Input/Output Types ──────────────────────────────────────────────────────

/// Device and network context for session creation.
pub struct SessionContext {
    pub device_name: Option<String>,
    pub device_type: Option<String>,
    pub os_name: Option<String>,
    pub os_version: Option<String>,
    pub browser_name: Option<String>,
    pub browser_version: Option<String>,
    pub user_agent: Option<String>,
    pub ip_address: Option<String>,
}

/// Result of a successful identifier step.
pub struct IdentifierResult {
    pub login: Login,
    pub user: User,
    pub credential_types: Vec<CredentialType>,
}

/// The outcome of a challenge step.
#[derive(Debug)]
pub enum ChallengeOutcome {
    /// Password was verified and the user has no OTP credential — session
    /// created immediately with password-only ACR.
    Authenticated { login: Login, session: Box<Session> },
    /// Password was verified and the user has an OTP credential — the client
    /// MUST call challenge again with [`CredentialType::Otp`].
    MfaRequired { login: Login },
}

// ─── LoginService ────────────────────────────────────────────────────────────

pub struct LoginService {
    user_repo: Arc<dyn UserRepository>,
    credential_repo: Arc<dyn UserCredentialRepository>,
    session_repo: Arc<dyn SessionRepository>,
    login_repo: Arc<dyn LoginRepository>,
    password_hasher: Arc<dyn PasswordHasher>,
    totp_verifier: Arc<dyn TotpVerifier>,
    hash_options: Arc<dyn SettingProvider<PasswordHashSetting>>,
}

impl LoginService {
    #[must_use]
    pub fn new(
        user_repo: Arc<dyn UserRepository>,
        credential_repo: Arc<dyn UserCredentialRepository>,
        session_repo: Arc<dyn SessionRepository>,
        login_repo: Arc<dyn LoginRepository>,
        password_hasher: Arc<dyn PasswordHasher>,
        totp_verifier: Arc<dyn TotpVerifier>,
        hash_options: Arc<dyn SettingProvider<PasswordHashSetting>>,
    ) -> Self {
        Self {
            user_repo,
            credential_repo,
            session_repo,
            login_repo,
            password_hasher,
            totp_verifier,
            hash_options,
        }
    }

    pub async fn get(&self, login_oid: Uuid) -> Result<Login, AppError> {
        self.login_repo
            .find_by_oid(login_oid)
            .await?
            .ok_or_else(|| AppError::from_code(AuthErrorCode::InvalidLoginState))
    }

    /// Return the credential types currently available to the user.
    ///
    /// This is also used by the first-party login UI when an authorization
    /// interaction is already bound to an active session. In that case the UI
    /// can offer a fresh second-factor challenge without asking for the
    /// password again.
    pub async fn credential_types(
        &self,
        user_oid: identity_domain::user::UserOid,
    ) -> Result<Vec<CredentialType>, AppError> {
        let mut credential_types = Vec::new();
        for credential_type in [
            CredentialType::Password,
            CredentialType::Otp,
            CredentialType::RecoveryCode,
        ] {
            if !self
                .credential_repo
                .find_by_user_oid_and_type(user_oid, credential_type)
                .await?
                .is_empty()
            {
                credential_types.push(credential_type);
            }
        }
        Ok(credential_types)
    }

    pub async fn change_password(
        &self,
        user_oid: identity_domain::user::UserOid,
        new_password: &str,
    ) -> Result<(), AppError> {
        if new_password.len() < 12 {
            return Err(AppError::from_code(
                crate::error::codes::common::CommonErrorCode::ValidationFailed,
            )
            .with_field_error(
                "newPassword",
                AppError::from_code(AuthErrorCode::PasswordTooShort),
            ));
        }
        let credential = self
            .credential_repo
            .find_by_user_oid_and_type(user_oid, CredentialType::Password)
            .await?
            .into_iter()
            .next()
            .ok_or_else(|| AppError::from_code(AuthErrorCode::CredentialTypeUnsupported))?;
        let stored_password = match &credential.data {
            CredentialData::Password(password) => password.clone(),
            _ => {
                return Err(AppError::from_code(
                    AuthErrorCode::CredentialTypeUnsupported,
                ));
            }
        };
        let options = self.hash_options.current_value();
        let hasher = Arc::clone(&self.password_hasher);
        let new_password_to_verify = new_password.to_owned();
        let verify_options = options.clone();
        let verified = super::password::run_password_hashing(move || {
            hasher.verify(&new_password_to_verify, &stored_password, &verify_options)
        })
        .await?;
        if verified != VerifyResult::Failure {
            return Err(AppError::from_code(
                crate::error::codes::common::CommonErrorCode::ValidationFailed,
            )
            .with_field_error(
                "newPassword",
                AppError::from_code(AuthErrorCode::PasswordUnchanged),
            ));
        }
        let hasher = Arc::clone(&self.password_hasher);
        let new_password = new_password.to_owned();
        let password = super::password::run_password_hashing(move || {
            hasher.hash(&new_password, options.as_ref())
        })
        .await?;
        self.credential_repo
            .update_password_by_oid(credential.oid, &password)
            .await?;
        Ok(())
    }

    /// Fetch the user associated with a login by their OID.
    pub async fn get_user(
        &self,
        user_oid: identity_domain::user::UserOid,
    ) -> Result<User, AppError> {
        self.user_repo
            .find_by_oid(user_oid)
            .await?
            .ok_or_else(|| AppError::from_code(AuthErrorCode::UserNotFound))
    }

    /// Step 1: Verify the identifier (email or username) and bind the
    /// resolved user onto an existing login flow.
    pub async fn identify(
        &self,
        login_oid: Uuid,
        identifier: &str,
    ) -> Result<IdentifierResult, AppError> {
        let identifier = identifier.trim();
        if identifier.is_empty() {
            return Err(AppError::from_code(AuthErrorCode::IdentifierRequired));
        }

        let login_state = self
            .login_repo
            .find_by_oid(login_oid)
            .await?
            .ok_or_else(|| AppError::from_code(AuthErrorCode::InvalidLoginState))?;

        if login_state.status != LoginStatus::CREATED {
            return Err(AppError::from_code(AuthErrorCode::InvalidLoginState));
        }

        // Look up user by normalized email or username.
        let user = self.user_repo.find_by_identifier(identifier).await?;

        // Check if user is locked.
        if user.locked {
            if let Some(until) = user.locked_until {
                if Utc::now() < until {
                    return Err(AppError::from_code(AuthErrorCode::UserLocked));
                }
                self.user_repo.reset_failed_attempts(user.oid).await?;
            } else {
                return Err(AppError::from_code(AuthErrorCode::UserLocked));
            }
        }

        if !user.enabled {
            return Err(AppError::from_code(AuthErrorCode::UserLocked));
        }

        let credential_types = self.credential_types(user.oid).await?;

        // Bind the resolved user onto the existing login record.
        let login = self
            .login_repo
            .bind_user(login_oid, user.oid.into())
            .await?;

        Ok(IdentifierResult {
            login,
            user,
            credential_types,
        })
    }

    /// Step 2: Verify a credential and either create a session or signal that
    /// MFA is required.
    ///
    /// The user is resolved from the login record itself (via `login.user_oid`)
    /// so no identifier string needs to be re-submitted by the client.
    ///
    /// # Password flow
    /// - If the user has an OTP credential: returns [`ChallengeOutcome::MfaRequired`].
    /// - Otherwise: creates a session, or refreshes the bound session during
    ///   reauthentication, with `acr = ACR_AAL1` and returns
    ///   [`ChallengeOutcome::Authenticated`].
    ///
    /// # OTP flow
    /// The login status MUST already be `mfa_required` (set by a prior
    /// password challenge). Up to [`MAX_OTP_ATTEMPTS`] invalid codes are allowed
    /// per login flow; further attempts return [`AuthErrorCode::TooManyAttempts`]
    /// and invalidate the login. Creates or refreshes the bound session with
    /// `acr = ACR_AAL2` and an internal expiry on success.
    pub async fn challenge(
        &self,
        login_oid: Uuid,
        credential_type: CredentialType,
        credential: &str,
        ctx: SessionContext,
    ) -> Result<ChallengeOutcome, AppError> {
        // Look up the login record (carries user_oid — no extra identifier needed).
        let login = self
            .login_repo
            .find_by_oid(login_oid)
            .await?
            .ok_or_else(|| AppError::from_code(AuthErrorCode::InvalidLoginState))?;

        if login.user_oid.is_none() {
            return Err(AppError::from_code(AuthErrorCode::InvalidLoginState));
        }

        // Check login expiry for all credential types.
        let expiry_duration = chrono::Duration::from_std(LOGIN_EXPIRY)
            .unwrap_or_else(|_| chrono::Duration::seconds(300));
        if Utc::now().signed_duration_since(login.created_at) > expiry_duration {
            if let Err(e) = self
                .login_repo
                .update_status(login.oid, LoginStatus::FAILED, None, None)
                .await
            {
                tracing::error!(error = %e, "failed to update login status on expiry");
            }
            return Err(AppError::from_code(AuthErrorCode::LoginExpired));
        }

        let hash_options = self.hash_options.current_value();

        match credential_type {
            CredentialType::Password => {
                self.challenge_password(login, credential, hash_options.as_ref(), ctx)
                    .await
            }
            CredentialType::Otp => self.challenge_otp(login, credential, ctx).await,
            CredentialType::RecoveryCode => {
                self.challenge_recovery_code(login, credential, ctx).await
            }
        }
    }

    // ── Private helpers ──────────────────────────────────────────────────────

    async fn challenge_password(
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
        let stored_password = stored_password.clone();
        let hash_options = hash_options.clone();
        let verify_hash_options = hash_options.clone();
        let verify_result = super::password::run_password_hashing(move || {
            password_hasher.verify(&verify_password, &stored_password, &verify_hash_options)
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
                    let rehash = super::password::run_password_hashing(move || {
                        password_hasher.hash(&credential, &hash_options)
                    })
                    .await;

                    match rehash {
                        Ok(new_password) => {
                            if let Err(error) = self
                                .credential_repo
                                .update_password_by_oid(password_cred.oid, &new_password)
                                .await
                            {
                                tracing::error!(
                                    error = %error,
                                    "failed to persist rehashed password"
                                );
                            }
                        }
                        Err(error) => {
                            tracing::error!(error = %error, "failed to rehash password");
                        }
                    }
                }

                // Check if the user has an OTP credential.
                let otp_credentials = self
                    .credential_repo
                    .find_by_user_oid_and_type(user.oid, CredentialType::Otp)
                    .await?;

                if otp_credentials.is_empty() {
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
                        tracing::error!(error = %e, "failed to update login status to authenticated");
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
                        tracing::error!(error = %e, "failed to update login status to mfa_required");
                    }
                    if let Err(e) = self.login_repo.reset_failed_attempts(login.oid).await {
                        tracing::error!(error = %e, "failed to reset login failed attempts for MFA");
                    }

                    Ok(ChallengeOutcome::MfaRequired { login })
                }
            }
        }
    }

    async fn challenge_otp(
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
            tracing::error!(error = %e, "failed to update login status to authenticated");
        }

        Ok(ChallengeOutcome::Authenticated {
            login,
            session: Box::new(session),
        })
    }

    async fn challenge_recovery_code(
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
        let expected_hash = super::mfa::recovery_code_hash(code);
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
            bool::from(subtle::ConstantTimeEq::ct_eq(
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
            tracing::error!(%error, "failed to authenticate recovery-code login");
        }
        Ok(ChallengeOutcome::Authenticated {
            login,
            session: Box::new(session),
        })
    }

    async fn fail_login_for_too_many_otp_attempts(&self, login_oid: Uuid) {
        if let Err(e) = self
            .login_repo
            .update_status(login_oid, LoginStatus::FAILED, None, None)
            .await
        {
            tracing::error!(error = %e, "failed to update login status after too many OTP attempts");
        }
    }

    async fn complete_session(
        &self,
        login: &Login,
        user_oid: Uuid,
        ctx: SessionContext,
        acr: &str,
        amr: &[String],
    ) -> Result<Session, AppError> {
        if let Some(session_oid) = login.session_oid {
            return Ok(self
                .session_repo
                .reauthenticate_by_oid(
                    session_oid,
                    user_oid,
                    acr,
                    authentication_context_expires_at(acr),
                    amr,
                )
                .await?);
        }
        self.create_session(user_oid, ctx, acr, amr).await
    }

    /// Create a session only for a login that is not bound to an existing one.
    async fn create_session(
        &self,
        user_oid: Uuid,
        ctx: SessionContext,
        acr: &str,
        amr: &[String],
    ) -> Result<Session, AppError> {
        let now = Utc::now();
        let expires_at = now
            + chrono::Duration::from_std(SESSION_EXPIRY)
                .unwrap_or_else(|_| chrono::Duration::days(7));
        let acr_expires_at = Some(authentication_context_expires_at(acr));
        Ok(self
            .session_repo
            .create(CreateSessionInput {
                user_oid,
                device_name: ctx.device_name,
                device_type: ctx.device_type,
                os_name: ctx.os_name,
                os_version: ctx.os_version,
                browser_name: ctx.browser_name,
                browser_version: ctx.browser_version,
                user_agent: ctx.user_agent,
                ip_address: ctx.ip_address,
                expires_at: Some(expires_at),
                acr: Some(acr.to_owned()),
                acr_expires_at,
                amr: amr.to_vec(),
            })
            .await?)
    }

    async fn ensure_user_can_authenticate(&self, user: &User) -> Result<(), AppError> {
        if !user.enabled {
            return Err(AppError::from_code(AuthErrorCode::UserLocked));
        }
        if !user.locked {
            return Ok(());
        }
        match user.locked_until {
            Some(until) if Utc::now() >= until => {
                self.user_repo.reset_failed_attempts(user.oid).await?;
                Ok(())
            }
            _ => Err(AppError::from_code(AuthErrorCode::UserLocked)),
        }
    }
}

fn authentication_context_expires_at(acr: &str) -> chrono::DateTime<Utc> {
    let ttl = if acr == ACR_AAL2 {
        ELEVATED_AUTHENTICATION_TTL
    } else {
        identity_domain::auth::RECENT_AUTHENTICATION_TTL
    };
    Utc::now() + chrono::Duration::from_std(ttl).unwrap_or_else(|_| chrono::Duration::minutes(5))
}

fn can_challenge_second_factor(login: &Login) -> bool {
    login.status == LoginStatus::MFA_REQUIRED
        || (login.status == LoginStatus::IDENTIFIER_VERIFIED && login.session_oid.is_some())
}

fn failed_attempt_lock_until() -> chrono::DateTime<Utc> {
    Utc::now()
        + chrono::Duration::from_std(LOCK_DURATION)
            .unwrap_or_else(|_| chrono::Duration::seconds(900))
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use async_trait::async_trait;
    use chrono::Utc;
    use identity_domain::{
        auth::{
            ACR_AAL2, AMR_MFA, AMR_OTP, AMR_PASSWORD, LoginFailureReason, LoginStatus,
            MAX_FAILED_ATTEMPTS, MAX_OTP_ATTEMPTS,
            model::{Login, Session, SessionOid},
            password::{HashOptions, PasswordHashSetting, VerifyResult},
            repository::{
                CreateSessionInput, LoginRepository, LoginRepositoryError, SessionRepository,
                SessionRepositoryError,
            },
            totp::TotpVerifier,
        },
        user::{
            CredentialData, CredentialType, OtpCredentialData, User, UserCredential,
            UserCredentialOid, UserOid,
            model::{Argon2Options, Argon2Variant, Argon2Version, Password},
            repository::{
                UserCredentialRepository, UserCredentialRepositoryError, UserRepository,
                UserRepositoryError,
            },
        },
    };
    use uuid::Uuid;

    use super::{LoginService, SessionContext};
    use crate::{
        application::error::{AppError, code::AppErrorCode, codes::auth::AuthErrorCode},
        setting::runtime::SettingProvider,
    };

    struct FixedHashOptions(Arc<HashOptions>);

    impl SettingProvider<PasswordHashSetting> for FixedHashOptions {
        fn current_value(&self) -> Arc<HashOptions> {
            Arc::clone(&self.0)
        }
    }

    struct AlwaysInvalidTotp;

    impl TotpVerifier for AlwaysInvalidTotp {
        fn verify(
            &self,
            _otp_data: &OtpCredentialData,
            _code: &str,
        ) -> Result<Option<u64>, identity_domain::auth::totp::TotpError> {
            Ok(None)
        }
    }

    struct StubPasswordHasher;

    impl identity_domain::auth::password::PasswordHasher for StubPasswordHasher {
        fn hash(
            &self,
            _password: &str,
            _options: &HashOptions,
        ) -> Result<Password, identity_domain::auth::password::PasswordHashError> {
            Err(
                identity_domain::auth::password::PasswordHashError::HashFailed(
                    "not used in OTP tests".to_owned(),
                ),
            )
        }

        fn verify(
            &self,
            _password: &str,
            _stored: &Password,
            _options: &HashOptions,
        ) -> Result<VerifyResult, identity_domain::auth::password::PasswordHashError> {
            Err(
                identity_domain::auth::password::PasswordHashError::HashFailed(
                    "not used in OTP tests".to_owned(),
                ),
            )
        }
    }

    struct TestUserRepo {
        user: Arc<Mutex<User>>,
    }

    #[async_trait]
    impl UserRepository for TestUserRepo {
        async fn find_by_identifier(&self, _identifier: &str) -> Result<User, UserRepositoryError> {
            Ok(self.user.lock().unwrap().clone())
        }

        async fn find_by_oid(&self, oid: UserOid) -> Result<Option<User>, UserRepositoryError> {
            let user = self.user.lock().unwrap();
            Ok((user.oid == oid).then(|| user.clone()))
        }

        async fn increment_failed_attempts(
            &self,
            user_oid: UserOid,
            lock_threshold: i32,
            lock_until: chrono::DateTime<chrono::Utc>,
        ) -> Result<i32, UserRepositoryError> {
            let mut user = self.user.lock().unwrap();
            if user.oid != user_oid {
                return Err(UserRepositoryError::UserNotFound);
            }
            user.failed_attempts += 1;
            if user.failed_attempts >= lock_threshold {
                user.locked = true;
                user.locked_until = Some(lock_until);
            }
            Ok(user.failed_attempts)
        }

        async fn reset_failed_attempts(
            &self,
            user_oid: UserOid,
        ) -> Result<(), UserRepositoryError> {
            let mut user = self.user.lock().unwrap();
            if user.oid != user_oid {
                return Err(UserRepositoryError::UserNotFound);
            }
            user.failed_attempts = 0;
            user.locked = false;
            user.locked_until = None;
            Ok(())
        }
    }

    struct TestCredentialRepo {
        credentials: Vec<UserCredential>,
    }

    #[async_trait]
    impl UserCredentialRepository for TestCredentialRepo {
        async fn find_by_user_oid_and_type(
            &self,
            _user_oid: UserOid,
            credential_type: CredentialType,
        ) -> Result<Vec<UserCredential>, UserCredentialRepositoryError> {
            Ok(self
                .credentials
                .iter()
                .filter(|credential| credential.r#type == credential_type)
                .cloned()
                .collect())
        }

        async fn update_password_by_oid(
            &self,
            _oid: UserCredentialOid,
            _password: &Password,
        ) -> Result<(), UserCredentialRepositoryError> {
            Ok(())
        }

        async fn consume_totp_counter(
            &self,
            _credential_oid: UserCredentialOid,
            _counter: u64,
        ) -> Result<bool, UserCredentialRepositoryError> {
            Ok(true)
        }

        async fn replace_by_user_oid(
            &self,
            _user_oid: UserOid,
            _replacements: Vec<(CredentialType, Vec<CredentialData>)>,
        ) -> Result<(), UserCredentialRepositoryError> {
            Ok(())
        }

        async fn enable_totp_if_disabled(
            &self,
            _user_oid: UserOid,
            _otp: identity_domain::user::OtpCredentialData,
            _recovery_codes: Vec<identity_domain::user::RecoveryCodeCredentialData>,
        ) -> Result<bool, UserCredentialRepositoryError> {
            Ok(false)
        }

        async fn replace_recovery_codes_if_totp_enabled(
            &self,
            _user_oid: UserOid,
            _recovery_codes: Vec<identity_domain::user::RecoveryCodeCredentialData>,
        ) -> Result<bool, UserCredentialRepositoryError> {
            Ok(false)
        }

        async fn consume_recovery_code_by_oid(
            &self,
            _credential_oid: UserCredentialOid,
        ) -> Result<bool, UserCredentialRepositoryError> {
            Ok(true)
        }
    }

    struct TestSessionRepo;

    #[async_trait]
    impl SessionRepository for TestSessionRepo {
        async fn find_by_oid(
            &self,
            _oid: SessionOid,
        ) -> Result<Option<Session>, SessionRepositoryError> {
            Ok(None)
        }

        async fn find_active_accounts_by_oids(
            &self,
            _oids: &[SessionOid],
        ) -> Result<Vec<identity_domain::auth::model::ActiveSession>, SessionRepositoryError>
        {
            Ok(Vec::new())
        }

        async fn create(
            &self,
            input: CreateSessionInput,
        ) -> Result<Session, SessionRepositoryError> {
            Ok(Session {
                oid: SessionOid(Uuid::new_v4()),
                user_oid: input.user_oid,
                status: identity_domain::auth::SessionStatus::ACTIVE,
                device_name: input.device_name,
                device_type: input.device_type,
                os_name: input.os_name,
                os_version: input.os_version,
                browser_name: input.browser_name,
                browser_version: input.browser_version,
                user_agent: input.user_agent,
                ip_address: input.ip_address,
                last_active_at: None,
                expires_at: input.expires_at,
                revoked_at: None,
                created_at: Utc::now(),
                acr: input.acr,
                acr_expires_at: input.acr_expires_at,
                amr: input.amr,
            })
        }

        async fn reauthenticate_by_oid(
            &self,
            oid: SessionOid,
            expected_user_oid: Uuid,
            acr: &str,
            acr_expires_at: chrono::DateTime<Utc>,
            amr: &[String],
        ) -> Result<Session, SessionRepositoryError> {
            Ok(Session {
                oid,
                user_oid: expected_user_oid,
                status: identity_domain::auth::SessionStatus::ACTIVE,
                device_name: None,
                device_type: None,
                os_name: None,
                os_version: None,
                browser_name: None,
                browser_version: None,
                user_agent: None,
                ip_address: None,
                last_active_at: Some(Utc::now()),
                expires_at: None,
                revoked_at: None,
                created_at: Utc::now(),
                acr: Some(acr.to_owned()),
                acr_expires_at: Some(acr_expires_at),
                amr: amr.to_vec(),
            })
        }

        async fn touch_active_by_oid(
            &self,
            _oid: SessionOid,
        ) -> Result<bool, SessionRepositoryError> {
            Ok(true)
        }

        async fn revoke_by_oid(
            &self,
            _oid: SessionOid,
            _revoked_at: chrono::DateTime<chrono::Utc>,
        ) -> Result<Option<Session>, SessionRepositoryError> {
            Ok(None)
        }
    }

    #[derive(Default)]
    struct TestLoginRepoState {
        logins: Vec<Login>,
        update_status_calls: Vec<(Uuid, LoginStatus)>,
    }

    struct TestLoginRepo {
        state: Arc<Mutex<TestLoginRepoState>>,
    }

    #[async_trait]
    impl LoginRepository for TestLoginRepo {
        async fn find_by_oid(&self, oid: Uuid) -> Result<Option<Login>, LoginRepositoryError> {
            let state = self.state.lock().unwrap();
            Ok(state.logins.iter().find(|login| login.oid == oid).cloned())
        }

        async fn create_pending(
            &self,
            _client_oid: Uuid,
            _client_authorization_oid: Uuid,
            _requested_acr: Option<&str>,
        ) -> Result<Login, LoginRepositoryError> {
            Err(LoginRepositoryError::LoginNotFound)
        }

        async fn bind_user(
            &self,
            _login_oid: Uuid,
            _user_oid: Uuid,
        ) -> Result<Login, LoginRepositoryError> {
            Err(LoginRepositoryError::LoginNotFound)
        }

        async fn update_status(
            &self,
            login_oid: Uuid,
            status: LoginStatus,
            _session_oid: Option<SessionOid>,
            _acr: Option<&str>,
        ) -> Result<(), LoginRepositoryError> {
            let mut state = self.state.lock().unwrap();
            state.update_status_calls.push((login_oid, status));
            if let Some(login) = state.logins.iter_mut().find(|login| login.oid == login_oid) {
                login.status = status;
            }
            Ok(())
        }

        async fn bind_session(
            &self,
            login_oid: Uuid,
            session_oid: SessionOid,
        ) -> Result<(), LoginRepositoryError> {
            let mut state = self.state.lock().unwrap();
            let login = state
                .logins
                .iter_mut()
                .find(|login| login.oid == login_oid)
                .ok_or(LoginRepositoryError::LoginNotFound)?;
            login.session_oid = Some(session_oid);
            Ok(())
        }

        async fn increment_failed_attempts(
            &self,
            login_oid: Uuid,
            _failure_reason: Option<LoginFailureReason>,
        ) -> Result<i32, LoginRepositoryError> {
            let mut state = self.state.lock().unwrap();
            let login = state
                .logins
                .iter_mut()
                .find(|login| login.oid == login_oid)
                .ok_or(LoginRepositoryError::LoginNotFound)?;
            login.failed_attempts += 1;
            Ok(login.failed_attempts)
        }

        async fn reset_failed_attempts(&self, login_oid: Uuid) -> Result<(), LoginRepositoryError> {
            let mut state = self.state.lock().unwrap();
            if let Some(login) = state.logins.iter_mut().find(|login| login.oid == login_oid) {
                login.failed_attempts = 0;
            }
            Ok(())
        }
    }

    fn test_user() -> User {
        User {
            oid: UserOid(Uuid::new_v4()),
            email: "user@example.com".to_owned(),
            email_normalized: "user@example.com".to_owned(),
            name: "user".to_owned(),
            name_normalized: "user".to_owned(),
            given_name: None,
            family_name: None,
            middle_name: None,
            nickname: None,
            profile: None,
            picture: None,
            website: None,
            gender: None,
            birthdate: None,
            zoneinfo: None,
            locale: None,
            theme: None,
            email_verified: true,
            phone_number: None,
            phone_number_verified: None,
            address_formatted: None,
            address_street_address: None,
            address_locality: None,
            address_region: None,
            address_postal_code: None,
            address_country: None,
            failed_attempts: 0,
            enabled: true,
            locked: false,
            locked_until: None,
            created_at: Utc::now(),
            updated_at: None,
        }
    }

    fn test_login(user_oid: Uuid, failed_attempts: i32) -> Login {
        Login {
            oid: Uuid::new_v4(),
            client_oid: Uuid::new_v4(),
            client_authorization_oid: Uuid::new_v4(),
            session_oid: None,
            user_oid: Some(user_oid),
            status: LoginStatus::MFA_REQUIRED,
            failed_attempts,
            created_at: Utc::now(),
            acr: None,
            requested_acr: None,
        }
    }

    fn otp_service(login_repo: Arc<TestLoginRepo>, user: User) -> (LoginService, Arc<Mutex<User>>) {
        let user = Arc::new(Mutex::new(user));
        let service = LoginService::new(
            Arc::new(TestUserRepo {
                user: Arc::clone(&user),
            }),
            Arc::new(TestCredentialRepo {
                credentials: vec![UserCredential {
                    oid: UserCredentialOid(Uuid::new_v4()),
                    r#type: CredentialType::Otp,
                    data: CredentialData::Otp(OtpCredentialData {
                        secret: "secret".to_owned(),
                        digits: 6,
                        period: 30,
                        algorithm: identity_domain::user::OtpAlgorithm::Sha1,
                        last_used_counter: None,
                    }),
                }],
            }),
            Arc::new(TestSessionRepo),
            login_repo,
            Arc::new(StubPasswordHasher),
            Arc::new(AlwaysInvalidTotp),
            Arc::new(FixedHashOptions(Arc::new(HashOptions::Argon2(
                Argon2Options {
                    variant: Argon2Variant::Argon2id,
                    version: Argon2Version::Argon2013,
                    time_cost: 3,
                    memory_cost: 65_536,
                    parallelism: 4,
                },
            )))),
        );
        (service, user)
    }

    fn assert_error_code(error: AppError, expected: AuthErrorCode) {
        assert_eq!(error.code(), expected.code());
    }

    #[tokio::test]
    async fn forced_reauthentication_reuses_the_bound_session() {
        let user = test_user();
        let mut login = test_login(Uuid::from(user.oid), 0);
        let bound_session_oid = SessionOid(Uuid::new_v4());
        login.session_oid = Some(bound_session_oid);
        let login_repo = Arc::new(TestLoginRepo {
            state: Arc::new(Mutex::new(TestLoginRepoState {
                logins: vec![login.clone()],
                ..Default::default()
            })),
        });
        let (service, _) = otp_service(login_repo, user);

        let session = service
            .complete_session(
                &login,
                login.user_oid.unwrap(),
                SessionContext {
                    device_name: None,
                    device_type: None,
                    os_name: None,
                    os_version: None,
                    browser_name: None,
                    browser_version: None,
                    user_agent: None,
                    ip_address: None,
                },
                ACR_AAL2,
                &[
                    AMR_PASSWORD.to_owned(),
                    AMR_OTP.to_owned(),
                    AMR_MFA.to_owned(),
                ],
            )
            .await
            .unwrap();

        assert_eq!(session.oid, bound_session_oid);
        assert_eq!(session.acr.as_deref(), Some(ACR_AAL2));
    }

    #[tokio::test]
    async fn bound_reauthentication_can_challenge_otp_without_password() {
        let user = test_user();
        let mut login = test_login(Uuid::from(user.oid), 0);
        login.status = LoginStatus::IDENTIFIER_VERIFIED;
        login.session_oid = Some(SessionOid(Uuid::new_v4()));
        let login_oid = login.oid;
        let login_repo = Arc::new(TestLoginRepo {
            state: Arc::new(Mutex::new(TestLoginRepoState {
                logins: vec![login],
                ..Default::default()
            })),
        });
        let (service, _) = otp_service(login_repo, user);

        let error = service
            .challenge(
                login_oid,
                CredentialType::Otp,
                "000000",
                SessionContext {
                    device_name: None,
                    device_type: None,
                    os_name: None,
                    os_version: None,
                    browser_name: None,
                    browser_version: None,
                    user_agent: None,
                    ip_address: None,
                },
            )
            .await
            .expect_err("the test verifier rejects the code after state validation");

        assert_error_code(error, AuthErrorCode::InvalidOtp);
    }

    #[tokio::test]
    async fn unbound_login_cannot_use_otp_as_a_password_replacement() {
        let user = test_user();
        let mut login = test_login(Uuid::from(user.oid), 0);
        login.status = LoginStatus::IDENTIFIER_VERIFIED;
        let login_oid = login.oid;
        let login_repo = Arc::new(TestLoginRepo {
            state: Arc::new(Mutex::new(TestLoginRepoState {
                logins: vec![login],
                ..Default::default()
            })),
        });
        let (service, _) = otp_service(login_repo, user);

        let error = service
            .challenge(
                login_oid,
                CredentialType::Otp,
                "000000",
                SessionContext {
                    device_name: None,
                    device_type: None,
                    os_name: None,
                    os_version: None,
                    browser_name: None,
                    browser_version: None,
                    user_agent: None,
                    ip_address: None,
                },
            )
            .await
            .expect_err("unbound login must still verify the password first");

        assert_error_code(error, AuthErrorCode::InvalidLoginState);
    }

    #[tokio::test]
    async fn otp_rejects_when_attempt_limit_already_reached() {
        let user = test_user();
        let login = test_login(Uuid::from(user.oid), MAX_OTP_ATTEMPTS);
        let login_oid = login.oid;
        let login_repo = Arc::new(TestLoginRepo {
            state: Arc::new(Mutex::new(TestLoginRepoState {
                logins: vec![login],
                ..Default::default()
            })),
        });
        let (service, _) = otp_service(Arc::clone(&login_repo), user);

        let error = service
            .challenge(
                login_oid,
                CredentialType::Otp,
                "000000",
                SessionContext {
                    device_name: None,
                    device_type: None,
                    os_name: None,
                    os_version: None,
                    browser_name: None,
                    browser_version: None,
                    user_agent: None,
                    ip_address: None,
                },
            )
            .await
            .expect_err("expected too many attempts");

        assert_error_code(error, AuthErrorCode::TooManyAttempts);
        let state = login_repo.state.lock().unwrap();
        assert_eq!(state.update_status_calls.len(), 1);
        assert_eq!(state.update_status_calls[0].1, LoginStatus::FAILED);
    }

    #[tokio::test]
    async fn otp_invalid_code_returns_invalid_otp_before_limit() {
        let user = test_user();
        let login = test_login(Uuid::from(user.oid), MAX_OTP_ATTEMPTS - 2);
        let login_oid = login.oid;
        let login_repo = Arc::new(TestLoginRepo {
            state: Arc::new(Mutex::new(TestLoginRepoState {
                logins: vec![login],
                ..Default::default()
            })),
        });
        let (service, _) = otp_service(Arc::clone(&login_repo), user);

        let error = service
            .challenge(
                login_oid,
                CredentialType::Otp,
                "000000",
                SessionContext {
                    device_name: None,
                    device_type: None,
                    os_name: None,
                    os_version: None,
                    browser_name: None,
                    browser_version: None,
                    user_agent: None,
                    ip_address: None,
                },
            )
            .await
            .expect_err("expected invalid otp");

        assert_error_code(error, AuthErrorCode::InvalidOtp);
        assert_eq!(
            login_repo.state.lock().unwrap().logins[0].failed_attempts,
            MAX_OTP_ATTEMPTS - 1
        );
    }

    #[tokio::test]
    async fn otp_last_allowed_failure_returns_too_many_attempts() {
        let user = test_user();
        let login = test_login(Uuid::from(user.oid), MAX_OTP_ATTEMPTS - 1);
        let login_oid = login.oid;
        let login_repo = Arc::new(TestLoginRepo {
            state: Arc::new(Mutex::new(TestLoginRepoState {
                logins: vec![login],
                ..Default::default()
            })),
        });
        let (service, _) = otp_service(login_repo.clone(), user);

        let error = service
            .challenge(
                login_oid,
                CredentialType::Otp,
                "000000",
                SessionContext {
                    device_name: None,
                    device_type: None,
                    os_name: None,
                    os_version: None,
                    browser_name: None,
                    browser_version: None,
                    user_agent: None,
                    ip_address: None,
                },
            )
            .await
            .expect_err("expected too many attempts");

        assert_error_code(error, AuthErrorCode::TooManyAttempts);
        let state = login_repo.state.lock().unwrap();
        assert_eq!(state.logins[0].failed_attempts, MAX_OTP_ATTEMPTS);
        assert_eq!(state.update_status_calls[0].1, LoginStatus::FAILED);
    }

    #[tokio::test]
    async fn otp_failures_across_fresh_logins_lock_the_user() {
        let user = test_user();
        let user_oid = Uuid::from(user.oid);
        let logins: Vec<_> = (0..=MAX_FAILED_ATTEMPTS)
            .map(|_| test_login(user_oid, 0))
            .collect();
        let login_oids: Vec<_> = logins.iter().map(|login| login.oid).collect();
        let login_repo = Arc::new(TestLoginRepo {
            state: Arc::new(Mutex::new(TestLoginRepoState {
                logins,
                ..Default::default()
            })),
        });
        let (service, user_state) = otp_service(login_repo, user);

        for login_oid in &login_oids[..usize::try_from(MAX_FAILED_ATTEMPTS - 1).unwrap()] {
            let error = service
                .challenge(
                    *login_oid,
                    CredentialType::Otp,
                    "000000",
                    SessionContext {
                        device_name: None,
                        device_type: None,
                        os_name: None,
                        os_version: None,
                        browser_name: None,
                        browser_version: None,
                        user_agent: None,
                        ip_address: None,
                    },
                )
                .await
                .expect_err("expected invalid otp");
            assert_error_code(error, AuthErrorCode::InvalidOtp);
        }

        let threshold_index = usize::try_from(MAX_FAILED_ATTEMPTS - 1).unwrap();
        let error = service
            .challenge(
                login_oids[threshold_index],
                CredentialType::Otp,
                "000000",
                SessionContext {
                    device_name: None,
                    device_type: None,
                    os_name: None,
                    os_version: None,
                    browser_name: None,
                    browser_version: None,
                    user_agent: None,
                    ip_address: None,
                },
            )
            .await
            .expect_err("expected threshold failure");
        assert_error_code(error, AuthErrorCode::TooManyAttempts);
        {
            let user = user_state.lock().unwrap();
            assert_eq!(user.failed_attempts, MAX_FAILED_ATTEMPTS);
            assert!(user.locked);
        }

        let error = service
            .challenge(
                login_oids[threshold_index + 1],
                CredentialType::Otp,
                "000000",
                SessionContext {
                    device_name: None,
                    device_type: None,
                    os_name: None,
                    os_version: None,
                    browser_name: None,
                    browser_version: None,
                    user_agent: None,
                    ip_address: None,
                },
            )
            .await
            .expect_err("expected user lock to apply to another login");
        assert_error_code(error, AuthErrorCode::UserLocked);
    }
}
