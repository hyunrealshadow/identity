use std::sync::Arc;

use chrono::Utc;
use uuid::Uuid;

use crate::{
    error::{AppError, code::AppErrorCode, codes::auth::AuthErrorCode},
    setting::runtime::SettingProvider,
};
use identity_domain::{
    auth::{
        ACR_EXPIRY, ACR_MFA, ACR_PASSWORD, LOCK_DURATION, LOGIN_EXPIRY, LoginStatus,
        MAX_FAILED_ATTEMPTS, SESSION_EXPIRY,
        model::{Login, Session},
        password::{HashOptions, PasswordHashSetting, PasswordHasher, VerifyResult},
        repository::{LoginRepository, SessionRepository},
        totp::TotpVerifier,
    },
    user::{
        model::{CredentialData, CredentialType, OtpCredentialData, Password, User},
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
pub enum ChallengeOutcome {
    /// Password was verified and the user has no OTP credential — session
    /// created immediately with password-only ACR.
    Authenticated { login: Login, session: Box<Session> },
    /// Password was verified and the user has an OTP credential — the client
    /// MUST call challenge again with `credential_type = "otp"`.
    MfaRequired { login: Login },
}

// ─── LoginService ────────────────────────────────────────────────────────────

pub struct LoginService {
    pub(crate) user_repo: Arc<dyn UserRepository>,
    pub(crate) credential_repo: Arc<dyn UserCredentialRepository>,
    pub(crate) session_repo: Arc<dyn SessionRepository>,
    pub(crate) login_repo: Arc<dyn LoginRepository>,
    pub(crate) password_hasher: Arc<dyn PasswordHasher>,
    pub(crate) totp_verifier: Arc<dyn TotpVerifier>,
    pub(crate) hash_options: Arc<dyn SettingProvider<PasswordHashSetting>>,
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

    /// Fetch the user associated with a login by their OID.
    pub async fn get_user(&self, user_oid: identity_domain::user::UserOid) -> Option<User> {
        self.user_repo.find_by_oid(user_oid).await.ok().flatten()
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

        // Probe each supported credential type for this user.
        let mut credential_types = Vec::new();
        for ct in [
            CredentialType::Password,
            CredentialType::Otp,
            CredentialType::RecoveryCode,
        ] {
            let credentials = self
                .credential_repo
                .find_by_user_oid_and_type(user.oid, ct.clone())
                .await?;
            if !credentials.is_empty() {
                credential_types.push(ct);
            }
        }

        // Bind the resolved user onto the existing login record.
        let login = self
            .login_repo
            .bind_user(login_oid, user.oid.into(), LoginStatus::IDENTIFIER_VERIFIED)
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
    /// - Otherwise: creates a session with `acr = ACR_PASSWORD` and returns
    ///   [`ChallengeOutcome::Authenticated`].
    ///
    /// # OTP flow
    /// The login status MUST already be `mfa_required` (set by a prior
    /// password challenge). Creates a session with `acr = ACR_MFA` and an
    /// `acr_expires_at` of `now + ACR_EXPIRY`.
    pub async fn challenge(
        &self,
        login_oid: Uuid,
        credential_type: &str,
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
            "password" => {
                self.challenge_password(login, credential, hash_options.as_ref(), ctx)
                    .await
            }
            "otp" => self.challenge_otp(login, credential, ctx).await,
            _ => Err(
                AppError::from_code(AuthErrorCode::CredentialTypeUnsupported)
                    .with_param("credential_type", credential_type),
            ),
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

        // Check lock.
        if user.locked {
            if let Some(until) = user.locked_until {
                if Utc::now() < until {
                    return Err(AppError::from_code(AuthErrorCode::UserLocked));
                }
                if let Err(e) = self.user_repo.reset_failed_attempts(user.oid).await {
                    tracing::error!(error = %e, "failed to reset expired lock");
                }
            } else {
                return Err(AppError::from_code(AuthErrorCode::UserLocked));
            }
        }

        if !user.enabled {
            return Err(AppError::from_code(AuthErrorCode::UserLocked));
        }

        // Load the password credential.
        let credentials = self
            .credential_repo
            .find_by_user_oid_and_type(user.oid, CredentialType::Password)
            .await?;

        let password_cred = credentials
            .into_iter()
            .next()
            .ok_or_else(|| AppError::from_code(AuthErrorCode::CredentialTypeUnsupported))?;

        let stored_password: Password = match password_cred.data {
            CredentialData::Password(p) => p,
            _ => {
                return Err(AppError::from_code(
                    AuthErrorCode::CredentialTypeUnsupported,
                ));
            }
        };

        // Verify the password.
        let verify_result =
            self.password_hasher
                .verify(credential, &stored_password, hash_options)?;

        match verify_result {
            VerifyResult::Failure => {
                if let Err(e) = self
                    .login_repo
                    .increment_failed_attempts(
                        login.oid,
                        Some(&AuthErrorCode::InvalidCredential.code().to_string()),
                    )
                    .await
                {
                    tracing::error!(error = %e, "failed to increment login failed attempts");
                }

                let new_attempts = user.failed_attempts + 1;
                let lock_until = if new_attempts >= MAX_FAILED_ATTEMPTS {
                    Some(
                        Utc::now()
                            + chrono::Duration::from_std(LOCK_DURATION)
                                .unwrap_or_else(|_| chrono::Duration::seconds(900)),
                    )
                } else {
                    None
                };
                if let Err(e) = self
                    .user_repo
                    .increment_failed_attempts(user.oid, lock_until)
                    .await
                {
                    tracing::error!(error = %e, "failed to increment user failed attempts");
                }

                if new_attempts >= MAX_FAILED_ATTEMPTS {
                    return Err(AppError::from_code(AuthErrorCode::UserLocked));
                }
                Err(AppError::from_code(AuthErrorCode::InvalidCredential))
            }
            VerifyResult::Success | VerifyResult::NeedsRehash => {
                // Transparently rehash if needed.
                if verify_result == VerifyResult::NeedsRehash
                    && let Ok(new_password) = self.password_hasher.hash(credential, hash_options)
                    && let Err(e) = self
                        .credential_repo
                        .update_password_by_oid(password_cred.oid, &new_password)
                        .await
                {
                    tracing::error!(error = %e, "failed to rehash password");
                }

                // Reset failed attempts on the user.
                if let Err(e) = self.user_repo.reset_failed_attempts(user.oid).await {
                    tracing::error!(error = %e, "failed to reset user failed attempts");
                }

                // Check if the user has an OTP credential.
                let otp_credentials = self
                    .credential_repo
                    .find_by_user_oid_and_type(user.oid, CredentialType::Otp)
                    .await?;

                if otp_credentials.is_empty() {
                    // No MFA — create session immediately with password ACR.
                    let session = self
                        .create_session(user.oid.into(), ctx, ACR_PASSWORD, false)
                        .await?;

                    if let Err(e) = self
                        .login_repo
                        .update_status(
                            login.oid,
                            LoginStatus::AUTHENTICATED,
                            Some(session.oid),
                            Some(ACR_PASSWORD),
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
        // OTP challenge is only valid when the login is in `mfa_required` state.
        if login.status != LoginStatus::MFA_REQUIRED {
            return Err(AppError::from_code(AuthErrorCode::InvalidLoginState));
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

        // Load the OTP credential.
        let otp_credentials = self
            .credential_repo
            .find_by_user_oid_and_type(user.oid, CredentialType::Otp)
            .await?;

        let otp_cred = otp_credentials
            .into_iter()
            .find(|c| c.r#type == CredentialType::Otp)
            .ok_or_else(|| AppError::from_code(AuthErrorCode::CredentialTypeUnsupported))?;

        let otp_data: OtpCredentialData = match otp_cred.data {
            CredentialData::Otp(o) => o,
            _ => {
                return Err(AppError::from_code(
                    AuthErrorCode::CredentialTypeUnsupported,
                ));
            }
        };

        // Verify the TOTP code.
        let valid = self.totp_verifier.verify(&otp_data, code)?;

        if !valid {
            if let Err(e) = self
                .login_repo
                .increment_failed_attempts(
                    login.oid,
                    Some(&AuthErrorCode::InvalidOtp.code().to_string()),
                )
                .await
            {
                tracing::error!(error = %e, "failed to increment login failed attempts");
            }
            return Err(AppError::from_code(AuthErrorCode::InvalidOtp));
        }

        // Create session with MFA ACR + expiry.
        let session = self
            .create_session(user.oid.into(), ctx, ACR_MFA, true)
            .await?;

        if let Err(e) = self
            .login_repo
            .update_status(
                login.oid,
                LoginStatus::AUTHENTICATED,
                Some(session.oid),
                Some(ACR_MFA),
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

    /// Create a session for `user_oid` with the given ACR.
    ///
    /// When `with_acr_expiry` is `true` the `acr_expires_at` field is set to
    /// `now + ACR_EXPIRY`; otherwise it is `None`.
    async fn create_session(
        &self,
        user_oid: Uuid,
        ctx: SessionContext,
        acr: &str,
        with_acr_expiry: bool,
    ) -> Result<Session, AppError> {
        let expires_at = Utc::now()
            + chrono::Duration::from_std(SESSION_EXPIRY)
                .unwrap_or_else(|_| chrono::Duration::days(7));

        let acr_expires_at = if with_acr_expiry {
            Some(
                Utc::now()
                    + chrono::Duration::from_std(ACR_EXPIRY)
                        .unwrap_or_else(|_| chrono::Duration::seconds(3600)),
            )
        } else {
            None
        };

        Ok(self
            .session_repo
            .create(
                user_oid,
                ctx.device_name,
                ctx.device_type,
                ctx.os_name,
                ctx.os_version,
                ctx.browser_name,
                ctx.browser_version,
                ctx.user_agent,
                ctx.ip_address,
                Some(expires_at),
                Some(acr.to_owned()),
                acr_expires_at,
            )
            .await?)
    }
}
