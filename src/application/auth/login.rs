use std::sync::Arc;

use chrono::Utc;
use uuid::Uuid;

use crate::application::{
    error::{
        AppError,
        code::AppErrorCode,
        codes::{auth::AuthErrorCode, common::CommonErrorCode},
    },
    setting::runtime::SettingProvider,
};
use crate::domain::{
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
    Authenticated { login: Login, session: Session },
    /// Password was verified and the user has an OTP credential — the client
    /// MUST call challenge again with `credential_type = "otp"`.
    MfaRequired { login: Login },
}

// ─── LoginService ────────────────────────────────────────────────────────────

pub struct LoginService {
    pub user_repo: Arc<dyn UserRepository>,
    pub credential_repo: Arc<dyn UserCredentialRepository>,
    pub session_repo: Arc<dyn SessionRepository>,
    pub login_repo: Arc<dyn LoginRepository>,
    pub password_hasher: Arc<dyn PasswordHasher>,
    pub totp_verifier: Arc<dyn TotpVerifier>,
    pub hash_options: Arc<dyn SettingProvider<PasswordHashSetting>>,
}

impl LoginService {
    /// Step 1: Verify the identifier (email or username) and create a login
    /// record linked to the resolved user.
    pub async fn identify(&self, identifier: &str) -> Result<IdentifierResult, AppError> {
        let identifier = identifier.trim();
        if identifier.is_empty() {
            return Err(AppError::from_code(CommonErrorCode::InvalidRequest));
        }

        // Look up user by normalized email or username.
        let user = self.user_repo.find_by_identifier(identifier).await?;

        // Check if user is locked.
        if user.locked {
            if let Some(until) = user.locked_until {
                if Utc::now() < until {
                    return Err(AppError::from_code(AuthErrorCode::UserLocked));
                }
                // Lock has expired — reset it.
                self.user_repo.reset_failed_attempts(user.oid).await?;
            } else {
                return Err(AppError::from_code(AuthErrorCode::UserLocked));
            }
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

        // Create a login record linked to the resolved user.
        let login = self
            .login_repo
            .create(user.oid, LoginStatus::IDENTIFIER_VERIFIED, None)
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

        // Check login expiry for all credential types.
        let expiry_duration = chrono::Duration::from_std(LOGIN_EXPIRY)
            .unwrap_or_else(|_| chrono::Duration::seconds(300));
        if Utc::now().signed_duration_since(login.created_at) > expiry_duration {
            let _ = self
                .login_repo
                .update_status(login.oid, LoginStatus::FAILED, None, None)
                .await;
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
            .find_by_oid(login.user_oid)
            .await?
            .ok_or_else(|| AppError::from_code(AuthErrorCode::UserNotFound))?;

        // Check lock.
        if user.locked {
            if let Some(until) = user.locked_until {
                if Utc::now() < until {
                    return Err(AppError::from_code(AuthErrorCode::UserLocked));
                }
            }
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
                let _ = self
                    .login_repo
                    .increment_failed_attempts(
                        login.oid,
                        Some(&AuthErrorCode::InvalidCredential.code().to_string()),
                    )
                    .await;

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
                let _ = self
                    .user_repo
                    .increment_failed_attempts(user.oid, lock_until)
                    .await;

                if new_attempts >= MAX_FAILED_ATTEMPTS {
                    return Err(AppError::from_code(AuthErrorCode::UserLocked));
                }
                Err(AppError::from_code(AuthErrorCode::InvalidCredential))
            }
            VerifyResult::Success | VerifyResult::NeedsRehash => {
                // Transparently rehash if needed.
                if verify_result == VerifyResult::NeedsRehash {
                    if let Ok(new_password) = self.password_hasher.hash(credential, hash_options) {
                        let _ = self
                            .credential_repo
                            .update_password_by_oid(password_cred.oid, &new_password)
                            .await;
                    }
                }

                // Reset failed attempts on the user.
                let _ = self.user_repo.reset_failed_attempts(user.oid).await;

                // Check if the user has an OTP credential.
                let otp_credentials = self
                    .credential_repo
                    .find_by_user_oid_and_type(user.oid, CredentialType::Otp)
                    .await?;

                if otp_credentials.is_empty() {
                    // No MFA — create session immediately with password ACR.
                    let session = self
                        .create_session(user.oid, ctx, ACR_PASSWORD, false)
                        .await?;

                    let _ = self
                        .login_repo
                        .update_status(
                            login.oid,
                            LoginStatus::AUTHENTICATED,
                            Some(session.oid),
                            Some(ACR_PASSWORD),
                        )
                        .await;

                    Ok(ChallengeOutcome::Authenticated { login, session })
                } else {
                    // MFA required — do NOT create a session yet.
                    let _ = self
                        .login_repo
                        .update_status(login.oid, LoginStatus::MFA_REQUIRED, None, None)
                        .await;

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
            .find_by_oid(login.user_oid)
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
            let _ = self
                .login_repo
                .increment_failed_attempts(
                    login.oid,
                    Some(&AuthErrorCode::InvalidOtp.code().to_string()),
                )
                .await;
            return Err(AppError::from_code(AuthErrorCode::InvalidOtp));
        }

        // Create session with MFA ACR + expiry.
        let session = self.create_session(user.oid, ctx, ACR_MFA, true).await?;

        let _ = self
            .login_repo
            .update_status(
                login.oid,
                LoginStatus::AUTHENTICATED,
                Some(session.oid),
                Some(ACR_MFA),
            )
            .await;

        Ok(ChallengeOutcome::Authenticated { login, session })
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
