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
        MAX_FAILED_ATTEMPTS, MAX_OTP_ATTEMPTS, SESSION_EXPIRY,
        model::{Login, Session},
        password::{HashOptions, PasswordHashSetting, PasswordHasher, VerifyResult},
        repository::{CreateSessionInput, LoginRepository, SessionRepository},
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
#[derive(Debug)]
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
    /// password challenge). Up to [`MAX_OTP_ATTEMPTS`] invalid codes are allowed
    /// per login flow; further attempts return [`AuthErrorCode::TooManyAttempts`]
    /// and invalidate the login. Creates a session with `acr = ACR_MFA` and an
    /// `acr_expires_at` of `now + ACR_EXPIRY` on success.
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
        // OTP challenge is only valid when the login is in `mfa_required` state.
        if login.status != LoginStatus::MFA_REQUIRED {
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

        let otp_data: OtpCredentialData = match otp_cred.data {
            CredentialData::Otp(o) => o,
            _ => {
                return Err(
                    AppError::from_code(AuthErrorCode::CredentialTypeUnsupported)
                        .with_param("credential_type", "otp"),
                );
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

            let new_attempts = login.failed_attempts + 1;
            if new_attempts >= MAX_OTP_ATTEMPTS {
                self.fail_login_for_too_many_otp_attempts(login.oid).await;
                return Err(AppError::from_code(AuthErrorCode::TooManyAttempts));
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

    async fn fail_login_for_too_many_otp_attempts(&self, login_oid: Uuid) {
        if let Err(e) = self
            .login_repo
            .update_status(login_oid, LoginStatus::FAILED, None, None)
            .await
        {
            tracing::error!(error = %e, "failed to update login status after too many OTP attempts");
        }
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
            })
            .await?)
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use async_trait::async_trait;
    use chrono::Utc;
    use identity_domain::{
        auth::{
            LoginStatus, MAX_OTP_ATTEMPTS,
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
        ) -> Result<bool, identity_domain::auth::totp::TotpError> {
            Ok(false)
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
        user: User,
    }

    #[async_trait]
    impl UserRepository for TestUserRepo {
        async fn find_by_identifier(&self, _identifier: &str) -> Result<User, UserRepositoryError> {
            Ok(self.user.clone())
        }

        async fn find_by_oid(&self, oid: UserOid) -> Result<Option<User>, UserRepositoryError> {
            Ok((self.user.oid == oid).then_some(self.user.clone()))
        }

        async fn increment_failed_attempts(
            &self,
            _user_oid: UserOid,
            _lock_until: Option<chrono::DateTime<chrono::Utc>>,
        ) -> Result<(), UserRepositoryError> {
            Ok(())
        }

        async fn reset_failed_attempts(
            &self,
            _user_oid: UserOid,
        ) -> Result<(), UserRepositoryError> {
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
                status: identity_domain::auth::SessionStatus::ACTIVE.to_string(),
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
            })
        }

        async fn touch_by_oid(&self, _oid: SessionOid) -> Result<(), SessionRepositoryError> {
            Ok(())
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
        update_status_calls: Vec<(Uuid, String)>,
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
            _status: &str,
        ) -> Result<Login, LoginRepositoryError> {
            Err(LoginRepositoryError::LoginNotFound)
        }

        async fn update_status(
            &self,
            login_oid: Uuid,
            status: &str,
            _session_oid: Option<SessionOid>,
            _acr: Option<&str>,
        ) -> Result<(), LoginRepositoryError> {
            let mut state = self.state.lock().unwrap();
            state
                .update_status_calls
                .push((login_oid, status.to_owned()));
            if let Some(login) = state.logins.iter_mut().find(|login| login.oid == login_oid) {
                login.status = status.to_owned();
            }
            Ok(())
        }

        async fn increment_failed_attempts(
            &self,
            login_oid: Uuid,
            _failure_reason: Option<&str>,
        ) -> Result<(), LoginRepositoryError> {
            let mut state = self.state.lock().unwrap();
            if let Some(login) = state.logins.iter_mut().find(|login| login.oid == login_oid) {
                login.failed_attempts += 1;
            }
            Ok(())
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
            status: LoginStatus::MFA_REQUIRED.to_string(),
            failed_attempts,
            created_at: Utc::now(),
            acr: None,
            requested_acr: None,
        }
    }

    fn otp_service(login_repo: Arc<TestLoginRepo>, user: User) -> LoginService {
        LoginService::new(
            Arc::new(TestUserRepo { user: user.clone() }),
            Arc::new(TestCredentialRepo {
                credentials: vec![UserCredential {
                    oid: UserCredentialOid(Uuid::new_v4()),
                    r#type: CredentialType::Otp,
                    data: CredentialData::Otp(OtpCredentialData {
                        secret: "secret".to_owned(),
                        digits: 6,
                        period: 30,
                        algorithm: identity_domain::user::OtpAlgorithm::Sha1,
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
        )
    }

    fn assert_error_code(error: AppError, expected: AuthErrorCode) {
        assert_eq!(error.code(), expected.code());
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
        let service = otp_service(Arc::clone(&login_repo), user);

        let error = service
            .challenge(
                login_oid,
                "otp",
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
        let service = otp_service(Arc::clone(&login_repo), user);

        let error = service
            .challenge(
                login_oid,
                "otp",
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
        let service = otp_service(login_repo.clone(), user);

        let error = service
            .challenge(
                login_oid,
                "otp",
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
}
