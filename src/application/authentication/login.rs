//! Login interaction orchestration and public authentication use cases.

use super::{
    passkey::PasskeyService,
    password_policy::{BreachedPasswordChecker, UnavailableBreachChecker},
};
use crate::{
    authentication::{password::PasswordHasher, totp::TotpVerifier},
    error::{AppError, codes::auth::AuthErrorCode},
    observability::{EventSink, NoopEventSink},
    setting::SettingsSource,
    user::{
        UserOid,
        model::{CredentialType, User},
        repository::UserCredentialRepository,
    },
};
use chrono::{DateTime, Duration, Utc};
use identity_domain::{
    auth::{
        ACR_AAL2, LOCK_DURATION, LoginStatus, MAX_FAILED_ATTEMPTS, SessionOid,
        model::{Login, Session},
        repository::{LoginRepository, SessionRepository},
    },
    user::{MfaMethod as UserMfaMethod, repository::UserRepository},
};
use std::sync::Arc;
use uuid::Uuid;
mod challenge;
mod otp;
mod passkey;
mod password;
mod password_change;
mod recovery_code;
mod session;

#[cfg(test)]
mod tests;

// ─── Input/Output Types ──────────────────────────────────────────────────────

/// Result of a password change that also revokes other sessions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PasswordChangeOutcome {
    pub password_changed: bool,
    pub revoked_other_sessions: u32,
    pub session_revocation_failures: u32,
}

/// Browser sessions and device context supplied by the login transport.
#[derive(Default)]
pub struct SessionContext {
    /// Only sessions presented by this browser may be reused after authentication.
    pub browser_session_oids: Vec<SessionOid>,
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
    pub preferred_credential_type: Option<CredentialType>,
}

/// The outcome of a challenge step.
#[derive(Debug)]
pub enum ChallengeOutcome {
    /// Password was verified and the user has no OTP credential — session
    /// created or renewed immediately with password-only ACR.
    Authenticated { login: Login, session: Box<Session> },
    /// The first factor is established; the client must supply an allowed
    /// second factor before authentication can complete.
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
    settings: Arc<dyn SettingsSource>,
    events: Arc<dyn EventSink>,
    passkeys: Option<Arc<PasskeyService>>,
    breach_checker: Arc<dyn BreachedPasswordChecker>,
}

impl LoginService {
    #[must_use]
    pub fn with_breach_checker(mut self, checker: Arc<dyn BreachedPasswordChecker>) -> Self {
        self.breach_checker = checker;
        self
    }
    #[must_use]
    pub fn new(
        user_repo: Arc<dyn UserRepository>,
        credential_repo: Arc<dyn UserCredentialRepository>,
        session_repo: Arc<dyn SessionRepository>,
        login_repo: Arc<dyn LoginRepository>,
        password_hasher: Arc<dyn PasswordHasher>,
        totp_verifier: Arc<dyn TotpVerifier>,
        settings: Arc<dyn SettingsSource>,
    ) -> Self {
        Self {
            user_repo,
            credential_repo,
            session_repo,
            login_repo,
            password_hasher,
            totp_verifier,
            settings,
            breach_checker: Arc::new(UnavailableBreachChecker),
            passkeys: None,
            events: Arc::new(NoopEventSink),
        }
    }

    /// Attach the key event and audit sink.
    #[must_use]
    pub fn with_events(mut self, events: Arc<dyn EventSink>) -> Self {
        self.events = events;
        self
    }

    #[must_use]
    pub fn with_passkeys(mut self, passkeys: Arc<PasskeyService>) -> Self {
        self.passkeys = Some(passkeys);
        self
    }

    pub async fn get(&self, login_oid: Uuid) -> Result<Login, AppError> {
        self.login_repo
            .find_by_oid(login_oid)
            .await?
            .ok_or_else(|| AppError::from_code(AuthErrorCode::InvalidLoginState))
    }

    /// Enter the credential phase using established authentication evidence.
    /// The chosen credential, transport and presentation do not determine it.
    #[tracing::instrument(skip_all, name = "authentication.prepare")]
    pub async fn prepare_challenge(&self, login_oid: Uuid) -> Result<Login, AppError> {
        let mut login = self.get(login_oid).await?;
        if login.status != LoginStatus::IDENTIFIER_VERIFIED
            || login.session_oid.is_none()
            || login.expires_at <= Utc::now()
        {
            return Ok(login);
        }
        let Some(user_oid) = login.user_oid else {
            return Ok(login);
        };
        let credentials = self.credential_types(user_oid.into()).await?;
        if login.requested_acr.as_deref() == Some(ACR_AAL2)
            || credentials
                .iter()
                .any(|kind| *kind != CredentialType::Password)
        {
            self.login_repo
                .update_status(login.oid, LoginStatus::MFA_REQUIRED, None, None)
                .await?;
            login.status = LoginStatus::MFA_REQUIRED;
        }
        Ok(login)
    }

    /// Return the credential types enrolled by the user. The interaction's
    /// phase determines which of these may be offered for a challenge.
    ///
    /// This is also used by the first-party login UI when an authorization
    /// interaction is already bound to an active session. In that case the UI
    /// can offer a fresh second-factor challenge without asking for the
    /// password again.
    pub async fn credential_types(
        &self,
        user_oid: UserOid,
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
        if let Some(passkeys) = &self.passkeys
            && !passkeys.list(user_oid).await?.is_empty()
        {
            credential_types.push(CredentialType::Passkey);
        }
        Ok(credential_types)
    }

    /// Fetch the user associated with a login by their OID.
    pub async fn get_user(&self, user_oid: UserOid) -> Result<User, AppError> {
        self.user_repo
            .find_by_oid(user_oid)
            .await?
            .ok_or_else(|| AppError::from_code(AuthErrorCode::UserNotFound))
    }

    /// Step 1: Verify the identifier (email or username) and bind the
    /// resolved user onto an existing login flow.
    #[tracing::instrument(skip_all, name = "authentication.identify")]
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
            preferred_credential_type: preferred_credential_type(
                &login,
                &credential_types,
                user.preferred_mfa_method,
            ),
            credential_types: challenge_credential_types(&login, &credential_types),
            login,
            user,
        })
    }
}

fn can_challenge_second_factor(login: &Login) -> bool {
    login.status == LoginStatus::MFA_REQUIRED
}

/// Methods allowed by the current authentication phase.
#[must_use]
pub fn challenge_credential_types(
    login: &Login,
    credentials: &[CredentialType],
) -> Vec<CredentialType> {
    credentials
        .iter()
        .copied()
        .filter(|kind| match login.status {
            LoginStatus::IDENTIFIER_VERIFIED => {
                matches!(kind, CredentialType::Password | CredentialType::Passkey)
            }
            LoginStatus::MFA_REQUIRED => *kind != CredentialType::Password,
            _ => false,
        })
        .collect()
}

fn failed_attempt_lock_until() -> DateTime<Utc> {
    Utc::now() + Duration::from_std(LOCK_DURATION).unwrap_or_else(|_| Duration::seconds(900))
}

/// The user's ordering preference selects a valid path; it never bypasses a factor.
#[must_use]
pub fn preferred_credential_type(
    login: &Login,
    credentials: &[CredentialType],
    preference: UserMfaMethod,
) -> Option<CredentialType> {
    use identity_domain::user::MfaMethod;
    let has = |kind| credentials.contains(&kind);
    if login.user_oid.is_none() || login.expires_at <= Utc::now() {
        return None;
    }
    if login.status == LoginStatus::MFA_REQUIRED {
        if login.session_oid.is_some()
            && preference == MfaMethod::Passkey
            && has(CredentialType::Passkey)
        {
            return Some(CredentialType::Passkey);
        }
        return has(CredentialType::Otp)
            .then_some(CredentialType::Otp)
            .or_else(|| has(CredentialType::Passkey).then_some(CredentialType::Passkey))
            .or_else(|| has(CredentialType::RecoveryCode).then_some(CredentialType::RecoveryCode));
    }
    if login.status != LoginStatus::IDENTIFIER_VERIFIED {
        return None;
    }
    if has(CredentialType::Passkey)
        && (preference == MfaMethod::Passkey || !has(CredentialType::Otp))
    {
        return Some(CredentialType::Passkey);
    }
    if has(CredentialType::Password) {
        return Some(CredentialType::Password);
    }
    has(CredentialType::Passkey).then_some(CredentialType::Passkey)
}

fn validate_passkey_login(login: &Login) -> Result<(), AppError> {
    if login.expires_at <= Utc::now() {
        return Err(AppError::from_code(AuthErrorCode::LoginExpired));
    }
    if !matches!(
        login.status,
        LoginStatus::IDENTIFIER_VERIFIED | LoginStatus::MFA_REQUIRED
    ) || login.user_oid.is_none()
    {
        return Err(AppError::from_code(AuthErrorCode::InvalidLoginState));
    }
    if login.failed_attempts >= MAX_FAILED_ATTEMPTS {
        return Err(AppError::from_code(AuthErrorCode::TooManyAttempts));
    }
    Ok(())
}
