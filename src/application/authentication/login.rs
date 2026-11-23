//! Login interaction orchestration and public authentication use cases.

use super::{
    passkey::PasskeyService,
    password_policy::{BreachedPasswordChecker, UnavailableBreachChecker},
};
use crate::{
    authentication::{password::PasswordHasher, totp::TotpVerifier},
    error::{AppError, codes::auth::AuthErrorCode},
    observability::{EventSink, NoopEventSink},
    setting::{IdentifierEnumerationAllowedSetting, SettingsSource},
    user::{
        UserOid,
        model::{CredentialType, User},
        repository::UserCredentialRepository,
    },
};
use chrono::{DateTime, Duration, Utc};
use identity_domain::{
    audit::AuditFailureReason,
    auth::{
        AuthenticationContextClass, LOCK_DURATION, LoginStatus, MAX_FAILED_ATTEMPTS, SessionOid,
        model::{Login, Session},
        repository::{LoginRepository, SessionRepository},
    },
    user::{
        MfaMethod as UserMfaMethod,
        repository::{UserRepository, UserRepositoryError},
    },
};
use std::sync::Arc;
use uuid::Uuid;
mod challenge;
mod email;
mod enrollment;
mod otp;
mod passkey;
mod password;
mod password_change;
mod recovery_code;
mod session;

#[cfg(test)]
mod tests;

pub use email::{
    EmailCodeRequest, EmailCodeSent, LoginEmailDependencies, can_receive_email_code,
    email_sign_in_available,
};
pub use enrollment::{LoginMfaEnrollmentDependencies, LoginPasskeyEnrollment, LoginTotpEnrollment};

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
    /// The matched account. `None` while the interaction conceals whether an
    /// account exists (see [`Login::concealed_identifier`]): then nothing of
    /// the account may be shown before the password succeeds.
    pub user: Option<User>,
    pub credential_types: Vec<CredentialType>,
    pub preferred_credential_type: Option<CredentialType>,
}

/// The outcome of a challenge step.
#[derive(Debug)]
pub enum ChallengeOutcome {
    /// The requested class is established — session created or renewed.
    Authenticated { login: Login, session: Box<Session> },
    /// The first factor is established; the client must supply an allowed
    /// second factor before authentication can complete.
    MfaRequired { login: Login },
    /// The established factors fall short of the requested class and the
    /// user has no credential that meets it; authentication completes only by
    /// enrolling one (see [`enrollment_method`]).
    MfaEnrollmentRequired { login: Login },
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
    mfa_enrollment: Option<LoginMfaEnrollmentDependencies>,
    email: Option<LoginEmailDependencies>,
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
            mfa_enrollment: None,
            email: None,
            events: Arc::new(NoopEventSink),
        }
    }

    /// Attach the key event and audit sink.
    #[must_use]
    pub fn with_events(mut self, events: Arc<dyn EventSink>) -> Self {
        self.events = events;
        self
    }

    /// Allow an interaction to enroll a credential its requested class needs.
    #[must_use]
    pub fn with_mfa_enrollment(mut self, dependencies: LoginMfaEnrollmentDependencies) -> Self {
        self.mfa_enrollment = Some(dependencies);
        self
    }

    /// Offer email sign-in when the instance turns it on.
    #[must_use]
    pub fn with_email(mut self, dependencies: LoginEmailDependencies) -> Self {
        self.email = Some(dependencies);
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
        if login.expires_at <= Utc::now() {
            return Ok(login);
        }
        let Some(user_oid) = login.user_oid else {
            return Ok(login);
        };
        let established_by_session =
            login.status == LoginStatus::IDENTIFIER_VERIFIED && login.session_oid.is_some();
        // An enrollment-phase login whose user gained a second factor
        // elsewhere (or whose enrollment was confirmed without completing the
        // session) is challenged with that factor instead.
        let awaiting_enrollment = login.status == LoginStatus::MFA_ENROLLMENT_REQUIRED;
        if !established_by_session && !awaiting_enrollment {
            return Ok(login);
        }
        let credentials = self.credential_types(user_oid.into()).await?;
        let has_second_factor = if awaiting_enrollment {
            // A `phr` enrollment is left only by registering a passkey in
            // this interaction or by asserting an existing one.
            !requires_phishing_resistance(&login)
                && credentials
                    .iter()
                    .any(|kind| matches!(kind, CredentialType::Otp | CredentialType::Passkey))
        } else {
            // An existing session establishes the first factor. Without any
            // second factor, a multi-factor request asks for the password so
            // a missing factor can be enrolled after it.
            credentials.iter().any(|kind| kind.is_second_factor())
        };
        if has_second_factor {
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
        if self.email_sign_in_available()
            && self
                .user_repo
                .find_by_oid(user_oid)
                .await?
                .is_some_and(|user| can_receive_email_code(&user))
        {
            credential_types.push(CredentialType::EmailOtp);
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

        if !self
            .settings
            .snapshot()
            .get::<IdentifierEnumerationAllowedSetting>()
        {
            return self.identify_concealed(login_oid, identifier).await;
        }

        // Look up user by normalized email or username.
        let user = match self.user_repo.find_by_identifier(identifier).await {
            Ok(user) => user,
            Err(UserRepositoryError::UserNotFound) => {
                self.login_repo
                    .record_identification_failure(
                        login_oid,
                        None,
                        AuditFailureReason::UnknownAccount,
                    )
                    .await?;
                return Err(AppError::from_code(AuthErrorCode::UserNotFound));
            }
            Err(error) => return Err(error.into()),
        };

        // Check if user is locked.
        if user.locked {
            let still_locked = user.locked_until.is_none_or(|until| Utc::now() < until);
            if still_locked {
                self.login_repo
                    .record_identification_failure(
                        login_oid,
                        Some(user.oid.into()),
                        AuditFailureReason::AccountLocked,
                    )
                    .await?;
                return Err(AppError::from_code(AuthErrorCode::UserLocked));
            }
            self.user_repo.reset_failed_attempts(user.oid).await?;
        }

        if !user.enabled {
            self.login_repo
                .record_identification_failure(
                    login_oid,
                    Some(user.oid.into()),
                    AuditFailureReason::AccountDisabled,
                )
                .await?;
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
            user: Some(user),
        })
    }

    /// The identifier step when accounts may not be enumerated: every
    /// identifier continues to the password, whether or not it matched an
    /// account that can sign in. Rejections are still audited here; the
    /// account state is disclosed only after a correct password.
    async fn identify_concealed(
        &self,
        login_oid: Uuid,
        identifier: &str,
    ) -> Result<IdentifierResult, AppError> {
        let user = match self.user_repo.find_by_identifier(identifier).await {
            Ok(user) => Some(user),
            Err(UserRepositoryError::UserNotFound) => None,
            Err(error) => return Err(error.into()),
        };
        let rejection = match &user {
            None => Some(AuditFailureReason::UnknownAccount),
            Some(user) if !user.enabled => Some(AuditFailureReason::AccountDisabled),
            Some(user)
                if user.locked && user.locked_until.is_none_or(|until| Utc::now() < until) =>
            {
                Some(AuditFailureReason::AccountLocked)
            }
            Some(_) => None,
        };
        let user_oid = user.as_ref().map(|user| Uuid::from(user.oid));
        if let Some(reason) = rejection {
            self.login_repo
                .record_identification_failure(login_oid, user_oid, reason)
                .await?;
        }
        let login = self
            .login_repo
            .bind_concealed_identifier(login_oid, identifier, user_oid)
            .await?;
        Ok(IdentifierResult {
            preferred_credential_type: Some(CredentialType::Password),
            credential_types: self.concealed_credential_types(),
            login,
            user: None,
        })
    }
}

impl LoginService {
    /// The methods offered while an interaction conceals whether an account
    /// exists: the same for every identifier, since offering the account's
    /// own methods would reveal it.
    #[must_use]
    pub fn concealed_credential_types(&self) -> Vec<CredentialType> {
        let mut types = vec![CredentialType::Password];
        if self.email_sign_in_available() {
            types.push(CredentialType::EmailOtp);
        }
        types
    }
}

/// Whether the login requires a multi-factor class.
fn requires_second_factor(login: &Login) -> bool {
    login
        .required_acr()
        .is_some_and(AuthenticationContextClass::is_multi_factor)
}

/// Whether only a passkey can complete the login. A one-time or recovery code
/// still verifies a second factor, after which the user registers a passkey
/// on this device and authenticates with it.
fn requires_phishing_resistance(login: &Login) -> bool {
    login.required_acr() == Some(AuthenticationContextClass::PhishingResistant)
}

/// The credential an enrollment-phase login asks the user to add.
#[must_use]
pub fn enrollment_method(login: &Login) -> CredentialType {
    if requires_phishing_resistance(login) {
        CredentialType::Passkey
    } else {
        CredentialType::Otp
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
            LoginStatus::IDENTIFIER_VERIFIED => matches!(
                kind,
                CredentialType::Password | CredentialType::Passkey | CredentialType::EmailOtp
            ),
            LoginStatus::MFA_REQUIRED => kind.is_second_factor(),
            _ => false,
        })
        .collect()
}

/// Combine the authentication methods already satisfied on `login` with
/// `additional`, preserving order without duplicates. When completing a
/// second-factor flow whose first factor was not recorded on `login`, fall
/// back to `pwd`.
fn combine_amr(login: &Login, additional: &[&str], expect_first_factor: bool) -> Vec<String> {
    let mut amr = if login.amr.is_empty() && expect_first_factor {
        vec![identity_domain::auth::AMR_PASSWORD.to_owned()]
    } else {
        login.amr.clone()
    };
    for method in additional {
        if !amr.iter().any(|existing| existing == method) {
            amr.push((*method).to_owned());
        }
    }
    amr
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
    // A request that prefers `phr` is offered an enrolled passkey first,
    // whatever it requires and whatever the user's own preference.
    if login.preferred_acr() == Some(AuthenticationContextClass::PhishingResistant)
        && has(CredentialType::Passkey)
        && matches!(
            login.status,
            LoginStatus::IDENTIFIER_VERIFIED | LoginStatus::MFA_REQUIRED
        )
    {
        return Some(CredentialType::Passkey);
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
    has(CredentialType::Passkey)
        .then_some(CredentialType::Passkey)
        .or_else(|| has(CredentialType::EmailOtp).then_some(CredentialType::EmailOtp))
}

fn validate_passkey_login(login: &Login) -> Result<(), AppError> {
    if login.expires_at <= Utc::now() {
        return Err(AppError::from_code(AuthErrorCode::LoginExpired));
    }
    // Passkey options would list the account's credentials.
    if login.concealed_identifier().is_some() {
        return Err(AppError::from_code(AuthErrorCode::InvalidLoginState));
    }
    // A `phr` enrollment may still be completed with an existing passkey.
    let enrolling_passkey =
        login.status == LoginStatus::MFA_ENROLLMENT_REQUIRED && requires_phishing_resistance(login);
    if !(enrolling_passkey
        || matches!(
            login.status,
            LoginStatus::IDENTIFIER_VERIFIED | LoginStatus::MFA_REQUIRED
        ))
        || login.user_oid.is_none()
    {
        return Err(AppError::from_code(AuthErrorCode::InvalidLoginState));
    }
    if login.failed_attempts >= MAX_FAILED_ATTEMPTS {
        return Err(AppError::from_code(AuthErrorCode::TooManyAttempts));
    }
    Ok(())
}
