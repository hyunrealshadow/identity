//! Self-registration: someone without an account creates one from the
//! identifier step of a login.
//!
//! The email address comes first. A single-use link that belongs to the login
//! is emailed to it, and only someone who follows the link chooses a username
//! and password; the account is created with the address already verified.
//! The answer to the first step is the same whether or not the address has
//! an account: an address that already has one receives a notice instead of
//! a link, so the page never reveals which addresses are registered.
//!
//! Creating the account binds it to the login at its first factor, so the
//! person signs in with the new password and the login continues as any
//! other.
//!
//! Sending follows email sign-in: the resend interval and send limit live on
//! the login's outbound challenge.

use async_trait::async_trait;
use chrono::{DateTime, Duration, Utc};
use identity_domain::{
    auth::{
        EMAIL_CODE_RESEND_INTERVAL, LOGIN_EMAIL_DELIVERY, LoginStatus, REGISTRATION_LINK_TTL,
        challenge::{
            AuthenticationChallenge, ChallengeBinding, ChallengeMethod, ChallengePurpose,
            DeliveryChallengeAdmission, DeliveryChallengeContext, DeliveryChallengeRequest,
            DeliveryChallengeState,
        },
        model::Login,
    },
    user::repository::UserIdentifierUpdate,
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use tracing::{Instrument, warn};
use uuid::Uuid;

use super::{LoginEmailDependencies, LoginService};
use crate::{
    authentication::{
        account::{validate_email, validate_username},
        password::run_password_hashing,
        password_policy::{validate_breached_password, validate_password},
    },
    email::{EmailRecipient, EmailTemplateKind, LinkToken, link_matches, send_templated_email},
    error::{
        AppError,
        codes::{account::AccountErrorCode, auth::AuthErrorCode},
    },
    observability::{BusinessEvent, EventValue},
    setting::{
        EmailDeliverySettings, EmailTemplatesSetting, PasswordHashSetting,
        RegistrationEnabledSetting, SettingsSnapshot,
    },
    user::Password,
};

/// The account a registration link creates, ready to store.
///
/// `Debug` is not derived: the password hash must never be logged.
pub struct NewAccount {
    pub login_oid: Uuid,
    /// The registration challenge whose link was followed; it is used up.
    pub challenge_oid: Uuid,
    pub username: String,
    pub username_normalized: String,
    pub email: String,
    pub email_normalized: String,
    pub password: Password,
}

/// Outcome of creating an account from a registration link.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RegistrationOutcome {
    Registered,
    /// The link was used, replaced, or expired, or the login moved on.
    LinkInvalid,
    UsernameExists,
    EmailExists,
}

#[async_trait]
pub trait RegistrationRepository: Send + Sync {
    /// Whether an account uses the normalized email address.
    async fn email_registered(&self, email_normalized: &str) -> Result<bool, AppError>;

    /// The login's current registration challenge, if it has not expired.
    async fn latest(&self, login_oid: Uuid) -> Result<Option<AuthenticationChallenge>, AppError>;

    /// Use the challenge up, create the account with its address verified
    /// and its password, bind it to the login at its first factor, and audit
    /// the registration, all in one transaction.
    async fn register(&self, account: NewAccount) -> Result<RegistrationOutcome, AppError>;
}

/// A request to email a registration link for one login.
pub struct RegistrationRequest {
    pub login_oid: Uuid,
    pub email: String,
    /// Locales the browser asked for, most preferred first.
    pub locales: Vec<String>,
    /// The application being signed in to, for the message.
    pub application_name: Option<String>,
    /// The registration page up to its token: the token is appended as is.
    pub link_prefix: String,
}

/// The outcome of a send, identical whether or not the address has an
/// account.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegistrationSent {
    pub expires_at: DateTime<Utc>,
    pub resend_available_at: DateTime<Utc>,
}

/// The address a registration link verifies, as shown on its page.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegistrationLink {
    pub email: String,
}

/// Verifier state kept inside [`DeliveryChallengeState::verifier`].
/// Never sent to a browser or written to logs.
#[derive(Serialize, Deserialize)]
struct RegistrationVerifier {
    /// SHA-256 of the link token, base64url. Absent when the address already
    /// had an account, so no link was sent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    link: Option<String>,
    email: String,
    email_normalized: String,
}

fn interval() -> Duration {
    Duration::from_std(EMAIL_CODE_RESEND_INTERVAL).unwrap_or_else(|_| Duration::seconds(60))
}

fn ttl() -> Duration {
    Duration::from_std(REGISTRATION_LINK_TTL).unwrap_or_else(|_| Duration::minutes(15))
}

/// Whether self-registration is turned on and email can be sent.
#[must_use]
pub fn registration_available(snapshot: &SettingsSnapshot) -> bool {
    snapshot.get::<RegistrationEnabledSetting>()
        && snapshot.section::<EmailDeliverySettings>().is_configured()
}

/// Whether a login may create an account: it is still at its identifier
/// step and has no account or session bound.
fn login_accepts_registration(login: &Login) -> bool {
    login.status == LoginStatus::CREATED && login.user_oid.is_none() && login.session_oid.is_none()
}

fn unavailable() -> AppError {
    AppError::from_code(AuthErrorCode::RegistrationUnavailable)
}

fn link_invalid() -> AppError {
    AppError::from_code(AuthErrorCode::RegistrationLinkInvalid)
}

impl LoginService {
    fn registration_dependencies(
        &self,
    ) -> Option<(
        LoginEmailDependencies,
        std::sync::Arc<dyn RegistrationRepository>,
    )> {
        let repository = self.registration.clone()?;
        self.email
            .clone()
            .filter(|_| registration_available(&self.settings.snapshot()))
            .map(|email| (email, repository))
    }

    /// Whether the identifier step of `login` offers creating an account.
    #[must_use]
    pub fn registration_offered(&self, login: &Login) -> bool {
        login_accepts_registration(login)
            && login.expires_at > Utc::now()
            && self.registration_dependencies().is_some()
    }

    /// When another registration email may be requested for `login`, if one
    /// was sent.
    pub async fn registration_resend_available_at(
        &self,
        login: &Login,
    ) -> Result<Option<DateTime<Utc>>, AppError> {
        if !login_accepts_registration(login) {
            return Ok(None);
        }
        if self.registration.is_none() {
            return Ok(None);
        }
        let Some(dependencies) = self.email.as_ref() else {
            return Ok(None);
        };
        let status = dependencies
            .challenges
            .delivery_status(
                ChallengeBinding::Login(login.oid),
                ChallengeMethod::EmailOtp,
                ChallengePurpose::Registration,
            )
            .await?;
        Ok(status.map(|status| status.sent_at + interval()))
    }

    /// Email a registration link, or a notice when the address already has
    /// an account. The response does not depend on which.
    #[tracing::instrument(skip_all, name = "authentication.registration.send")]
    pub async fn send_registration(
        &self,
        request: RegistrationRequest,
    ) -> Result<RegistrationSent, AppError> {
        let result = self.send_registration_inner(request).await;
        let mut event = BusinessEvent::business("authentication.registration.sent");
        event = match &result {
            Ok(_) => event.outcome("accepted"),
            Err(error) => event
                .outcome("rejected")
                .attribute("error_code", EventValue::Integer(i64::from(error.code()))),
        };
        self.events.emit(event);
        result
    }

    async fn send_registration_inner(
        &self,
        request: RegistrationRequest,
    ) -> Result<RegistrationSent, AppError> {
        let login = self.get(request.login_oid).await?;
        let now = Utc::now();
        if login.expires_at <= now {
            return Err(AppError::from_code(AuthErrorCode::LoginExpired));
        }
        if !login_accepts_registration(&login) {
            return Err(AppError::from_code(AuthErrorCode::InvalidLoginState));
        }
        let Some((dependencies, repository)) = self.registration_dependencies() else {
            return Err(unavailable());
        };
        let UserIdentifierUpdate::Email { value, normalized } = validate_email(&request.email)?
        else {
            return Err(AppError::from_code(AccountErrorCode::EmailInvalid).with_field("email"));
        };
        let account_exists = repository.email_registered(&normalized).await?;
        let link = (!account_exists).then(LinkToken::generate);
        let (token, digest) = link.map(|link| (link.token, link.digest)).unzip();
        let verifier = serde_json::to_value(RegistrationVerifier {
            link: digest,
            email: value.clone(),
            email_normalized: normalized,
        })
        .map_err(AppError::internal)?;

        let expires_at = now + ttl();
        let sent = match dependencies
            .challenges
            .admit_delivery(
                DeliveryChallengeContext {
                    user_oid: None,
                    binding: ChallengeBinding::Login(login.oid),
                    method: ChallengeMethod::EmailOtp,
                    purpose: ChallengePurpose::Registration,
                },
                DeliveryChallengeRequest {
                    now,
                    policy: LOGIN_EMAIL_DELIVERY,
                    code_expires_at: expires_at,
                    required_login_status: Some(LoginStatus::CREATED),
                    verifier: Some(verifier),
                },
            )
            .await?
        {
            DeliveryChallengeAdmission::Admitted {
                resend_available_at,
                ..
            } => RegistrationSent {
                expires_at,
                resend_available_at,
            },
            DeliveryChallengeAdmission::TooSoon { available_at } => {
                let seconds = (available_at - now).num_seconds().max(1);
                return Err(
                    AppError::from_code(AuthErrorCode::RegistrationResendTooSoon)
                        .with_param("seconds", seconds.to_string()),
                );
            }
            DeliveryChallengeAdmission::LimitReached => {
                return Err(AppError::from_code(AuthErrorCode::TooManyAttempts));
            }
            DeliveryChallengeAdmission::InvalidState => {
                return Err(AppError::from_code(AuthErrorCode::InvalidLoginState));
            }
        };

        let snapshot = self.settings.snapshot();
        let delivery = DeliveryJob {
            dependencies,
            delivery: snapshot.section::<EmailDeliverySettings>(),
            templates: snapshot.get::<EmailTemplatesSetting>(),
            email: value,
            locales: request.locales,
            application_name: request.application_name,
            link: token.map(|token| format!("{}{}", request.link_prefix, token)),
        };
        // The response must not wait on which message is sent, or whether.
        tokio::spawn(
            async move {
                if let Err(error) = delivery.run().await {
                    warn!(error = %error, "failed to deliver registration email");
                }
            }
            .in_current_span(),
        );
        Ok(sent)
    }

    /// The address a registration link of `login` verifies, without using
    /// the link. Lets the page refuse a stale link before anything is typed.
    pub async fn check_registration_link(
        &self,
        login_oid: Uuid,
        token: &str,
    ) -> Result<RegistrationLink, AppError> {
        let (_, _, verifier) = self.matching_registration(login_oid, token).await?;
        Ok(RegistrationLink {
            email: verifier.email,
        })
    }

    /// Create the account of a registration link and bind it to `login`.
    /// The password follows the same policy as any other new password. The
    /// link is used up only when the account is created.
    #[tracing::instrument(skip_all, name = "authentication.registration.complete")]
    pub async fn complete_registration(
        &self,
        login_oid: Uuid,
        token: &str,
        username: &str,
        password: &str,
    ) -> Result<(), AppError> {
        let result = self
            .complete_registration_inner(login_oid, token, username, password)
            .await;
        let mut event = BusinessEvent::audit("authentication.registration.completed");
        event = match &result {
            Ok(()) => event.outcome("success"),
            Err(error) => event
                .outcome("rejected")
                .attribute("error_code", EventValue::Integer(i64::from(error.code()))),
        };
        self.events.emit(event);
        result
    }

    async fn complete_registration_inner(
        &self,
        login_oid: Uuid,
        token: &str,
        username: &str,
        password: &str,
    ) -> Result<(), AppError> {
        let (repository, challenge, verifier) =
            self.matching_registration(login_oid, token).await?;
        let UserIdentifierUpdate::Username {
            value: username,
            normalized: username_normalized,
        } = validate_username(username)?
        else {
            return Err(
                AppError::from_code(AccountErrorCode::UsernameInvalid).with_field("username")
            );
        };
        validate_password(password, &[&username, &verifier.email], "newPassword")?;
        let snapshot = self.settings.snapshot();
        validate_breached_password(
            self.breach_checker.as_ref(),
            &snapshot,
            password,
            "newPassword",
        )
        .await?;
        let options = snapshot.get::<PasswordHashSetting>();
        let hasher = std::sync::Arc::clone(&self.password_hasher);
        let plain = password.to_owned();
        let password = run_password_hashing(move || hasher.hash(&plain, &options)).await?;
        match repository
            .register(NewAccount {
                login_oid,
                challenge_oid: challenge.id,
                username,
                username_normalized,
                email: verifier.email,
                email_normalized: verifier.email_normalized,
                password,
            })
            .await?
        {
            RegistrationOutcome::Registered => Ok(()),
            RegistrationOutcome::LinkInvalid => Err(link_invalid()),
            RegistrationOutcome::UsernameExists => Err(AppError::from_code(
                AccountErrorCode::ValidationFailed,
            )
            .with_field_error(
                "username",
                AppError::from_code(AccountErrorCode::UsernameExists),
            )),
            // The address got an account after the link was sent.
            RegistrationOutcome::EmailExists => Err(link_invalid()),
        }
    }

    /// The repository, challenge and verifier of a link that is still valid.
    async fn matching_registration(
        &self,
        login_oid: Uuid,
        token: &str,
    ) -> Result<
        (
            std::sync::Arc<dyn RegistrationRepository>,
            AuthenticationChallenge,
            RegistrationVerifier,
        ),
        AppError,
    > {
        let login = self.get(login_oid).await?;
        if login.expires_at <= Utc::now() {
            return Err(AppError::from_code(AuthErrorCode::LoginExpired));
        }
        if !login_accepts_registration(&login) {
            return Err(link_invalid());
        }
        let Some((_, repository)) = self.registration_dependencies() else {
            return Err(unavailable());
        };
        let Some(challenge) = repository.latest(login.oid).await? else {
            return Err(link_invalid());
        };
        let Some(verifier) = matching_verifier(&challenge, token.trim()) else {
            return Err(link_invalid());
        };
        Ok((repository, challenge, verifier))
    }
}

/// The challenge's verifier when `token` is its link token and the link is
/// still valid.
fn matching_verifier(
    challenge: &AuthenticationChallenge,
    token: &str,
) -> Option<RegistrationVerifier> {
    let now = Utc::now();
    if challenge.expires_at <= now || token.is_empty() {
        return None;
    }
    let state = serde_json::from_value::<DeliveryChallengeState>(challenge.state.clone()).ok()?;
    if state.code_expires_at <= now {
        return None;
    }
    let verifier = serde_json::from_value::<RegistrationVerifier>(state.verifier?).ok()?;
    let expected = verifier.link.as_deref()?;
    link_matches(token, expected).then_some(verifier)
}

/// Composes and sends one registration email.
struct DeliveryJob {
    dependencies: LoginEmailDependencies,
    delivery: EmailDeliverySettings,
    templates: crate::email::EmailTemplates,
    email: String,
    locales: Vec<String>,
    application_name: Option<String>,
    /// `None` when the address already has an account.
    link: Option<String>,
}

impl DeliveryJob {
    async fn run(self) -> Result<(), AppError> {
        let locales: Vec<&str> = self.locales.iter().map(String::as_str).collect();
        send_templated_email(
            self.dependencies.sender.as_ref(),
            self.dependencies.renderer.as_ref(),
            &self.delivery,
            &self.templates,
            EmailTemplateKind::Registration,
            EmailRecipient {
                address: &self.email,
                name: None,
                locales: &locales,
            },
            |locale| {
                json!({
                    "link": self.link,
                    "email": self.email,
                    "account_exists": self.link.is_none(),
                    "expires_in_minutes": ttl().num_minutes(),
                    "application": self.application_name.as_ref().map(|name| json!({ "name": name })),
                    "locale": locale,
                })
            },
        )
        .await
        .map_err(|error| {
            warn!(
                reason = error.reason(),
                "registration email was not delivered"
            );
            AppError::internal(error)
        })
    }
}
