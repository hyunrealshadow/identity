//! Password reset: someone who forgot their password asks, from the password
//! step of a login, for a single-use link sent to the account's verified
//! email address, and sets a new password with it.
//!
//! The link belongs to that login. Using it replaces the password, ends every
//! session of the account with its grants, and closes the account's other
//! pending logins; the login it came from stays at its first factor so the
//! account signs in with the new password, and any second factor it has
//! enrolled is still required.
//!
//! Sending follows email sign-in: the resend interval, send limit and
//! verifier state live on the login's outbound challenge, so the answer is
//! the same whether or not the identifier matched an account while the login
//! conceals it.

use chrono::{DateTime, Duration, Utc};
use identity_domain::{
    auth::{
        EMAIL_CODE_RESEND_INTERVAL, LOGIN_EMAIL_DELIVERY, LoginStatus, PASSWORD_RESET_TTL,
        challenge::{
            ChallengeBinding, ChallengeContext, ChallengeMethod, ChallengePurpose,
            DeliveryChallengeAdmission, DeliveryChallengeContext, DeliveryChallengeRequest,
            DeliveryChallengeState,
        },
        model::Login,
    },
    user::User,
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use tracing::warn;
use uuid::Uuid;

use super::{LoginEmailDependencies, LoginService};
use crate::{
    email::{EmailRecipient, EmailTemplateKind, LinkToken, link_matches, render_templated_email},
    error::{AppError, codes::auth},
    observability::{BusinessEvent, EventValue},
    setting::{
        EmailDeliverySettings, EmailTemplatesSetting, PasswordResetEnabledSetting, SettingsSnapshot,
    },
    user::{CredentialType, UserOid, repository::PasswordReplacementKind},
};

/// A request to email a password reset link for one login.
pub struct PasswordResetRequest {
    pub login_oid: Uuid,
    /// Locales the browser asked for, most preferred first. The account's
    /// own locale preference comes before them.
    pub locales: Vec<String>,
    /// The reset page up to its token: the token is appended as is.
    pub link_prefix: String,
}

/// The outcome of a send, identical whether or not an account matched.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PasswordResetSent {
    pub expires_at: DateTime<Utc>,
    pub resend_available_at: DateTime<Utc>,
}

/// Verifier state kept inside [`DeliveryChallengeState::verifier`].
/// Never sent to a browser or written to logs.
#[derive(Serialize, Deserialize)]
struct PasswordResetVerifier {
    /// SHA-256 of the link token, base64url.
    link: String,
}

fn interval() -> Duration {
    Duration::from_std(EMAIL_CODE_RESEND_INTERVAL).unwrap_or_else(|_| Duration::seconds(60))
}

fn ttl() -> Duration {
    Duration::from_std(PASSWORD_RESET_TTL).unwrap_or_else(|_| Duration::minutes(15))
}

fn challenge_context(user_oid: Uuid, login_oid: Uuid) -> ChallengeContext {
    ChallengeContext {
        user_oid,
        binding: ChallengeBinding::Login(login_oid),
        method: ChallengeMethod::EmailOtp,
        purpose: ChallengePurpose::PasswordReset,
    }
}

/// Whether password reset is turned on and email can be sent.
#[must_use]
pub fn password_reset_available(snapshot: &SettingsSnapshot) -> bool {
    snapshot.get::<PasswordResetEnabledSetting>()
        && snapshot.section::<EmailDeliverySettings>().is_configured()
}

/// Whether an account may receive a password reset email. A lockout from
/// failed attempts does not prevent it: the reset ends that lockout.
#[must_use]
pub fn can_receive_password_reset(user: &User) -> bool {
    user.enabled
        && user.email_verified
        && !user.email.trim().is_empty()
        && !user.is_permanently_locked()
}

/// Whether a login may ask for a reset: it waits for its first factor and
/// did not start from an existing session, which a reset would end.
fn login_accepts_reset(login: &Login) -> bool {
    login.status == LoginStatus::IDENTIFIER_VERIFIED && login.session_oid.is_none()
}

impl LoginService {
    fn password_reset_dependencies(&self) -> Option<LoginEmailDependencies> {
        self.email
            .clone()
            .filter(|_| password_reset_available(&self.settings.snapshot()))
    }

    /// Whether the password step of `login` offers a reset. While the login
    /// conceals the account it is offered for every identifier.
    pub async fn password_reset_offered(&self, login: &Login) -> Result<bool, AppError> {
        if !login_accepts_reset(login) || self.password_reset_dependencies().is_none() {
            return Ok(false);
        }
        if login.concealed_identifier().is_some() {
            return Ok(true);
        }
        match login.user_oid {
            Some(user_oid) => self.account_accepts_reset(user_oid.into()).await,
            None => Ok(false),
        }
    }

    async fn account_accepts_reset(&self, user_oid: UserOid) -> Result<bool, AppError> {
        let Some(user) = self.user_repo.find_by_oid(user_oid).await? else {
            return Ok(false);
        };
        if !can_receive_password_reset(&user) {
            return Ok(false);
        }
        Ok(!self
            .credential_repo
            .find_by_user_oid_and_type(user_oid, CredentialType::Password)
            .await?
            .is_empty())
    }

    /// When another reset email may be requested for `login`, if one was sent.
    pub async fn password_reset_resend_available_at(
        &self,
        login: &Login,
    ) -> Result<Option<DateTime<Utc>>, AppError> {
        if !login_accepts_reset(login) {
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
                ChallengePurpose::PasswordReset,
            )
            .await?;
        Ok(status.map(|status| status.sent_at + interval()))
    }

    /// Email a password reset link for a login waiting for its first factor.
    #[tracing::instrument(skip_all, name = "authentication.password_reset.send")]
    pub async fn send_password_reset(
        &self,
        request: PasswordResetRequest,
    ) -> Result<PasswordResetSent, AppError> {
        let result = self.send_password_reset_inner(request).await;
        let mut event = BusinessEvent::business("authentication.password_reset.sent");
        event = match &result {
            Ok(_) => event.outcome("accepted"),
            Err(error) => event
                .outcome("rejected")
                .attribute("error_code", EventValue::Integer(i64::from(error.code()))),
        };
        self.events.emit(event);
        result
    }

    async fn send_password_reset_inner(
        &self,
        request: PasswordResetRequest,
    ) -> Result<PasswordResetSent, AppError> {
        let login = self.get(request.login_oid).await?;
        let now = Utc::now();
        if login.expires_at <= now {
            return Err(auth::error::LoginExpired.into());
        }
        if !login_accepts_reset(&login) {
            return Err(auth::error::InvalidLoginState.into());
        }
        let Some(dependencies) = self.password_reset_dependencies() else {
            return Err(unavailable());
        };
        let concealed = login.concealed_identifier().is_some();
        let recipient = match login.user_oid {
            Some(user_oid) if self.account_accepts_reset(user_oid.into()).await? => {
                self.user_repo.find_by_oid(user_oid.into()).await?
            }
            _ => None,
        };
        if recipient.is_none() && !concealed {
            return Err(unavailable());
        }

        let (token, verifier) = if recipient.is_some() {
            let link = LinkToken::generate();
            let verifier = serde_json::to_value(PasswordResetVerifier { link: link.digest })
                .map_err(AppError::internal)?;
            (Some(link.token), Some(verifier))
        } else {
            (None, None)
        };

        let expires_at = now + ttl();
        let (email, render_failed) = match recipient.as_ref().zip(token.as_ref()) {
            Some((user, token)) => {
                let snapshot = self.settings.snapshot();
                let locales: Vec<&str> = user
                    .locale
                    .as_deref()
                    .into_iter()
                    .chain(request.locales.iter().map(String::as_str))
                    .collect();
                let rendered = render_templated_email(
                    dependencies.renderer.as_ref(),
                    &snapshot.get::<EmailTemplatesSetting>(),
                    EmailTemplateKind::PasswordReset,
                    EmailRecipient {
                        address: &user.email,
                        name: Some(&user.name),
                        locales: &locales,
                    },
                    expires_at,
                    |locale| {
                        json!({
                            "link": format!("{}{}", request.link_prefix, token),
                            "expires_in_minutes": ttl().num_minutes(),
                            "user": { "name": user.name, "email": user.email },
                            "locale": locale,
                        })
                    },
                );
                match rendered {
                    Ok(email) => (Some(email), false),
                    // While the login conceals the account, the answer must
                    // not depend on whether an email goes out.
                    Err(error) if concealed => {
                        warn!(error = %error, "password reset email could not be composed");
                        (None, true)
                    }
                    Err(error) => {
                        return Err(auth::error::PasswordResetDeliveryFailed.with_source(error));
                    }
                }
            }
            None => (None, false),
        };
        // The email is queued with the challenge it carries.
        let sent = match dependencies
            .challenges
            .admit_delivery(
                DeliveryChallengeContext {
                    user_oid: login.user_oid,
                    binding: ChallengeBinding::Login(login.oid),
                    method: ChallengeMethod::EmailOtp,
                    purpose: ChallengePurpose::PasswordReset,
                },
                DeliveryChallengeRequest {
                    now,
                    policy: LOGIN_EMAIL_DELIVERY,
                    code_expires_at: expires_at,
                    required_login_status: Some(LoginStatus::IDENTIFIER_VERIFIED),
                    verifier: if render_failed { None } else { verifier },
                    preserve_verifier: render_failed,
                    expected_email_normalized: recipient
                        .as_ref()
                        .map(|user| user.email_normalized.clone()),
                },
                email,
            )
            .await?
        {
            DeliveryChallengeAdmission::Admitted {
                resend_available_at,
                ..
            } => PasswordResetSent {
                expires_at,
                resend_available_at,
            },
            DeliveryChallengeAdmission::TooSoon { available_at } => {
                let seconds = (available_at - now).num_seconds().max(1);
                return Err(auth::error::PasswordResetResendTooSoon::new(seconds).into());
            }
            DeliveryChallengeAdmission::LimitReached => {
                return Err(auth::error::TooManyAttempts.into());
            }
            DeliveryChallengeAdmission::InvalidState => {
                return Err(auth::error::InvalidLoginState.into());
            }
        };

        Ok(sent)
    }

    /// Whether `token` is the current reset link of `login`, without using it.
    /// Lets the reset page refuse a stale link before a new password is typed.
    pub async fn check_password_reset_link(
        &self,
        login_oid: Uuid,
        token: &str,
    ) -> Result<(), AppError> {
        self.matching_reset(login_oid, token).await.map(|_| ())
    }

    /// Replace the password with the reset link `token` of `login`.
    ///
    /// The new password follows the same policy as a password change. The
    /// link is used up only when the password is replaced.
    #[tracing::instrument(skip_all, name = "authentication.password_reset.complete")]
    pub async fn reset_password(
        &self,
        login_oid: Uuid,
        token: &str,
        new_password: &str,
    ) -> Result<(), AppError> {
        let result = self
            .reset_password_inner(login_oid, token, new_password)
            .await;
        let mut event = BusinessEvent::audit("authentication.password_reset.completed");
        event = match &result {
            Ok(revoked) => event
                .outcome("success")
                .attribute("revoked_sessions", EventValue::Integer(i64::from(*revoked))),
            Err(error) => event
                .outcome("rejected")
                .attribute("error_code", EventValue::Integer(i64::from(error.code()))),
        };
        self.events.emit(event);
        result.map(|_| ())
    }

    async fn reset_password_inner(
        &self,
        login_oid: Uuid,
        token: &str,
        new_password: &str,
    ) -> Result<u32, AppError> {
        let (dependencies, login, user_oid, challenge_id) =
            self.matching_reset(login_oid, token).await?;
        if !self.account_accepts_reset(user_oid).await? {
            return Err(unavailable());
        }
        let prepared = self.prepare_password_change(user_oid, new_password).await?;
        // Use the link up before the password changes, so it works only once.
        if dependencies
            .challenges
            .take(challenge_context(user_oid.into(), login.oid), challenge_id)
            .await?
            .is_none()
        {
            return Err(link_invalid());
        }
        self.replace_prepared_password(
            user_oid,
            &prepared,
            PasswordReplacementKind::Reset { login: login.oid },
        )
        .await
    }

    /// The login, account and challenge of a reset link that is still valid.
    async fn matching_reset(
        &self,
        login_oid: Uuid,
        token: &str,
    ) -> Result<(LoginEmailDependencies, Login, UserOid, Uuid), AppError> {
        let login = self.get(login_oid).await?;
        if login.expires_at <= Utc::now() {
            return Err(auth::error::LoginExpired.into());
        }
        if !login_accepts_reset(&login) {
            return Err(link_invalid());
        }
        let Some(dependencies) = self.password_reset_dependencies() else {
            return Err(unavailable());
        };
        let Some(user_oid) = login.user_oid else {
            return Err(link_invalid());
        };
        let Some(challenge) = dependencies
            .challenges
            .latest(challenge_context(user_oid, login.oid))
            .await?
        else {
            return Err(link_invalid());
        };
        if !matches(&challenge, token.trim()) {
            return Err(link_invalid());
        }
        Ok((dependencies, login, user_oid.into(), challenge.id))
    }
}

fn unavailable() -> AppError {
    auth::error::PasswordResetUnavailable.into()
}

fn link_invalid() -> AppError {
    auth::error::PasswordResetLinkInvalid.into()
}

/// Whether `token` is the challenge's link token and the link is still valid.
fn matches(
    challenge: &identity_domain::auth::challenge::AuthenticationChallenge,
    token: &str,
) -> bool {
    let now = Utc::now();
    if challenge.expires_at <= now || token.is_empty() {
        return false;
    }
    let Ok(state) = serde_json::from_value::<DeliveryChallengeState>(challenge.state.clone())
    else {
        return false;
    };
    if state.code_expires_at <= now {
        return false;
    }
    let Some(verifier) = state
        .verifier
        .and_then(|value| serde_json::from_value::<PasswordResetVerifier>(value).ok())
    else {
        return false;
    };
    link_matches(token, &verifier.link)
}
