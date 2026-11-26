//! Email sign-in: a one-time code and a single-use link sent to the account's
//! verified email address, accepted instead of the password as the first
//! factor. A second factor the account has enrolled is still required.
//!
//! The send admission (resend interval, send limit, and verifier state) is
//! kept on the outbound authentication challenge itself, so it behaves the
//! same whether or not the identifier matched an account. While the interaction
//! conceals whether an account exists, the email is composed and sent in the
//! background and every outcome looks alike.

use std::sync::Arc;

use chrono::{DateTime, Duration, Utc};
use identity_domain::{
    auth::{
        AMR_EMAIL, EMAIL_CODE_RESEND_INTERVAL, EMAIL_CODE_TTL, LOGIN_EMAIL_DELIVERY,
        LoginFailureReason, LoginStatus, MAX_FAILED_ATTEMPTS, MAX_OTP_ATTEMPTS,
        challenge::{
            AuthenticationChallenge, ChallengeBinding, ChallengeContext, ChallengeMethod,
            ChallengePurpose, DeliveryChallengeAdmission, DeliveryChallengeContext,
            DeliveryChallengeRequest, DeliveryChallengeState,
        },
        model::Login,
    },
    user::User,
};
use rand::RngExt;
use serde::{Deserialize, Serialize};
use serde_json::json;
use subtle::ConstantTimeEq;
use tracing::warn;
use uuid::Uuid;

use super::{ChallengeOutcome, LoginService, SessionContext, failed_attempt_lock_until};
use crate::{
    authentication::challenge::ChallengeRepository,
    data_protection::DataProtector,
    email::{
        EmailRecipient, EmailTemplateKind, EmailTemplateRenderer, LinkToken, link_matches,
        render_templated_email,
    },
    error::{AppError, codes::auth},
    observability::{BusinessEvent, EventValue},
    setting::{
        EmailDeliverySettings, EmailSignInEnabledSetting, EmailTemplatesSetting, SettingsSnapshot,
    },
};

/// Data-protection purpose of the stored sign-in code.
const EMAIL_CODE_PURPOSE: &str = "authentication.email_code";
const EMAIL_CODE_DIGITS: usize = 6;

/// What email sign-in needs besides the login repositories.
#[derive(Clone)]
pub struct LoginEmailDependencies {
    pub challenges: Arc<dyn ChallengeRepository>,
    pub renderer: Arc<dyn EmailTemplateRenderer>,
    pub protector: Arc<dyn DataProtector>,
}

/// A request to email a sign-in code for one login.
pub struct EmailCodeRequest {
    pub login_oid: Uuid,
    /// Locales the browser asked for, most preferred first. The account's
    /// own locale preference comes before them.
    pub locales: Vec<String>,
    /// The application being signed in to, for the message.
    pub application_name: Option<String>,
    /// The sign-in link up to its token: the token is appended as is.
    pub link_prefix: String,
}

/// The outcome of a send, identical whether or not an account matched.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EmailCodeSent {
    pub expires_at: DateTime<Utc>,
    pub resend_available_at: DateTime<Utc>,
}

/// Verifier state kept inside [`DeliveryChallengeState::verifier`].
/// Never sent to a browser or written to logs.
#[derive(Serialize, Deserialize)]
struct EmailChallengeVerifier {
    /// The code, protected for [`EMAIL_CODE_PURPOSE`].
    code: String,
    /// SHA-256 of the link token, base64url.
    link: String,
}

fn interval() -> Duration {
    Duration::from_std(EMAIL_CODE_RESEND_INTERVAL).unwrap_or_else(|_| Duration::seconds(60))
}

fn ttl() -> Duration {
    Duration::from_std(EMAIL_CODE_TTL).unwrap_or_else(|_| Duration::minutes(10))
}

fn challenge_context(user_oid: Uuid, login_oid: Uuid) -> ChallengeContext {
    ChallengeContext {
        user_oid,
        binding: ChallengeBinding::Login(login_oid),
        method: ChallengeMethod::EmailOtp,
        purpose: ChallengePurpose::Authentication,
    }
}

/// Whether email sign-in is turned on and email can be sent.
#[must_use]
pub fn email_sign_in_available(snapshot: &SettingsSnapshot) -> bool {
    snapshot.get::<EmailSignInEnabledSetting>()
        && snapshot.section::<EmailDeliverySettings>().is_configured()
}

/// Whether an account may receive a sign-in email.
#[must_use]
pub fn can_receive_email_code(user: &User) -> bool {
    user.enabled
        && user.email_verified
        && !user.email.trim().is_empty()
        && !(user.locked && user.locked_until.is_none_or(|until| Utc::now() < until))
}

impl LoginService {
    /// Whether this instance offers email sign-in right now.
    #[must_use]
    pub fn email_sign_in_available(&self) -> bool {
        self.email.is_some() && email_sign_in_available(&self.settings.snapshot())
    }

    /// When another sign-in email may be requested for `login`, if one was
    /// sent while waiting for the first factor.
    pub async fn email_code_resend_available_at(
        &self,
        login: &Login,
    ) -> Result<Option<DateTime<Utc>>, AppError> {
        if login.status != LoginStatus::IDENTIFIER_VERIFIED {
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
                ChallengePurpose::Authentication,
            )
            .await?;
        Ok(status.map(|status| status.sent_at + interval()))
    }

    /// Email a sign-in code and link for a login waiting for its first factor.
    #[tracing::instrument(skip_all, name = "authentication.email_code.send")]
    pub async fn send_email_code(
        &self,
        request: EmailCodeRequest,
    ) -> Result<EmailCodeSent, AppError> {
        let result = self.send_email_code_inner(request).await;
        let mut event = BusinessEvent::business("authentication.email_code.sent");
        event = match &result {
            Ok(_) => event.outcome("accepted"),
            Err(error) => event
                .outcome("rejected")
                .attribute("error_code", EventValue::Integer(i64::from(error.code()))),
        };
        self.events.emit(event);
        result
    }

    async fn send_email_code_inner(
        &self,
        request: EmailCodeRequest,
    ) -> Result<EmailCodeSent, AppError> {
        let login = self.get(request.login_oid).await?;
        let now = Utc::now();
        if login.expires_at <= now {
            return Err(auth::error::LoginExpired.into());
        }
        if login.status != LoginStatus::IDENTIFIER_VERIFIED {
            return Err(auth::error::InvalidLoginState.into());
        }
        let Some(dependencies) = self
            .email
            .clone()
            .filter(|_| self.email_sign_in_available())
        else {
            return Err(unsupported());
        };
        let concealed = login.concealed_identifier().is_some();
        let user = match login.user_oid {
            Some(user_oid) => self.user_repo.find_by_oid(user_oid.into()).await?,
            None => None,
        };
        let recipient = user.filter(can_receive_email_code);
        if recipient.is_none() && !concealed {
            return Err(unsupported());
        }

        let (generated, verifier) = if recipient.is_some() {
            let code = {
                let mut rng = rand::rng();
                (0..EMAIL_CODE_DIGITS)
                    .map(|_| char::from(b'0' + rng.random_range(0..10u8)))
                    .collect::<String>()
            };
            let link = LinkToken::generate();
            let protected_code = dependencies
                .protector
                .protect(EMAIL_CODE_PURPOSE, code.as_bytes())
                .await
                .map_err(AppError::from)?;
            let verifier = serde_json::to_value(EmailChallengeVerifier {
                code: protected_code,
                link: link.digest,
            })
            .map_err(AppError::internal)?;
            (Some((code, link.token)), Some(verifier))
        } else {
            (None, None)
        };

        let expires_at = now + ttl();
        let (email, render_failed) = match recipient.as_ref().zip(generated.as_ref()) {
            Some((user, (code, token))) => {
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
                    EmailTemplateKind::SignInCode,
                    EmailRecipient {
                        address: &user.email,
                        name: Some(&user.name),
                        locales: &locales,
                    },
                    expires_at,
                    |locale| {
                        json!({
                            "code": code,
                            "link": format!("{}{}", request.link_prefix, token),
                            "expires_in_minutes": ttl().num_minutes(),
                            "user": { "name": user.name, "email": user.email },
                            "application": request.application_name.as_ref().map(|name| json!({ "name": name })),
                            "locale": locale,
                        })
                    },
                );
                match rendered {
                    Ok(email) => (Some(email), false),
                    // While the login conceals the account, the answer must
                    // not depend on whether an email goes out.
                    Err(error) if concealed => {
                        warn!(error = %error, "sign-in email could not be composed");
                        (None, true)
                    }
                    Err(error) => {
                        return Err(auth::error::EmailDeliveryFailed.with_source(error));
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
                    purpose: ChallengePurpose::Authentication,
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
            } => EmailCodeSent {
                expires_at,
                resend_available_at,
            },
            DeliveryChallengeAdmission::TooSoon { available_at } => {
                let seconds = (available_at - now).num_seconds().max(1);
                return Err(auth::error::EmailCodeResendTooSoon::new(seconds).into());
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

    /// Verify an emailed code, or the token of an emailed link, as the first
    /// factor.
    pub(super) async fn challenge_email_otp(
        &self,
        login: Login,
        credential: &str,
        ctx: SessionContext,
    ) -> Result<ChallengeOutcome, AppError> {
        if login.status != LoginStatus::IDENTIFIER_VERIFIED {
            return Err(auth::error::InvalidLoginState.into());
        }
        let Some(dependencies) = self
            .email
            .clone()
            .filter(|_| self.email_sign_in_available())
        else {
            return Err(unsupported());
        };
        if login.failed_attempts >= MAX_OTP_ATTEMPTS {
            self.fail_login_for_too_many_otp_attempts(login.oid).await;
            return Err(auth::error::TooManyAttempts.into());
        }
        let user = match login.user_oid {
            Some(user_oid) => self.user_repo.find_by_oid(user_oid.into()).await?,
            None => None,
        };
        let challenge = match &user {
            Some(user) => {
                dependencies
                    .challenges
                    .latest(challenge_context(user.oid.into(), login.oid))
                    .await?
            }
            None => None,
        };
        let verified = match &challenge {
            Some(challenge) => matches(&dependencies, challenge, credential.trim()).await,
            None => false,
        };
        let (Some(user), Some(challenge), true) = (user, challenge, verified) else {
            return Err(self.reject_email_code(&login).await);
        };
        // Consume the challenge so neither its code nor its link is used twice.
        if dependencies
            .challenges
            .take(challenge_context(user.oid.into(), login.oid), challenge.id)
            .await?
            .is_none()
        {
            return Err(self.reject_email_code(&login).await);
        }
        self.ensure_user_can_authenticate(&user).await?;
        if !user.email_verified {
            return Err(unsupported());
        }
        self.user_repo.reset_failed_attempts(user.oid).await?;
        self.login_repo.reset_failed_attempts(login.oid).await?;
        self.first_factor_verified(login, &user, AMR_EMAIL, ctx)
            .await
    }

    /// Count a wrong or unusable code against the login and its account.
    async fn reject_email_code(&self, login: &Login) -> AppError {
        let attempts = match self
            .login_repo
            .increment_failed_attempts(login.oid, Some(LoginFailureReason::InvalidOtp))
            .await
        {
            Ok(attempts) => attempts,
            Err(error) => return error.into(),
        };
        let mut user_attempts = 0;
        if let Some(user_oid) = login.user_oid {
            match self
                .user_repo
                .increment_failed_attempts(
                    user_oid.into(),
                    MAX_FAILED_ATTEMPTS,
                    failed_attempt_lock_until(),
                )
                .await
            {
                Ok(count) => user_attempts = count,
                Err(error) => return error.into(),
            }
        }
        // Reaching the account's lockout is not disclosed while the login
        // conceals the account.
        let account_locked =
            login.concealed_identifier().is_none() && user_attempts >= MAX_FAILED_ATTEMPTS;
        if attempts >= MAX_OTP_ATTEMPTS || account_locked {
            self.fail_login_for_too_many_otp_attempts(login.oid).await;
            return auth::error::TooManyAttempts.into();
        }
        auth::error::InvalidOtp.into()
    }
}

fn unsupported() -> AppError {
    auth::error::CredentialTypeUnsupported::new("email_otp").into()
}

/// Whether `credential` is the challenge's code or its link token.
async fn matches(
    dependencies: &LoginEmailDependencies,
    challenge: &AuthenticationChallenge,
    credential: &str,
) -> bool {
    let now = Utc::now();
    if challenge.expires_at <= now {
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
        .and_then(|value| serde_json::from_value::<EmailChallengeVerifier>(value).ok())
    else {
        return false;
    };
    let is_code =
        credential.len() == EMAIL_CODE_DIGITS && credential.bytes().all(|b| b.is_ascii_digit());
    if is_code {
        let Ok(code) = dependencies
            .protector
            .unprotect(EMAIL_CODE_PURPOSE, &verifier.code)
            .await
        else {
            return false;
        };
        return bool::from(code.as_slice().ct_eq(credential.as_bytes()));
    }
    link_matches(credential, &verifier.link)
}
