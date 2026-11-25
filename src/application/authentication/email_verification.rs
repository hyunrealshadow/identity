//! Email address verification from the account center. A single-use link is
//! emailed to the address being verified: either the account's current
//! address, or a new address that replaces it only when the link is followed.
//! Only a digest of the link token is stored. Following the link needs no
//! session, so it works from another device; the Login page only shows a
//! confirmation, and the verification happens when the user continues, so a
//! mail scanner that fetches the link cannot use it.

use std::sync::Arc;

use chrono::{DateTime, Duration, Utc};
use identity_domain::user::{
    User, UserOid,
    email_verification::{
        EMAIL_VERIFICATION_RESEND_INTERVAL, EMAIL_VERIFICATION_TTL, EmailVerification,
        EmailVerificationAdmission, EmailVerificationOutcome, EmailVerificationRepository,
        EmailVerificationRequest,
    },
    repository::UserIdentifierUpdate,
};
use serde_json::json;
use tracing::warn;
use uuid::Uuid;

use super::account::{AccountService, map_identifier_error, validate_email};
use crate::{
    email::{
        EmailRecipient, EmailSender, EmailTemplateKind, EmailTemplateRenderer, LinkToken,
        link_digest, login_link_prefix, plausible_link_token, send_templated_email,
    },
    error::{
        AppError,
        codes::{account::AccountErrorCode, common::CommonErrorCode},
    },
    observability::{BusinessEvent, EventValue},
    setting::{AppSettings, EmailDeliverySettings, EmailTemplatesSetting, SettingsSource},
};

/// Login route that confirms a verification link.
const VERIFY_EMAIL_ROUTE: &str = "verify-email";

/// What email verification needs besides the account repository.
#[derive(Clone)]
pub struct EmailVerificationDependencies {
    pub repository: Arc<dyn EmailVerificationRepository>,
    pub sender: Arc<dyn EmailSender>,
    pub renderer: Arc<dyn EmailTemplateRenderer>,
    pub settings: Arc<dyn SettingsSource>,
}

/// The result of asking to change the account's email address.
#[derive(Debug, Clone)]
pub enum EmailChange {
    /// The address was replaced at once, unverified, because this instance
    /// cannot send email, or only its letter case changed.
    Changed(Box<User>),
    /// A link was sent to the new address; the current one stays until the
    /// link is followed.
    VerificationSent(EmailVerificationSent),
}

/// A verification email that was sent.
#[derive(Debug, Clone)]
pub struct EmailVerificationSent {
    pub verification: EmailVerification,
    pub resend_available_at: DateTime<Utc>,
}

/// An outstanding verification as shown in the account center.
#[derive(Debug, Clone)]
pub struct PendingEmailVerification {
    pub verification: EmailVerification,
    pub resend_available_at: DateTime<Utc>,
}

/// The result of following a verification link.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedEmail {
    pub user_oid: UserOid,
    pub email: String,
    pub changed: bool,
}

fn duration(value: std::time::Duration) -> Duration {
    Duration::from_std(value).unwrap_or(Duration::MAX)
}

impl AccountService {
    /// Whether this instance can send verification emails right now.
    #[must_use]
    pub fn email_verification_available(&self) -> bool {
        self.email_verification
            .as_ref()
            .is_some_and(|dependencies| {
                dependencies
                    .settings
                    .snapshot()
                    .section::<EmailDeliverySettings>()
                    .is_configured()
            })
    }

    /// Change the account's email address. While email can be sent, the new
    /// address must be verified first: a link is sent to it and the current
    /// address stays in place. Otherwise the address is replaced at once and
    /// is unverified.
    #[tracing::instrument(skip_all, name = "account.email.change")]
    pub async fn update_email(
        &self,
        user_oid: UserOid,
        email: &str,
        locales: Vec<String>,
    ) -> Result<EmailChange, AppError> {
        let update = validate_email(email)?;
        let UserIdentifierUpdate::Email { value, normalized } = &update else {
            unreachable!("validate_email returns an email update");
        };
        let user = self
            .find_user(user_oid)
            .await?
            .ok_or_else(|| AppError::from_code(CommonErrorCode::NotFound))?;
        let same_address = *normalized == user.email_normalized;
        if same_address || !self.email_verification_available() {
            if same_address && let Some(dependencies) = &self.email_verification {
                // Keeping the current address withdraws a pending change.
                dependencies
                    .repository
                    .cancel(user_oid)
                    .await
                    .map_err(AppError::internal)?;
            }
            let user = self
                .user_repo
                .update_identifier(user_oid, update)
                .await
                .map_err(map_identifier_error)?
                .ok_or_else(|| AppError::from_code(CommonErrorCode::NotFound))?;
            self.record_account_change("email", user_oid, "success");
            return Ok(EmailChange::Changed(Box::new(user)));
        }
        let sent = self
            .send_verification(&user, value.clone(), normalized.clone(), locales)
            .await?;
        Ok(EmailChange::VerificationSent(sent))
    }

    /// Send a new link for the pending address change, or else for the
    /// account's current address.
    #[tracing::instrument(skip_all, name = "account.email_verification.send")]
    pub async fn send_email_verification(
        &self,
        user_oid: UserOid,
        locales: Vec<String>,
    ) -> Result<EmailVerificationSent, AppError> {
        let user = self
            .find_user(user_oid)
            .await?
            .ok_or_else(|| AppError::from_code(CommonErrorCode::NotFound))?;
        let pending = self.pending_email_verification(user_oid).await?;
        let (email, normalized) = match pending {
            Some(pending) if pending.verification.changes_email => (
                pending.verification.email,
                pending.verification.email_normalized,
            ),
            _ => (user.email.clone(), user.email_normalized.clone()),
        };
        self.send_verification(&user, email, normalized, locales)
            .await
    }

    /// The account's outstanding verification, if it can still be followed.
    pub async fn pending_email_verification(
        &self,
        user_oid: UserOid,
    ) -> Result<Option<PendingEmailVerification>, AppError> {
        let Some(dependencies) = &self.email_verification else {
            return Ok(None);
        };
        let pending = dependencies
            .repository
            .pending(user_oid, Utc::now())
            .await
            .map_err(AppError::internal)?;
        Ok(pending.map(|verification| PendingEmailVerification {
            resend_available_at: verification.sent_at
                + duration(EMAIL_VERIFICATION_RESEND_INTERVAL),
            verification,
        }))
    }

    /// Withdraw the outstanding verification; its link stops working.
    #[tracing::instrument(skip_all, name = "account.email_verification.cancel")]
    pub async fn cancel_email_verification(&self, user_oid: UserOid) -> Result<bool, AppError> {
        let Some(dependencies) = &self.email_verification else {
            return Ok(false);
        };
        dependencies
            .repository
            .cancel(user_oid)
            .await
            .map_err(AppError::internal)
    }

    /// Follow a verification link: mark the address verified, replacing the
    /// account's address when the link was for a new one.
    #[tracing::instrument(skip_all, name = "account.email_verification.confirm")]
    pub async fn confirm_email_verification(&self, token: &str) -> Result<VerifiedEmail, AppError> {
        let result = self.confirm_email_verification_inner(token.trim()).await;
        let mut event = BusinessEvent::audit("account.email_verification.confirmed");
        event = match &result {
            Ok(verified) => event
                .outcome("success")
                .attribute("email_changed", EventValue::Boolean(verified.changed))
                .attribute(
                    "user_oid",
                    EventValue::Pseudonymized {
                        purpose: "user_oid",
                        value: Uuid::from(verified.user_oid).to_string(),
                    },
                ),
            Err(error) => event
                .outcome("rejected")
                .attribute("error_code", EventValue::Integer(i64::from(error.code()))),
        };
        self.events.emit(event);
        result
    }

    async fn confirm_email_verification_inner(
        &self,
        token: &str,
    ) -> Result<VerifiedEmail, AppError> {
        let Some(dependencies) = &self.email_verification else {
            return Err(AppError::from_code(
                AccountErrorCode::EmailVerificationInvalid,
            ));
        };
        if !plausible_link_token(token) {
            return Err(AppError::from_code(
                AccountErrorCode::EmailVerificationInvalid,
            ));
        }
        match dependencies
            .repository
            .confirm(&link_digest(token), Utc::now())
            .await
            .map_err(AppError::internal)?
        {
            EmailVerificationOutcome::Verified {
                user_oid,
                email,
                changed,
            } => Ok(VerifiedEmail {
                user_oid,
                email,
                changed,
            }),
            EmailVerificationOutcome::Invalid => Err(AppError::from_code(
                AccountErrorCode::EmailVerificationInvalid,
            )),
            EmailVerificationOutcome::EmailExists => {
                Err(AppError::from_code(AccountErrorCode::EmailExists))
            }
        }
    }

    async fn send_verification(
        &self,
        user: &User,
        email: String,
        email_normalized: String,
        locales: Vec<String>,
    ) -> Result<EmailVerificationSent, AppError> {
        let result = self
            .send_verification_inner(user, email, email_normalized, locales)
            .await;
        let mut event = BusinessEvent::business("account.email_verification.sent");
        event = match &result {
            Ok(sent) => event.outcome("accepted").attribute(
                "email_change",
                EventValue::Boolean(sent.verification.changes_email),
            ),
            Err(error) => event
                .outcome("rejected")
                .attribute("error_code", EventValue::Integer(i64::from(error.code()))),
        };
        self.events.emit(event);
        result
    }

    async fn send_verification_inner(
        &self,
        user: &User,
        email: String,
        email_normalized: String,
        locales: Vec<String>,
    ) -> Result<EmailVerificationSent, AppError> {
        let Some(dependencies) = self
            .email_verification
            .clone()
            .filter(|_| self.email_verification_available())
        else {
            return Err(AppError::from_code(
                AccountErrorCode::EmailVerificationUnavailable,
            ));
        };
        let snapshot = dependencies.settings.snapshot();
        let link_prefix = verification_link_prefix(&snapshot.section::<AppSettings>())?;
        let LinkToken { token, digest } = LinkToken::generate();
        let now = Utc::now();
        let admission = dependencies
            .repository
            .admit(EmailVerificationRequest {
                user_oid: user.oid,
                email,
                email_normalized,
                token_digest: digest,
                now,
            })
            .await
            .map_err(AppError::internal)?;
        let sent = match admission {
            EmailVerificationAdmission::Admitted {
                verification,
                resend_available_at,
            } => EmailVerificationSent {
                verification,
                resend_available_at,
            },
            EmailVerificationAdmission::TooSoon { available_at } => {
                let seconds = (available_at - now).num_seconds().max(1);
                return Err(
                    AppError::from_code(AccountErrorCode::EmailVerificationResendTooSoon)
                        .with_param("seconds", seconds.to_string()),
                );
            }
            EmailVerificationAdmission::LimitReached => {
                return Err(AppError::from_code(
                    AccountErrorCode::EmailVerificationLimitReached,
                ));
            }
            EmailVerificationAdmission::AlreadyVerified => {
                return Err(AppError::from_code(AccountErrorCode::EmailAlreadyVerified));
            }
            EmailVerificationAdmission::EmailExists => {
                return Err(AppError::from_code(AccountErrorCode::EmailExists).with_field("email"));
            }
            EmailVerificationAdmission::UserNotFound => {
                return Err(AppError::from_code(CommonErrorCode::NotFound));
            }
        };

        let locales: Vec<&str> = user
            .locale
            .as_deref()
            .into_iter()
            .chain(locales.iter().map(String::as_str))
            .collect();
        send_templated_email(
            dependencies.sender.as_ref(),
            dependencies.renderer.as_ref(),
            &snapshot.section::<EmailDeliverySettings>(),
            &snapshot.get::<EmailTemplatesSetting>(),
            EmailTemplateKind::EmailVerification,
            EmailRecipient {
                address: &sent.verification.email,
                name: Some(&user.name),
                locales: &locales,
            },
            |locale| {
                json!({
                    "link": format!("{link_prefix}{token}"),
                    "email": sent.verification.email,
                    "changes_email": sent.verification.changes_email,
                    "expires_in_hours": duration(EMAIL_VERIFICATION_TTL).num_hours(),
                    "user": { "name": user.name, "email": user.email },
                    "locale": locale,
                })
            },
        )
        .await
        .map_err(|error| {
            warn!(
                reason = error.reason(),
                "verification email was not delivered"
            );
            AppError::from_code(AccountErrorCode::EmailVerificationDeliveryFailed)
                .with_source(error)
        })?;
        Ok(sent)
    }
}

/// The Login page that confirms a link, ending where the token is appended.
fn verification_link_prefix(app: &AppSettings) -> Result<String, AppError> {
    login_link_prefix(app, VERIFY_EMAIL_ROUTE)
        .ok_or_else(|| AppError::from_code(AccountErrorCode::EmailVerificationUnavailable))
}

#[cfg(test)]
mod tests;
