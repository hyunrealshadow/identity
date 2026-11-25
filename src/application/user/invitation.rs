//! Invitations: an administrator creates an account without a password and
//! the user sets their first password with a single-use link emailed to the
//! account's address.
//!
//! Only a digest of the link token is stored. An account has at most one
//! outstanding invitation; sending another replaces its link. The invitation
//! is tied to the address it was sent to, so changing the account's address
//! voids it, and it is usable only while the account is enabled and still
//! has no password. Accepting it sets the password, marks the address
//! verified, and removes the invitation in one transaction. Opening the link
//! only shows the account: the password is set when the form is submitted,
//! so a mail scanner that fetches the link cannot use it.

use std::{sync::Arc, time::Duration};

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde_json::json;
use tracing::warn;

use identity_domain::auth::challenge::DeliveryPolicy;

use super::{Password, User, UserOid};
use crate::{
    authentication::{
        password::{PasswordHasher, run_password_hashing},
        password_policy::{BreachedPasswordChecker, validate_breached_password, validate_password},
    },
    email::{
        EmailRecipient, EmailSender, EmailTemplateKind, EmailTemplateRenderer, LinkToken,
        link_digest, login_link_prefix, plausible_link_token, send_templated_email,
    },
    error::{
        AppError,
        codes::{auth::AuthErrorCode, user_management::UserManagementErrorCode},
    },
    observability::{BusinessEvent, EventSink, NoopEventSink},
    setting::{
        AppSettings, EmailDeliverySettings, EmailTemplatesSetting, PasswordHashSetting,
        SettingsSource,
    },
};

/// How long an invitation link stays valid.
pub const USER_INVITATION_TTL: Duration = Duration::from_secs(7 * 24 * 60 * 60);
/// How often one account may be sent an invitation: a minute apart, with no
/// limit, since only administrators send them.
pub const USER_INVITATION_DELIVERY: DeliveryPolicy = DeliveryPolicy {
    resend_interval: Duration::from_secs(60),
    max_sends: None,
    window: None,
};

/// Login route that accepts an invitation.
const INVITATION_ROUTE: &str = "invitation";

/// When the account's outstanding invitation was sent and until when its
/// link works. An expired invitation stays listed until it is sent again or
/// the account gets a password.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UserInvitationStatus {
    pub sent_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}

/// A new invitation link, ready to store with the account.
#[derive(Debug, Clone)]
pub struct InvitationIssue {
    /// SHA-256 of the link token, base64url.
    pub token_digest: String,
    pub sent_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}

/// A link token and its stored form. The token goes only into the email.
pub(crate) struct InvitationToken {
    pub(crate) token: String,
    pub(crate) issue: InvitationIssue,
}

impl InvitationToken {
    pub(crate) fn generate(now: DateTime<Utc>) -> Self {
        let LinkToken { token, digest } = LinkToken::generate();
        let issue = InvitationIssue {
            token_digest: digest,
            sent_at: now,
            expires_at: now + ttl(),
        };
        Self { token, issue }
    }
}

fn ttl() -> chrono::Duration {
    chrono::Duration::from_std(USER_INVITATION_TTL).unwrap_or_else(|_| chrono::Duration::days(7))
}

/// Outcome of accepting an invitation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InvitationAcceptance {
    Accepted {
        user_oid: UserOid,
    },
    /// Unknown, expired, already used, or no longer matching the account.
    Invalid,
}

#[async_trait]
pub trait UserInvitationRepository: Send + Sync {
    /// The account's outstanding invitation, expired or not.
    async fn find_for_user(
        &self,
        user_oid: UserOid,
    ) -> Result<Option<UserInvitationStatus>, AppError>;

    /// The account a still usable invitation link belongs to.
    async fn find_by_token(
        &self,
        token_digest: &str,
        now: DateTime<Utc>,
    ) -> Result<Option<User>, AppError>;

    /// Use the invitation up: set the account's first password, mark its
    /// address verified, and audit the acceptance, all in one transaction.
    async fn accept(
        &self,
        token_digest: &str,
        password: &Password,
        now: DateTime<Utc>,
    ) -> Result<InvitationAcceptance, AppError>;
}

/// Composes and sends invitation emails.
#[derive(Clone)]
pub struct InvitationDelivery {
    pub sender: Arc<dyn EmailSender>,
    pub renderer: Arc<dyn EmailTemplateRenderer>,
    pub settings: Arc<dyn SettingsSource>,
}

impl InvitationDelivery {
    /// Whether invitations can be sent: email delivery is configured and the
    /// Login address is known.
    #[must_use]
    pub fn available(&self) -> bool {
        let snapshot = self.settings.snapshot();
        snapshot.section::<EmailDeliverySettings>().is_configured()
            && invitation_link_prefix(&snapshot.section::<AppSettings>()).is_ok()
    }

    /// Email the invitation link `token` to `user`.
    pub(crate) async fn send(&self, user: &User, token: &str) -> Result<(), AppError> {
        let snapshot = self.settings.snapshot();
        let link_prefix = invitation_link_prefix(&snapshot.section::<AppSettings>())?;
        let locales: Vec<&str> = user.locale.as_deref().into_iter().collect();
        send_templated_email(
            self.sender.as_ref(),
            self.renderer.as_ref(),
            &snapshot.section::<EmailDeliverySettings>(),
            &snapshot.get::<EmailTemplatesSetting>(),
            EmailTemplateKind::UserInvitation,
            EmailRecipient {
                address: &user.email,
                name: Some(&user.name),
                locales: &locales,
            },
            |locale| {
                json!({
                    "link": format!("{link_prefix}{token}"),
                    "expires_in_days": ttl().num_days(),
                    "user": { "name": user.name, "email": user.email },
                    "locale": locale,
                })
            },
        )
        .await
        .map_err(|error| {
            warn!(
                reason = error.reason(),
                "invitation email was not delivered"
            );
            AppError::from_code(UserManagementErrorCode::InvitationDeliveryFailed)
                .with_source(error)
        })
    }
}

/// The Login page that accepts an invitation, ending where the token is
/// appended.
fn invitation_link_prefix(app: &AppSettings) -> Result<String, AppError> {
    login_link_prefix(app, INVITATION_ROUTE)
        .ok_or_else(|| AppError::from_code(UserManagementErrorCode::InvitationUnavailable))
}

/// The account an invitation link belongs to, as shown to the invitee.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InvitationAccount {
    pub username: String,
    pub email: String,
}

/// Accepting invitations, for someone who is not signed in.
#[derive(Clone)]
pub struct InvitationService {
    repository: Arc<dyn UserInvitationRepository>,
    password_hasher: Arc<dyn PasswordHasher>,
    breach_checker: Arc<dyn BreachedPasswordChecker>,
    settings: Arc<dyn SettingsSource>,
    events: Arc<dyn EventSink>,
}

impl InvitationService {
    #[must_use]
    pub fn new(
        repository: Arc<dyn UserInvitationRepository>,
        password_hasher: Arc<dyn PasswordHasher>,
        breach_checker: Arc<dyn BreachedPasswordChecker>,
        settings: Arc<dyn SettingsSource>,
    ) -> Self {
        Self {
            repository,
            password_hasher,
            breach_checker,
            settings,
            events: Arc::new(NoopEventSink),
        }
    }

    #[must_use]
    pub fn with_events(mut self, events: Arc<dyn EventSink>) -> Self {
        self.events = events;
        self
    }

    /// The account of a usable invitation link, without using it.
    pub async fn check(&self, token: &str) -> Result<InvitationAccount, AppError> {
        let user = self.matching_user(token).await?;
        Ok(InvitationAccount {
            username: user.name,
            email: user.email,
        })
    }

    async fn matching_user(&self, token: &str) -> Result<User, AppError> {
        if !plausible_link_token(token) {
            return Err(link_invalid());
        }
        self.repository
            .find_by_token(&link_digest(token), Utc::now())
            .await?
            .ok_or_else(link_invalid)
    }

    /// Set the first password of the invitation's account. The password
    /// follows the same policy as any other new password.
    #[tracing::instrument(skip_all, name = "user.invitation.accept")]
    pub async fn accept(&self, token: &str, password: &str) -> Result<(), AppError> {
        let result = self.accept_inner(token, password).await;
        let mut event = BusinessEvent::audit("user.invitation.accepted");
        event = match &result {
            Ok(()) => event.outcome("success"),
            Err(error) => event.outcome("rejected").attribute(
                "error_code",
                crate::observability::EventValue::Integer(i64::from(error.code())),
            ),
        };
        self.events.emit(event);
        result
    }

    async fn accept_inner(&self, token: &str, password: &str) -> Result<(), AppError> {
        let user = self.matching_user(token).await?;
        validate_password(password, &[&user.name, &user.email], "newPassword")?;
        let snapshot = self.settings.snapshot();
        validate_breached_password(
            self.breach_checker.as_ref(),
            &snapshot,
            password,
            "newPassword",
        )
        .await?;
        let options = snapshot.get::<PasswordHashSetting>();
        let hasher = Arc::clone(&self.password_hasher);
        let password = password.to_owned();
        let password = run_password_hashing(move || hasher.hash(&password, &options)).await?;
        match self
            .repository
            .accept(&link_digest(token), &password, Utc::now())
            .await?
        {
            InvitationAcceptance::Accepted { .. } => Ok(()),
            InvitationAcceptance::Invalid => Err(link_invalid()),
        }
    }
}

fn link_invalid() -> AppError {
    AppError::from_code(AuthErrorCode::InvitationLinkInvalid)
}

#[cfg(test)]
mod tests;
