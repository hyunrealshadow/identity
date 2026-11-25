//! Accepting an invitation: the link shows its account without being used,
//! and the first password follows the password policy.
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use uuid::Uuid;

use super::{
    InvitationAcceptance, InvitationDelivery, InvitationService, Invitee, USER_INVITATION_TTL,
    UserInvitationRepository, UserInvitationStatus,
};
use crate::{
    authentication::{
        password::{HashOptions, PasswordHashError, PasswordHasher, VerifyResult},
        password_policy::BreachedPasswordChecker,
    },
    email::{
        EmailTemplateContent, EmailTemplateRenderError, EmailTemplateRenderer, LinkToken,
        RenderedEmail, link_digest,
    },
    error::{AppError, code::AppErrorCode, codes::auth::AuthErrorCode},
    setting::{
        AppSettings, BreachedPasswordCheckEnabledSetting, EmailDeliverySettings,
        PasswordHashSetting, SettingDefinition as _, SettingsSnapshot,
    },
    user::{Argon2Password, Password, User, UserOid},
};

/// Stores the plain password as its "hash", so tests can see what was set.
struct PlainHasher;

impl PasswordHasher for PlainHasher {
    fn hash(&self, password: &str, options: &HashOptions) -> Result<Password, PasswordHashError> {
        let HashOptions::Argon2(options) = options;
        Ok(Password::Argon2(Argon2Password {
            hash: password.to_owned(),
            salt: "salt".to_owned(),
            options: options.clone(),
        }))
    }

    fn verify(
        &self,
        _: &str,
        _: &Password,
        _: &HashOptions,
    ) -> Result<VerifyResult, PasswordHashError> {
        Ok(VerifyResult::Failure)
    }
}

struct NeverBreached;

#[async_trait]
impl BreachedPasswordChecker for NeverBreached {
    async fn is_breached(&self, _: &str) -> Result<bool, AppError> {
        Ok(false)
    }
}

/// One invitation, usable until it is accepted.
struct OneInvitation {
    digest: String,
    user: User,
    accepted: Mutex<Option<String>>,
}

#[async_trait]
impl UserInvitationRepository for OneInvitation {
    async fn find_for_user(&self, _: UserOid) -> Result<Option<UserInvitationStatus>, AppError> {
        Ok(None)
    }

    async fn find_by_token(
        &self,
        token_digest: &str,
        _now: DateTime<Utc>,
    ) -> Result<Option<User>, AppError> {
        Ok(
            (token_digest == self.digest && self.accepted.lock().unwrap().is_none())
                .then(|| self.user.clone()),
        )
    }

    async fn accept(
        &self,
        token_digest: &str,
        password: &Password,
        _now: DateTime<Utc>,
    ) -> Result<InvitationAcceptance, AppError> {
        let mut accepted = self.accepted.lock().unwrap();
        if token_digest != self.digest || accepted.is_some() {
            return Ok(InvitationAcceptance::Invalid);
        }
        let Password::Argon2(password) = password;
        *accepted = Some(password.hash.clone());
        Ok(InvitationAcceptance::Accepted {
            user_oid: self.user.oid,
        })
    }
}

fn invited_user() -> User {
    User {
        oid: UserOid(Uuid::new_v4()),
        version: Uuid::new_v4(),
        email: "invited@example.com".to_owned(),
        email_normalized: "invited@example.com".to_owned(),
        name: "invited".to_owned(),
        name_normalized: "invited".to_owned(),
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
        theme: None,
        preferred_mfa_method: Default::default(),
        email_verified: false,
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
        required_actions: Default::default(),
        created_at: Utc::now(),
        updated_at: None,
    }
}

fn service() -> (InvitationService, Arc<OneInvitation>, String) {
    let token = LinkToken::generate();
    let repository = Arc::new(OneInvitation {
        digest: token.digest.clone(),
        user: invited_user(),
        accepted: Mutex::new(None),
    });
    let settings = Arc::new(
        SettingsSnapshot::default()
            .with::<PasswordHashSetting>(PasswordHashSetting::default_value())
            .with::<BreachedPasswordCheckEnabledSetting>(false),
    );
    let service = InvitationService::new(
        Arc::clone(&repository) as Arc<dyn UserInvitationRepository>,
        Arc::new(PlainHasher),
        Arc::new(NeverBreached),
        settings,
    );
    (service, repository, token.token)
}

/// Puts the link in the body, so tests can read it back.
struct LinkRenderer;

impl EmailTemplateRenderer for LinkRenderer {
    fn render(
        &self,
        _: &EmailTemplateContent,
        context: &serde_json::Value,
    ) -> Result<RenderedEmail, EmailTemplateRenderError> {
        Ok(RenderedEmail {
            subject: "invitation".to_owned(),
            html: context["link"].as_str().unwrap().to_owned(),
        })
    }
}

#[test]
fn a_new_link_is_emailed_to_its_account_and_only_its_digest_is_kept() {
    let delivery = InvitationDelivery {
        renderer: Arc::new(LinkRenderer),
        settings: Arc::new(
            SettingsSnapshot::default()
                .with_section(&AppSettings {
                    login_domain: Some("https://login.example.com".to_owned()),
                    ..AppSettings::default()
                })
                .with_section(&EmailDeliverySettings {
                    enabled: true,
                    host: "smtp.example.com".to_owned(),
                    sender_address: "identity@example.com".to_owned(),
                    ..EmailDeliverySettings::default()
                }),
        ),
    };
    let now = Utc::now();
    let issue = delivery
        .issue(
            &Invitee {
                name: "invited",
                email: "Invited@Example.com",
                email_normalized: "invited@example.com",
                locale: None,
            },
            now,
        )
        .unwrap();

    let link = &issue.email.message.html;
    let token = link
        .strip_prefix("https://login.example.com/invitation?token=")
        .expect("the email carries the invitation link");
    assert_eq!(issue.token_digest, link_digest(token));
    assert_eq!(issue.email.message.to_address, "Invited@Example.com");
    assert_eq!(issue.recipient_normalized, "invited@example.com");
    assert_eq!(
        (issue.expires_at - now).to_std().unwrap(),
        USER_INVITATION_TTL
    );
    assert_eq!(issue.email.expires_at, issue.expires_at);
}

#[tokio::test]
async fn checking_a_link_shows_its_account_without_using_it() {
    let (service, repository, token) = service();
    let account = service.check(&token).await.unwrap();
    assert_eq!(account.username, "invited");
    assert_eq!(account.email, "invited@example.com");
    assert!(repository.accepted.lock().unwrap().is_none());

    let error = service.check("not-the-token").await.unwrap_err();
    assert_eq!(error.code(), AuthErrorCode::InvitationLinkInvalid.code());
}

#[tokio::test]
async fn accepting_sets_a_policy_conforming_password_once() {
    let (service, repository, token) = service();
    let error = service.accept(&token, "short").await.unwrap_err();
    let field = error.validation().unwrap().fields().first().unwrap();
    assert_eq!(field.field(), "newPassword");
    assert_eq!(field.code(), AuthErrorCode::PasswordTooShort.code());
    // The username is too similar to be a password.
    assert!(service.accept(&token, "invited").await.is_err());
    assert!(repository.accepted.lock().unwrap().is_none());

    service
        .accept(&token, "a-first-sufficiently-long-password")
        .await
        .unwrap();
    assert_eq!(
        repository.accepted.lock().unwrap().as_deref(),
        Some("a-first-sufficiently-long-password")
    );

    let error = service
        .accept(&token, "another-sufficiently-long-password")
        .await
        .unwrap_err();
    assert_eq!(error.code(), AuthErrorCode::InvitationLinkInvalid.code());
}
