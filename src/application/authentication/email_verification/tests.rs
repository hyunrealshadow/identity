//! Email verification use cases against in-memory ports: which address a
//! link goes to, what is stored, and how outcomes surface as errors.

use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use identity_domain::user::{
    User, UserOid,
    email_verification::{
        EmailVerification, EmailVerificationAdmission, EmailVerificationOutcome,
        EmailVerificationRepository, EmailVerificationRepositoryError, EmailVerificationRequest,
    },
    repository::{UserIdentifierUpdate, UserProfilePatch, UserRepository, UserRepositoryError},
};
use serde_json::Value;
use uuid::Uuid;

use super::*;
use crate::{
    email::{
        EmailMessage, EmailTemplateContent, EmailTemplateRenderError, EmailTemplateRenderer,
        RenderedEmail,
    },
    error::{code::AppErrorCode, codes::account::AccountErrorCode},
    setting::{AppSettings, EmailDeliverySettings, SettingsSnapshot},
};

const LOGIN_DOMAIN: &str = "https://login.example.com";

fn user(email: &str, verified: bool) -> User {
    User {
        oid: UserOid(Uuid::new_v4()),
        version: Uuid::new_v4(),
        email: email.to_owned(),
        email_normalized: email.to_lowercase(),
        name: "ada".to_owned(),
        name_normalized: "ada".to_owned(),
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
        locale: Some("zh-CN".to_owned()),
        theme: None,
        preferred_mfa_method: Default::default(),
        email_verified: verified,
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

#[derive(Default)]
struct MemoryUsers {
    users: Mutex<HashMap<UserOid, User>>,
}

#[async_trait]
impl UserRepository for MemoryUsers {
    async fn find_by_identifier(&self, _identifier: &str) -> Result<User, UserRepositoryError> {
        Err(UserRepositoryError::UserNotFound)
    }

    async fn find_by_oid(&self, oid: UserOid) -> Result<Option<User>, UserRepositoryError> {
        Ok(self.users.lock().unwrap().get(&oid).cloned())
    }

    async fn increment_failed_attempts(
        &self,
        _user_oid: UserOid,
        _lock_threshold: i32,
        _lock_until: DateTime<Utc>,
    ) -> Result<i32, UserRepositoryError> {
        Ok(0)
    }

    async fn reset_failed_attempts(&self, _user_oid: UserOid) -> Result<(), UserRepositoryError> {
        Ok(())
    }

    async fn update_identifier(
        &self,
        oid: UserOid,
        update: UserIdentifierUpdate,
    ) -> Result<Option<User>, UserRepositoryError> {
        let mut users = self.users.lock().unwrap();
        let Some(user) = users.get_mut(&oid) else {
            return Ok(None);
        };
        if let UserIdentifierUpdate::Email { value, normalized } = update {
            if normalized != user.email_normalized {
                user.email_verified = false;
            }
            user.email = value;
            user.email_normalized = normalized;
        }
        Ok(Some(user.clone()))
    }

    async fn update_profile(
        &self,
        _oid: UserOid,
        _patch: UserProfilePatch,
    ) -> Result<Option<User>, UserRepositoryError> {
        unreachable!("not used by email verification")
    }
}

/// Records what the service asks for; the outcomes are scripted per test.
#[derive(Default)]
struct MemoryVerifications {
    admitted: Mutex<Vec<EmailVerificationRequest>>,
    /// Messages queued with admitted verifications.
    queued: Arc<RecordingSender>,
    admission: Mutex<Option<EmailVerificationAdmission>>,
    pending: Mutex<Option<EmailVerification>>,
    cancelled: Mutex<usize>,
    confirmed: Mutex<Vec<String>>,
    outcome: Mutex<Option<EmailVerificationOutcome>>,
}

#[async_trait]
impl EmailVerificationRepository for MemoryVerifications {
    async fn admit(
        &self,
        request: EmailVerificationRequest,
    ) -> Result<EmailVerificationAdmission, EmailVerificationRepositoryError> {
        self.admitted.lock().unwrap().push(request.clone());
        if let Some(admission) = self.admission.lock().unwrap().clone() {
            return Ok(admission);
        }
        self.queued
            .sent
            .lock()
            .unwrap()
            .push(request.message.message.clone());
        Ok(EmailVerificationAdmission::Admitted {
            verification: EmailVerification {
                oid: Uuid::new_v4(),
                user_oid: request.user_oid,
                changes_email: request.email != "ada@example.com",
                email: request.email,
                email_normalized: request.email_normalized,
                sent_at: request.now,
                expires_at: request.now + chrono::Duration::hours(24),
            },
            resend_available_at: request.now + chrono::Duration::seconds(60),
        })
    }

    async fn pending(
        &self,
        _user_oid: UserOid,
        _now: DateTime<Utc>,
    ) -> Result<Option<EmailVerification>, EmailVerificationRepositoryError> {
        Ok(self.pending.lock().unwrap().clone())
    }

    async fn cancel(&self, _user_oid: UserOid) -> Result<bool, EmailVerificationRepositoryError> {
        *self.cancelled.lock().unwrap() += 1;
        Ok(self.pending.lock().unwrap().take().is_some())
    }

    async fn confirm(
        &self,
        token_digest: &str,
        _now: DateTime<Utc>,
    ) -> Result<EmailVerificationOutcome, EmailVerificationRepositoryError> {
        self.confirmed.lock().unwrap().push(token_digest.to_owned());
        Ok(self
            .outcome
            .lock()
            .unwrap()
            .clone()
            .unwrap_or(EmailVerificationOutcome::Invalid))
    }
}

/// Records what was queued.
#[derive(Default)]
struct RecordingSender {
    sent: Mutex<Vec<EmailMessage>>,
}

/// Renders the template context as the body, so tests can read it back.
struct ContextRenderer;

impl EmailTemplateRenderer for ContextRenderer {
    fn render(
        &self,
        content: &EmailTemplateContent,
        context: &Value,
    ) -> Result<RenderedEmail, EmailTemplateRenderError> {
        Ok(RenderedEmail {
            subject: content.subject.clone(),
            html: context.to_string(),
        })
    }
}

fn settings(delivery: bool) -> Arc<SettingsSnapshot> {
    let mut snapshot = SettingsSnapshot::default().with_section(&AppSettings {
        login_domain: Some(LOGIN_DOMAIN.to_owned()),
        ..AppSettings::default()
    });
    if delivery {
        snapshot = snapshot.with_section(&EmailDeliverySettings {
            enabled: true,
            host: "smtp.example.com".to_owned(),
            sender_address: "identity@example.com".to_owned(),
            ..EmailDeliverySettings::default()
        });
    }
    Arc::new(snapshot)
}

struct Fixture {
    service: AccountService,
    users: Arc<MemoryUsers>,
    verifications: Arc<MemoryVerifications>,
    sender: Arc<RecordingSender>,
    account: User,
}

fn fixture_with(account: User, delivery: bool) -> Fixture {
    let users = Arc::new(MemoryUsers::default());
    users
        .users
        .lock()
        .unwrap()
        .insert(account.oid, account.clone());
    let verifications = Arc::new(MemoryVerifications::default());
    let sender = Arc::clone(&verifications.queued);
    let service =
        AccountService::new(users.clone()).with_email_verification(EmailVerificationDependencies {
            repository: verifications.clone(),
            renderer: Arc::new(ContextRenderer),
            settings: settings(delivery),
        });
    Fixture {
        service,
        users,
        verifications,
        sender,
        account,
    }
}

fn fixture(account: User) -> Fixture {
    fixture_with(account, true)
}

/// The link and other variables the message was rendered with.
fn sent_context(fixture: &Fixture) -> Value {
    let sent = fixture.sender.sent.lock().unwrap();
    serde_json::from_str(&sent.last().expect("an email was sent").html).unwrap()
}

#[tokio::test]
async fn a_new_address_is_verified_before_it_replaces_the_current_one() {
    let f = fixture(user("ada@example.com", true));

    let change = f
        .service
        .update_email(
            f.account.oid,
            " Ada.New@Example.com ",
            vec!["en-US".to_owned()],
        )
        .await
        .unwrap();

    let EmailChange::VerificationSent(sent) = change else {
        panic!("expected a verification link to be sent");
    };
    assert!(sent.verification.changes_email);
    let stored = f.users.users.lock().unwrap()[&f.account.oid].clone();
    assert_eq!(stored.email, "ada@example.com");
    assert!(stored.email_verified);

    let message = f.sender.sent.lock().unwrap()[0].clone();
    assert_eq!(message.to_address, "Ada.New@Example.com");
    let context = sent_context(&f);
    assert_eq!(context["email"], "Ada.New@Example.com");
    assert_eq!(context["changes_email"], true);
    assert_eq!(context["locale"], "zh-CN");

    // Only a digest of the emailed token is stored.
    let link = context["link"].as_str().unwrap();
    let token = link
        .strip_prefix(&format!("{LOGIN_DOMAIN}/verify-email?token="))
        .expect("link points at the Login confirmation page");
    let admitted = f.verifications.admitted.lock().unwrap()[0].clone();
    assert_eq!(admitted.email_normalized, "ada.new@example.com");
    assert_eq!(admitted.token_digest, link_digest(token));
    assert_ne!(admitted.token_digest, token);
}

#[tokio::test]
async fn without_email_delivery_the_address_changes_at_once_and_unverified() {
    let f = fixture_with(user("ada@example.com", true), false);

    let change = f
        .service
        .update_email(f.account.oid, "ada.new@example.com", Vec::new())
        .await
        .unwrap();

    let EmailChange::Changed(changed) = change else {
        panic!("expected the address to change at once");
    };
    assert_eq!(changed.email, "ada.new@example.com");
    assert!(!changed.email_verified);
    assert!(f.verifications.admitted.lock().unwrap().is_empty());
    assert!(f.sender.sent.lock().unwrap().is_empty());
}

#[tokio::test]
async fn keeping_the_current_address_withdraws_a_pending_change() {
    let f = fixture(user("ada@example.com", true));

    let change = f
        .service
        .update_email(f.account.oid, "ADA@example.com", Vec::new())
        .await
        .unwrap();

    assert!(matches!(change, EmailChange::Changed(_)));
    assert_eq!(*f.verifications.cancelled.lock().unwrap(), 1);
    assert!(f.verifications.admitted.lock().unwrap().is_empty());
    assert!(f.sender.sent.lock().unwrap().is_empty());
}

#[tokio::test]
async fn a_resend_goes_to_the_pending_new_address() {
    let f = fixture(user("ada@example.com", true));
    *f.verifications.pending.lock().unwrap() = Some(EmailVerification {
        oid: Uuid::new_v4(),
        user_oid: f.account.oid,
        email: "ada.new@example.com".to_owned(),
        email_normalized: "ada.new@example.com".to_owned(),
        changes_email: true,
        sent_at: Utc::now() - chrono::Duration::minutes(5),
        expires_at: Utc::now() + chrono::Duration::hours(23),
    });

    f.service
        .send_email_verification(f.account.oid, Vec::new())
        .await
        .unwrap();

    assert_eq!(
        f.sender.sent.lock().unwrap()[0].to_address,
        "ada.new@example.com"
    );
}

#[tokio::test]
async fn without_a_pending_change_the_current_address_is_verified() {
    let f = fixture(user("ada@example.com", false));

    let sent = f
        .service
        .send_email_verification(f.account.oid, Vec::new())
        .await
        .unwrap();

    assert!(!sent.verification.changes_email);
    assert_eq!(
        f.sender.sent.lock().unwrap()[0].to_address,
        "ada@example.com"
    );
    assert_eq!(sent_context(&f)["changes_email"], false);
}

#[tokio::test]
async fn refused_admissions_send_nothing_and_explain_why() {
    let now = Utc::now();
    let cases = [
        (
            EmailVerificationAdmission::TooSoon {
                available_at: now + chrono::Duration::seconds(42),
            },
            AccountErrorCode::EmailVerificationResendTooSoon,
        ),
        (
            EmailVerificationAdmission::LimitReached,
            AccountErrorCode::EmailVerificationLimitReached,
        ),
        (
            EmailVerificationAdmission::AlreadyVerified,
            AccountErrorCode::EmailAlreadyVerified,
        ),
        (
            EmailVerificationAdmission::EmailExists,
            AccountErrorCode::EmailExists,
        ),
    ];
    for (admission, expected) in cases {
        let f = fixture(user("ada@example.com", false));
        *f.verifications.admission.lock().unwrap() = Some(admission.clone());

        let error = f
            .service
            .send_email_verification(f.account.oid, Vec::new())
            .await
            .unwrap_err();

        assert_eq!(error.code(), expected.code(), "{admission:?}");
        assert!(f.sender.sent.lock().unwrap().is_empty());
        if matches!(admission, EmailVerificationAdmission::TooSoon { .. }) {
            let seconds: i64 = error.params().get("seconds").unwrap().parse().unwrap();
            assert!((41..=42).contains(&seconds));
        }
    }
}

#[tokio::test]
async fn nothing_is_sent_while_email_delivery_is_off() {
    let f = fixture_with(user("ada@example.com", false), false);

    let error = f
        .service
        .send_email_verification(f.account.oid, Vec::new())
        .await
        .unwrap_err();

    assert_eq!(
        error.code(),
        AccountErrorCode::EmailVerificationUnavailable.code()
    );
    assert!(f.verifications.admitted.lock().unwrap().is_empty());
}

#[tokio::test]
async fn a_link_is_confirmed_by_the_digest_of_its_token() {
    let f = fixture(user("ada@example.com", false));
    *f.verifications.outcome.lock().unwrap() = Some(EmailVerificationOutcome::Verified {
        user_oid: f.account.oid,
        email: "ada.new@example.com".to_owned(),
        changed: true,
    });
    let token = LinkToken::generate().token;

    let verified = f.service.confirm_email_verification(&token).await.unwrap();

    assert!(verified.changed);
    assert_eq!(verified.email, "ada.new@example.com");
    assert_eq!(
        f.verifications.confirmed.lock().unwrap().as_slice(),
        [link_digest(&token)]
    );
}

#[tokio::test]
async fn unusable_links_are_rejected() {
    let f = fixture(user("ada@example.com", false));

    for token in [
        "",
        "short",
        "not a token at all, with spaces and punctuation!",
    ] {
        let error = f
            .service
            .confirm_email_verification(token)
            .await
            .unwrap_err();
        assert_eq!(
            error.code(),
            AccountErrorCode::EmailVerificationInvalid.code()
        );
    }
    // Malformed tokens never reach the repository.
    assert!(f.verifications.confirmed.lock().unwrap().is_empty());

    let error = f
        .service
        .confirm_email_verification(&LinkToken::generate().token)
        .await
        .unwrap_err();
    assert_eq!(
        error.code(),
        AccountErrorCode::EmailVerificationInvalid.code()
    );

    *f.verifications.outcome.lock().unwrap() = Some(EmailVerificationOutcome::EmailExists);
    let error = f
        .service
        .confirm_email_verification(&LinkToken::generate().token)
        .await
        .unwrap_err();
    assert_eq!(error.code(), AccountErrorCode::EmailExists.code());
}
