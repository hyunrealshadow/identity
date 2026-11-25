//! Self-registration: an emailed link verifies the address before the
//! account exists, and the page never reveals which addresses have one.
use identity_domain::auth::challenge::{
    AuthenticationChallenge, ChallengeBinding, ChallengePurpose,
};
use serde_json::Value;

use super::{
    email::{MemoryChallenges, PlainProtector, RecordingSender},
    *,
};
use crate::{
    authentication::{
        challenge::ChallengeRepository,
        login::{
            LoginEmailDependencies, NewAccount, RegistrationOutcome, RegistrationRepository,
            RegistrationRequest,
        },
    },
    email::{
        EmailSender, EmailTemplateContent, EmailTemplateRenderError, EmailTemplateRenderer,
        RenderedEmail,
    },
    setting::{
        BreachedPasswordCheckEnabledSetting, EmailDeliverySettings, RegistrationEnabledSetting,
        SettingDefinition as _,
    },
};

const LINK_PREFIX: &str = "https://login.example.com/login/register?login_id=x&token=";
const EXISTING_EMAIL: &str = "taken@example.com";

/// Puts the link (empty when none was sent) in the subject and whether the
/// address had an account in the body.
struct LinkRenderer;

impl EmailTemplateRenderer for LinkRenderer {
    fn render(
        &self,
        _content: &EmailTemplateContent,
        context: &Value,
    ) -> Result<RenderedEmail, EmailTemplateRenderError> {
        Ok(RenderedEmail {
            subject: context["link"].as_str().unwrap_or_default().to_owned(),
            html: context["account_exists"].to_string(),
        })
    }
}

struct CreatedAccount {
    username: String,
    email: String,
    password_hash: String,
}

/// Registration persistence over the in-memory challenges and logins.
struct MemoryRegistrations {
    challenges: Arc<MemoryChallenges>,
    logins: Arc<Mutex<TestLoginRepoState>>,
    usernames: Vec<String>,
    created: Mutex<Vec<CreatedAccount>>,
}

#[async_trait]
impl RegistrationRepository for MemoryRegistrations {
    async fn email_registered(&self, email_normalized: &str) -> Result<bool, AppError> {
        Ok(email_normalized == EXISTING_EMAIL
            || self
                .created
                .lock()
                .unwrap()
                .iter()
                .any(|account| account.email == email_normalized))
    }

    async fn latest(&self, login_oid: Uuid) -> Result<Option<AuthenticationChallenge>, AppError> {
        Ok(self
            .challenges
            .stored
            .lock()
            .unwrap()
            .iter()
            .find(|(_, item)| {
                item.binding == ChallengeBinding::Login(login_oid)
                    && item.purpose == ChallengePurpose::Registration
                    && item.expires_at > Utc::now()
            })
            .map(|(id, item)| AuthenticationChallenge {
                id: *id,
                state: item.state.clone(),
                expires_at: item.expires_at,
            }))
    }

    async fn register(&self, account: NewAccount) -> Result<RegistrationOutcome, AppError> {
        if self.usernames.contains(&account.username_normalized)
            || self
                .created
                .lock()
                .unwrap()
                .iter()
                .any(|created| created.username == account.username_normalized)
        {
            return Ok(RegistrationOutcome::UsernameExists);
        }
        if self
            .challenges
            .stored
            .lock()
            .unwrap()
            .remove(&account.challenge_oid)
            .is_none()
        {
            return Ok(RegistrationOutcome::LinkInvalid);
        }
        let mut logins = self.logins.lock().unwrap();
        let Some(login) = logins
            .logins
            .iter_mut()
            .find(|login| login.oid == account.login_oid && login.status == LoginStatus::CREATED)
        else {
            return Ok(RegistrationOutcome::LinkInvalid);
        };
        login.user_oid = Some(Uuid::new_v4());
        login.status = LoginStatus::IDENTIFIER_VERIFIED;
        let Password::Argon2(hash) = account.password;
        self.created.lock().unwrap().push(CreatedAccount {
            username: account.username_normalized,
            email: account.email_normalized,
            password_hash: hash.hash,
        });
        Ok(RegistrationOutcome::Registered)
    }
}

struct RegistrationFlow {
    service: LoginService,
    registrations: Arc<MemoryRegistrations>,
    logins: Arc<Mutex<TestLoginRepoState>>,
    sender: Arc<RecordingSender>,
    login_oid: Uuid,
}

fn settings(enabled: bool) -> Arc<SettingsSnapshot> {
    Arc::new(
        SettingsSnapshot::default()
            .with::<PasswordHashSetting>(PasswordHashSetting::default_value())
            .with::<RegistrationEnabledSetting>(enabled)
            .with::<BreachedPasswordCheckEnabledSetting>(false)
            .with_section(&EmailDeliverySettings {
                enabled: true,
                host: "smtp.example.com".to_owned(),
                sender_address: "identity@example.com".to_owned(),
                ..EmailDeliverySettings::default()
            }),
    )
}

/// A login waiting at its identifier step.
fn fresh_login() -> Login {
    Login {
        user_oid: None,
        status: LoginStatus::CREATED,
        ..test_login(Uuid::new_v4(), 0)
    }
}

fn registration_flow(enabled: bool) -> RegistrationFlow {
    let login = fresh_login();
    let login_oid = login.oid;
    let login_repo = Arc::new(TestLoginRepo {
        state: Arc::new(Mutex::new(TestLoginRepoState {
            logins: vec![login],
            ..Default::default()
        })),
    });
    let logins = Arc::clone(&login_repo.state);
    let challenges = Arc::new(MemoryChallenges::new(Arc::clone(&logins)));
    let (service, _) = otp_service(Arc::clone(&login_repo), test_user());
    let sender = Arc::new(RecordingSender::default());
    let registrations = Arc::new(MemoryRegistrations {
        challenges: Arc::clone(&challenges),
        logins: Arc::clone(&logins),
        usernames: vec!["taken-name".to_owned()],
        created: Mutex::new(Vec::new()),
    });
    let mut service = service
        .with_email(LoginEmailDependencies {
            challenges: Arc::clone(&challenges) as Arc<dyn ChallengeRepository>,
            sender: Arc::clone(&sender) as Arc<dyn EmailSender>,
            renderer: Arc::new(LinkRenderer),
            protector: Arc::new(PlainProtector),
        })
        .with_registration(Arc::clone(&registrations) as Arc<dyn RegistrationRepository>);
    service.password_hasher = Arc::new(RecordingPasswordHasher);
    service.settings = settings(enabled);
    RegistrationFlow {
        service,
        registrations,
        logins,
        sender,
        login_oid,
    }
}

impl RegistrationFlow {
    fn login(&self) -> Login {
        self.logins
            .lock()
            .unwrap()
            .logins
            .iter()
            .find(|login| login.oid == self.login_oid)
            .cloned()
            .unwrap()
    }

    async fn send(
        &self,
        email: &str,
    ) -> Result<crate::authentication::login::RegistrationSent, AppError> {
        self.service
            .send_registration(RegistrationRequest {
                login_oid: self.login_oid,
                email: email.to_owned(),
                locales: vec!["en".to_owned()],
                application_name: None,
                link_prefix: LINK_PREFIX.to_owned(),
            })
            .await
    }

    /// The emails sent so far, once the background delivery ran.
    async fn delivered(&self, expected: usize) -> Vec<(String, String, String)> {
        for _ in 0..50 {
            if self.sender.sent.lock().unwrap().len() >= expected {
                break;
            }
            tokio::task::yield_now().await;
        }
        self.sender
            .sent
            .lock()
            .unwrap()
            .iter()
            .map(|message| {
                (
                    message.to_address.clone(),
                    message.subject.clone(),
                    message.html.clone(),
                )
            })
            .collect()
    }

    async fn token(&self) -> String {
        let sent = self.delivered(1).await;
        sent.last()
            .unwrap()
            .1
            .strip_prefix(LINK_PREFIX)
            .unwrap()
            .to_owned()
    }

    fn created_count(&self) -> usize {
        self.registrations.created.lock().unwrap().len()
    }
}

fn code(error: &AppError) -> u32 {
    error.code()
}

fn field_code(error: &AppError, field: &str) -> Option<u32> {
    error
        .validation()?
        .fields()
        .iter()
        .find(|error| error.field() == field)
        .map(|error| error.code())
}

#[tokio::test]
async fn registration_is_offered_only_while_turned_on() {
    let off = registration_flow(false);
    assert!(!off.service.registration_offered(&off.login()));
    let error = off.send("new@example.com").await.unwrap_err();
    assert_eq!(code(&error), AuthErrorCode::RegistrationUnavailable.code());

    let on = registration_flow(true);
    assert!(on.service.registration_offered(&on.login()));
}

#[tokio::test]
async fn a_new_address_gets_a_link_that_creates_a_verified_account_once() {
    let flow = registration_flow(true);
    flow.send("New.Person@Example.com").await.unwrap();
    let token = flow.token().await;
    let link = flow
        .service
        .check_registration_link(flow.login_oid, &token)
        .await
        .unwrap();
    assert_eq!(link.email, "New.Person@Example.com");
    assert!(
        flow.service
            .registration_resend_available_at(&flow.login())
            .await
            .unwrap()
            .is_some()
    );

    flow.service
        .complete_registration(
            flow.login_oid,
            &token,
            "new-person",
            "a-new-sufficiently-long-password",
        )
        .await
        .unwrap();
    {
        let created = flow.registrations.created.lock().unwrap();
        assert_eq!(created.len(), 1);
        assert_eq!(created[0].username, "new-person");
        assert_eq!(created[0].email, "new.person@example.com");
        assert_eq!(created[0].password_hash, "a-new-sufficiently-long-password");
    }
    // The login continues at its password step with the new account.
    let login = flow.login();
    assert_eq!(login.status, LoginStatus::IDENTIFIER_VERIFIED);
    assert!(login.user_oid.is_some());

    let error = flow
        .service
        .complete_registration(
            flow.login_oid,
            &token,
            "someone-else",
            "a-new-sufficiently-long-password",
        )
        .await
        .unwrap_err();
    assert_eq!(code(&error), AuthErrorCode::RegistrationLinkInvalid.code());
    assert_eq!(flow.created_count(), 1);
}

#[tokio::test]
async fn a_registered_address_gets_a_notice_and_the_same_answer() {
    let fresh = registration_flow(true);
    let new_answer = fresh.send("new@example.com").await.unwrap();
    let taken = registration_flow(true);
    let taken_answer = taken.send(EXISTING_EMAIL).await.unwrap();
    assert_eq!(
        taken_answer.resend_available_at - taken_answer.expires_at,
        new_answer.resend_available_at - new_answer.expires_at
    );

    let sent = taken.delivered(1).await;
    assert_eq!(sent.len(), 1);
    assert_eq!(sent[0].0, EXISTING_EMAIL);
    assert_eq!(sent[0].1, "", "no link goes to an address with an account");
    assert_eq!(sent[0].2, "true");
    // Nothing can be completed for it.
    let error = taken
        .service
        .check_registration_link(taken.login_oid, "guess")
        .await
        .unwrap_err();
    assert_eq!(code(&error), AuthErrorCode::RegistrationLinkInvalid.code());
}

#[tokio::test]
async fn a_rejected_username_or_password_keeps_the_link_usable() {
    let flow = registration_flow(true);
    flow.send("fresh.person@example.com").await.unwrap();
    let token = flow.token().await;

    let error = flow
        .service
        .complete_registration(flow.login_oid, &token, "new-person", "short")
        .await
        .unwrap_err();
    assert_eq!(
        field_code(&error, "newPassword"),
        Some(AuthErrorCode::PasswordTooShort.code())
    );
    let error = flow
        .service
        .complete_registration(
            flow.login_oid,
            &token,
            "taken-name",
            "a-new-sufficiently-long-password",
        )
        .await
        .unwrap_err();
    assert_eq!(
        field_code(&error, "username"),
        Some(crate::error::codes::account::AccountErrorCode::UsernameExists.code())
    );
    assert_eq!(flow.created_count(), 0);

    flow.service
        .complete_registration(
            flow.login_oid,
            &token,
            "new-person",
            "a-new-sufficiently-long-password",
        )
        .await
        .unwrap();
    assert_eq!(flow.created_count(), 1);
}

#[tokio::test]
async fn another_email_waits_for_the_resend_interval() {
    let flow = registration_flow(true);
    flow.send("new@example.com").await.unwrap();
    let error = flow.send("other@example.com").await.unwrap_err();
    assert_eq!(
        code(&error),
        AuthErrorCode::RegistrationResendTooSoon.code()
    );
}

#[tokio::test]
async fn an_invalid_address_is_a_field_error() {
    let flow = registration_flow(true);
    let error = flow.send("not-an-address").await.unwrap_err();
    assert_eq!(
        field_code(&error, "email"),
        Some(crate::error::codes::account::AccountErrorCode::EmailInvalid.code())
    );
    assert_eq!(flow.delivered(0).await.len(), 0);
}
