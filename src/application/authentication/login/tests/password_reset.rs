//! Password reset: a link sent to the verified address replaces a forgotten
//! password from the password step of a login.
use identity_domain::auth::challenge::DeliveryChallengeState;
use serde_json::Value;

use super::{
    email::{MemoryChallenges, PlainProtector, RecordingSender},
    *,
};
use crate::{
    authentication::{
        challenge::ChallengeRepository,
        login::{LoginEmailDependencies, PasswordResetRequest},
    },
    email::{
        EmailSender, EmailTemplateContent, EmailTemplateRenderError, EmailTemplateRenderer,
        RenderedEmail,
    },
    setting::{
        BreachedPasswordCheckEnabledSetting, EmailDeliverySettings,
        IdentifierEnumerationAllowedSetting, PasswordResetEnabledSetting, SettingDefinition as _,
    },
};

const LINK_PREFIX: &str = "https://login.example.com/login/reset-password?login_id=x&token=";

/// Puts the link in the subject.
struct LinkRenderer;

impl EmailTemplateRenderer for LinkRenderer {
    fn render(
        &self,
        _content: &EmailTemplateContent,
        context: &Value,
    ) -> Result<RenderedEmail, EmailTemplateRenderError> {
        Ok(RenderedEmail {
            subject: context["link"].as_str().unwrap().to_owned(),
            html: String::new(),
        })
    }
}

/// Hashes as the recording hasher does; only `correct-password` matches the
/// stored password.
struct ResetHasher;

impl PasswordHasher for ResetHasher {
    fn hash(&self, password: &str, options: &HashOptions) -> Result<Password, PasswordHashError> {
        RecordingPasswordHasher.hash(password, options)
    }

    fn verify(
        &self,
        password: &str,
        stored: &Password,
        options: &HashOptions,
    ) -> Result<VerifyResult, PasswordHashError> {
        TestSignInHasher.verify(password, stored, options)
    }
}

struct ResetFlow {
    service: LoginService,
    credentials: Arc<TestCredentialRepo>,
    challenges: Arc<MemoryChallenges>,
    sender: Arc<RecordingSender>,
    login_oid: Uuid,
    user_oid: UserOid,
}

fn settings(enabled: bool, conceal: bool) -> Arc<SettingsSnapshot> {
    Arc::new(
        SettingsSnapshot::default()
            .with::<PasswordHashSetting>(PasswordHashSetting::default_value())
            .with::<PasswordResetEnabledSetting>(enabled)
            .with::<BreachedPasswordCheckEnabledSetting>(false)
            .with::<IdentifierEnumerationAllowedSetting>(!conceal)
            .with_section(&EmailDeliverySettings {
                enabled: true,
                host: "smtp.example.com".to_owned(),
                sender_address: "identity@example.com".to_owned(),
                ..EmailDeliverySettings::default()
            }),
    )
}

fn identified(user: &User) -> Login {
    Login {
        status: LoginStatus::IDENTIFIER_VERIFIED,
        ..test_login(user.oid.into(), 0)
    }
}

fn reset_flow(user: User, login: Login) -> ResetFlow {
    let login_oid = login.oid;
    let user_oid = user.oid;
    let login_repo = Arc::new(TestLoginRepo {
        state: Arc::new(Mutex::new(TestLoginRepoState {
            logins: vec![login],
            ..Default::default()
        })),
    });
    let challenges = Arc::new(MemoryChallenges::new(Arc::clone(&login_repo.state)));
    let (service, _) = otp_service(Arc::clone(&login_repo), user);
    let sender = Arc::new(RecordingSender::default());
    let mut service = service.with_email(LoginEmailDependencies {
        challenges: Arc::clone(&challenges) as Arc<dyn ChallengeRepository>,
        sender: Arc::clone(&sender) as Arc<dyn EmailSender>,
        renderer: Arc::new(LinkRenderer),
        protector: Arc::new(PlainProtector),
    });
    let credentials = Arc::new(TestCredentialRepo::new(sign_in_credentials(true)));
    service.credential_repo = Arc::clone(&credentials) as Arc<dyn UserCredentialRepository>;
    service.password_hasher = Arc::new(ResetHasher);
    service.settings = settings(true, false);
    ResetFlow {
        service,
        credentials,
        challenges,
        sender,
        login_oid,
        user_oid,
    }
}

impl ResetFlow {
    async fn send(&self) -> Result<crate::authentication::login::PasswordResetSent, AppError> {
        self.service
            .send_password_reset(PasswordResetRequest {
                login_oid: self.login_oid,
                locales: vec!["en-US".to_owned()],
                application_name: Some("Example".to_owned()),
                link_prefix: LINK_PREFIX.to_owned(),
            })
            .await
    }

    async fn reset(&self, token: &str, password: &str) -> Result<(), AppError> {
        self.service
            .reset_password(self.login_oid, token, password)
            .await
    }

    fn sent_token(&self) -> String {
        let sent = self.sender.sent.lock().unwrap();
        let link = &sent.last().expect("a reset email").subject;
        link.strip_prefix(LINK_PREFIX).unwrap().to_owned()
    }

    fn sent_count(&self) -> usize {
        self.sender.sent.lock().unwrap().len()
    }

    fn resets(&self) -> Vec<(UserUserOid, Uuid)> {
        self.credentials
            .resets
            .lock()
            .unwrap()
            .iter()
            .filter_map(|(user, replacement)| match replacement.kind {
                PasswordReplacementKind::Reset { login } => Some((*user, login)),
                _ => None,
            })
            .collect()
    }

    async fn offered(&self) -> bool {
        let login = self.service.get(self.login_oid).await.unwrap();
        self.service.password_reset_offered(&login).await.unwrap()
    }

    /// Allow the next send without waiting for the resend interval.
    fn forget_last_send(&self) {
        let mut stored = self.challenges.stored.lock().unwrap();
        for item in stored.values_mut() {
            if let Ok(mut state) =
                serde_json::from_value::<DeliveryChallengeState>(item.state.clone())
            {
                state.sent_at -= Duration::minutes(2);
                item.state = serde_json::to_value(state).unwrap();
            }
        }
    }
}

fn code(error: &AppError) -> u32 {
    error.code()
}

#[tokio::test]
async fn an_emailed_link_replaces_the_password_once() {
    let user = test_user();
    let flow = reset_flow(user.clone(), identified(&user));
    assert!(flow.offered().await);

    let sent = flow.send().await.unwrap();
    assert!(sent.expires_at > Utc::now() + Duration::minutes(14));
    let token = flow.sent_token();
    flow.service
        .check_password_reset_link(flow.login_oid, &token)
        .await
        .unwrap();

    flow.reset(&token, "a-new-sufficiently-long-password")
        .await
        .unwrap();
    assert_eq!(flow.resets(), vec![(flow.user_oid, flow.login_oid)]);

    let again = flow
        .reset(&token, "another-sufficiently-long-password")
        .await
        .unwrap_err();
    assert_eq!(code(&again), AuthErrorCode::PasswordResetLinkInvalid.code());
    assert_eq!(flow.resets().len(), 1);
}

#[tokio::test]
async fn a_rejected_new_password_keeps_the_link() {
    let user = test_user();
    let flow = reset_flow(user.clone(), identified(&user));
    flow.send().await.unwrap();
    let token = flow.sent_token();

    // The test hasher treats this as the current password.
    let error = flow.reset(&token, "correct-password").await.unwrap_err();
    assert_eq!(
        error.validation().unwrap().fields()[0].code(),
        AuthErrorCode::PasswordUnchanged.code()
    );
    let error = flow.reset(&token, "short").await.unwrap_err();
    assert!(!error.validation().unwrap().is_empty());

    flow.reset(&token, "a-new-sufficiently-long-password")
        .await
        .unwrap();
    assert_eq!(flow.resets().len(), 1);
}

#[tokio::test]
async fn a_wrong_or_replaced_link_is_refused() {
    let user = test_user();
    let flow = reset_flow(user.clone(), identified(&user));
    flow.send().await.unwrap();
    let first = flow.sent_token();

    let wrong = flow
        .reset("not-the-token", "a-new-sufficiently-long-password")
        .await
        .unwrap_err();
    assert_eq!(code(&wrong), AuthErrorCode::PasswordResetLinkInvalid.code());

    flow.forget_last_send();
    flow.send().await.unwrap();
    let replaced = flow
        .reset(&first, "a-new-sufficiently-long-password")
        .await
        .unwrap_err();
    assert_eq!(
        code(&replaced),
        AuthErrorCode::PasswordResetLinkInvalid.code()
    );
    flow.reset(&flow.sent_token(), "a-new-sufficiently-long-password")
        .await
        .unwrap();
}

#[tokio::test]
async fn another_email_waits_for_the_resend_interval() {
    let user = test_user();
    let flow = reset_flow(user.clone(), identified(&user));
    flow.send().await.unwrap();
    let error = flow.send().await.unwrap_err();
    assert_eq!(
        code(&error),
        AuthErrorCode::PasswordResetResendTooSoon.code()
    );
    assert_eq!(flow.sent_count(), 1);
    let login = flow.service.get(flow.login_oid).await.unwrap();
    assert!(
        flow.service
            .password_reset_resend_available_at(&login)
            .await
            .unwrap()
            .is_some()
    );
}

#[tokio::test]
async fn an_account_without_a_verified_address_is_not_offered_a_reset() {
    let user = User {
        email_verified: false,
        ..test_user()
    };
    let flow = reset_flow(user.clone(), identified(&user));
    assert!(!flow.offered().await);
    let error = flow.send().await.unwrap_err();
    assert_eq!(code(&error), AuthErrorCode::PasswordResetUnavailable.code());
    assert_eq!(flow.sent_count(), 0);
}

#[tokio::test]
async fn a_concealed_account_looks_the_same_whether_or_not_it_can_reset() {
    let user = User {
        email_verified: false,
        ..test_user()
    };
    let login = Login {
        submitted_identifier: Some("someone@example.com".to_owned()),
        ..identified(&user)
    };
    let mut flow = reset_flow(user, login);
    flow.service.settings = settings(true, true);
    assert!(flow.offered().await);

    let sent = flow.send().await.unwrap();
    assert!(sent.resend_available_at > Utc::now());
    tokio::task::yield_now().await;
    assert_eq!(flow.sent_count(), 0);
    let error = flow
        .reset("anything", "a-new-sufficiently-long-password")
        .await
        .unwrap_err();
    assert_eq!(code(&error), AuthErrorCode::PasswordResetLinkInvalid.code());
}

#[tokio::test]
async fn reset_is_not_offered_when_turned_off_or_from_a_session() {
    let user = test_user();
    let mut flow = reset_flow(user.clone(), identified(&user));
    flow.service.settings = settings(false, false);
    assert!(!flow.offered().await);
    let error = flow.send().await.unwrap_err();
    assert_eq!(code(&error), AuthErrorCode::PasswordResetUnavailable.code());

    let from_session = Login {
        session_oid: Some(SessionOid(Uuid::new_v4())),
        ..identified(&user)
    };
    let flow = reset_flow(user, from_session);
    assert!(!flow.offered().await);
}

#[tokio::test]
async fn a_lockout_from_failed_attempts_does_not_prevent_a_reset() {
    let user = User {
        locked: true,
        locked_until: Some(Utc::now() + Duration::minutes(10)),
        ..test_user()
    };
    let flow = reset_flow(user.clone(), identified(&user));
    assert!(flow.offered().await);
    flow.send().await.unwrap();
    flow.reset(&flow.sent_token(), "a-new-sufficiently-long-password")
        .await
        .unwrap();
    assert_eq!(flow.resets().len(), 1);

    let held = User {
        locked: true,
        locked_until: None,
        ..test_user()
    };
    let flow = reset_flow(held.clone(), identified(&held));
    assert!(!flow.offered().await);
}
