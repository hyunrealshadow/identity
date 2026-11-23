//! Email sign-in: a code or link sent to the verified address as the first factor.
use std::collections::HashMap;

use identity_domain::{
    auth::{
        AMR_EMAIL, MAX_EMAIL_CODE_SENDS,
        challenge::{
            AuthenticationChallenge, ChallengeBinding, ChallengeContext, ChallengeMethod,
            ChallengePurpose, DeliveryChallengeAdmission, DeliveryChallengeContext,
            DeliveryChallengeRequest, DeliveryChallengeState, DeliveryChallengeStatus,
        },
    },
    data_protection::DataProtectionError,
};
use serde_json::Value;

use super::*;
use crate::{
    authentication::{
        challenge::ChallengeRepository,
        login::{LoginEmailDependencies, challenge_credential_types},
    },
    data_protection::DataProtector,
    email::{
        EmailDeliveryError, EmailMessage, EmailSender, EmailTemplateContent,
        EmailTemplateRenderError, EmailTemplateRenderer, RenderedEmail,
    },
    setting::{
        EmailDeliverySettings, EmailSignInEnabledSetting, IdentifierEnumerationAllowedSetting,
        SettingDefinition as _,
    },
};

struct StoredMemoryChallenge {
    user_oid: Option<Uuid>,
    binding: ChallengeBinding,
    method: ChallengeMethod,
    purpose: ChallengePurpose,
    state: Value,
    expires_at: DateTime<Utc>,
}

struct MemoryChallenges {
    logins: Arc<Mutex<TestLoginRepoState>>,
    stored: Mutex<HashMap<Uuid, StoredMemoryChallenge>>,
    order: Mutex<Vec<Uuid>>,
}

impl MemoryChallenges {
    fn new(logins: Arc<Mutex<TestLoginRepoState>>) -> Self {
        Self {
            logins,
            stored: Mutex::new(HashMap::new()),
            order: Mutex::new(Vec::new()),
        }
    }
}

#[async_trait]
impl ChallengeRepository for MemoryChallenges {
    async fn store(
        &self,
        context: ChallengeContext,
        challenge: AuthenticationChallenge,
    ) -> Result<(), AppError> {
        self.order.lock().unwrap().push(challenge.id);
        self.stored.lock().unwrap().insert(
            challenge.id,
            StoredMemoryChallenge {
                user_oid: Some(context.user_oid),
                binding: context.binding,
                method: context.method,
                purpose: context.purpose,
                state: challenge.state,
                expires_at: challenge.expires_at,
            },
        );
        Ok(())
    }

    async fn admit_delivery(
        &self,
        context: DeliveryChallengeContext,
        request: DeliveryChallengeRequest,
    ) -> Result<DeliveryChallengeAdmission, AppError> {
        let ChallengeBinding::Login(login_oid) = context.binding else {
            return Ok(DeliveryChallengeAdmission::InvalidState);
        };
        let mut logins = self.logins.lock().unwrap();
        let Some(login) = logins
            .logins
            .iter_mut()
            .find(|login| login.oid == login_oid)
        else {
            return Ok(DeliveryChallengeAdmission::InvalidState);
        };
        let status_ok = match request.required_login_status {
            Some(required) => login.status == required,
            None => matches!(
                login.status,
                LoginStatus::IDENTIFIER_VERIFIED
                    | LoginStatus::MFA_REQUIRED
                    | LoginStatus::MFA_ENROLLMENT_REQUIRED
            ),
        };
        if !status_ok || login.user_oid != context.user_oid || login.expires_at <= request.now {
            return Ok(DeliveryChallengeAdmission::InvalidState);
        }

        let mut stored = self.stored.lock().unwrap();
        let mut order = self.order.lock().unwrap();
        let existing_id = order.iter().rev().copied().find(|id| {
            stored.get(id).is_some_and(|item| {
                item.binding == context.binding
                    && item.method == context.method
                    && item.purpose == context.purpose
            })
        });
        let interval =
            Duration::from_std(request.resend_interval).unwrap_or_else(|_| Duration::seconds(60));
        let prev_count = if let Some(id) = existing_id {
            let item = stored.get(&id).unwrap();
            let state: DeliveryChallengeState = serde_json::from_value(item.state.clone()).unwrap();
            if state.send_count >= request.max_sends {
                return Ok(DeliveryChallengeAdmission::LimitReached);
            }
            let available_at = state.sent_at + interval;
            if available_at > request.now {
                return Ok(DeliveryChallengeAdmission::TooSoon { available_at });
            }
            state.send_count
        } else {
            0
        };

        let send_count = prev_count + 1;
        login.expires_at = login.expires_at.max(request.code_expires_at);
        let row_expires_at = login.expires_at;
        drop(logins);

        if let Some(old_id) = existing_id {
            stored.remove(&old_id);
        }
        let new_id = Uuid::new_v4();
        let state = serde_json::to_value(DeliveryChallengeState {
            sent_at: request.now,
            send_count,
            code_expires_at: request.code_expires_at,
            verifier: request.verifier,
        })
        .unwrap();
        order.push(new_id);
        stored.insert(
            new_id,
            StoredMemoryChallenge {
                user_oid: context.user_oid,
                binding: context.binding,
                method: context.method,
                purpose: context.purpose,
                state,
                expires_at: row_expires_at,
            },
        );
        Ok(DeliveryChallengeAdmission::Admitted {
            sent_at: request.now,
            send_count,
            resend_available_at: request.now + interval,
        })
    }

    async fn delivery_status(
        &self,
        binding: ChallengeBinding,
        method: ChallengeMethod,
        purpose: ChallengePurpose,
    ) -> Result<Option<DeliveryChallengeStatus>, AppError> {
        let ChallengeBinding::Login(login_oid) = binding else {
            return Ok(None);
        };
        let active = self.logins.lock().unwrap().logins.iter().any(|login| {
            login.oid == login_oid
                && matches!(
                    login.status,
                    LoginStatus::IDENTIFIER_VERIFIED
                        | LoginStatus::MFA_REQUIRED
                        | LoginStatus::MFA_ENROLLMENT_REQUIRED
                )
                && login.expires_at > Utc::now()
        });
        if !active {
            return Ok(None);
        }
        let stored = self.stored.lock().unwrap();
        let order = self.order.lock().unwrap();
        let Some(item) = order.iter().rev().find_map(|id| {
            stored.get(id).filter(|item| {
                item.binding == binding
                    && item.method == method
                    && item.purpose == purpose
                    && item.expires_at > Utc::now()
            })
        }) else {
            return Ok(None);
        };
        let state: DeliveryChallengeState = serde_json::from_value(item.state.clone()).unwrap();
        Ok(Some(DeliveryChallengeStatus {
            sent_at: state.sent_at,
            send_count: state.send_count,
        }))
    }

    async fn take(
        &self,
        context: ChallengeContext,
        id: Uuid,
    ) -> Result<Option<AuthenticationChallenge>, AppError> {
        let mut stored = self.stored.lock().unwrap();
        let matches = stored.get(&id).is_some_and(|item| {
            item.user_oid == Some(context.user_oid)
                && item.binding == context.binding
                && item.method == context.method
                && item.purpose == context.purpose
                && item.expires_at > Utc::now()
        });
        if matches {
            Ok(stored.remove(&id).map(|item| AuthenticationChallenge {
                id,
                state: item.state,
                expires_at: item.expires_at,
            }))
        } else {
            Ok(None)
        }
    }

    async fn latest(
        &self,
        context: ChallengeContext,
    ) -> Result<Option<AuthenticationChallenge>, AppError> {
        let stored = self.stored.lock().unwrap();
        Ok(self.order.lock().unwrap().iter().rev().find_map(|id| {
            let item = stored.get(id)?;
            (item.user_oid == Some(context.user_oid)
                && item.binding == context.binding
                && item.method == context.method
                && item.purpose == context.purpose
                && item.expires_at > Utc::now())
            .then(|| AuthenticationChallenge {
                id: *id,
                state: item.state.clone(),
                expires_at: item.expires_at,
            })
        }))
    }
}

/// Records what would be sent; the body carries the rendered context.
#[derive(Default)]
struct RecordingSender {
    sent: Mutex<Vec<EmailMessage>>,
}

#[async_trait]
impl EmailSender for RecordingSender {
    async fn send(
        &self,
        _settings: &EmailDeliverySettings,
        message: EmailMessage,
    ) -> Result<(), EmailDeliveryError> {
        self.sent.lock().unwrap().push(message);
        Ok(())
    }
}

/// Puts the code in the subject and the link in the body.
struct ContextRenderer;

impl EmailTemplateRenderer for ContextRenderer {
    fn render(
        &self,
        _content: &EmailTemplateContent,
        context: &Value,
    ) -> Result<RenderedEmail, EmailTemplateRenderError> {
        Ok(RenderedEmail {
            subject: context["code"].as_str().unwrap().to_owned(),
            html: context["link"].as_str().unwrap().to_owned(),
        })
    }
}

struct PlainProtector;

#[async_trait]
impl DataProtector for PlainProtector {
    async fn protect(
        &self,
        purpose: &str,
        plaintext: &[u8],
    ) -> Result<String, DataProtectionError> {
        Ok(format!("{purpose}:{}", String::from_utf8_lossy(plaintext)))
    }

    async fn unprotect(&self, purpose: &str, token: &str) -> Result<Vec<u8>, DataProtectionError> {
        token
            .strip_prefix(&format!("{purpose}:"))
            .map(|plain| plain.as_bytes().to_vec())
            .ok_or(DataProtectionError::InvalidProtectedPayload)
    }
}

const LINK_PREFIX: &str = "https://login.example.com/login/email?login_id=x&token=";

struct EmailFlow {
    service: LoginService,
    login_repo: Arc<TestLoginRepo>,
    challenges: Arc<MemoryChallenges>,
    sender: Arc<RecordingSender>,
    login_oid: Uuid,
}

fn settings(enabled: bool, conceal: bool) -> Arc<SettingsSnapshot> {
    Arc::new(
        SettingsSnapshot::default()
            .with::<PasswordHashSetting>(PasswordHashSetting::default_value())
            .with::<EmailSignInEnabledSetting>(enabled)
            .with::<IdentifierEnumerationAllowedSetting>(!conceal)
            .with_section(&EmailDeliverySettings {
                enabled: true,
                host: "smtp.example.com".to_owned(),
                sender_address: "identity@example.com".to_owned(),
                ..EmailDeliverySettings::default()
            }),
    )
}

fn email_flow(user: User, mfa: bool, login: Login) -> EmailFlow {
    let login_oid = login.oid;
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
        renderer: Arc::new(ContextRenderer),
        protector: Arc::new(PlainProtector),
    });
    service.credential_repo = Arc::new(TestCredentialRepo::new(sign_in_credentials(mfa)));
    service.password_hasher = Arc::new(TestSignInHasher);
    service.settings = settings(true, false);
    EmailFlow {
        service,
        login_repo,
        challenges,
        sender,
        login_oid,
    }
}

fn identified(user: &User) -> Login {
    Login {
        status: LoginStatus::IDENTIFIER_VERIFIED,
        ..test_login(user.oid.into(), 0)
    }
}

impl EmailFlow {
    async fn send(&self) -> Result<crate::authentication::login::EmailCodeSent, AppError> {
        self.service
            .send_email_code(crate::authentication::login::EmailCodeRequest {
                login_oid: self.login_oid,
                locales: vec!["en-US".to_owned()],
                application_name: Some("Example".to_owned()),
                link_prefix: LINK_PREFIX.to_owned(),
            })
            .await
    }

    async fn verify(&self, credential: &str) -> Result<ChallengeOutcome, AppError> {
        self.service
            .challenge(
                self.login_oid,
                CredentialType::EmailOtp,
                credential,
                SessionContext::default(),
            )
            .await
    }

    fn last_message(&self) -> EmailMessage {
        self.sender.sent.lock().unwrap().last().cloned().unwrap()
    }

    fn login(&self) -> Login {
        self.login_repo.state.lock().unwrap().logins[0].clone()
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

#[tokio::test]
async fn an_emailed_code_signs_in_as_the_first_factor() {
    let user = test_user();
    let flow = email_flow(user.clone(), false, identified(&user));
    assert_eq!(
        flow.service
            .email_code_resend_available_at(&flow.login())
            .await
            .unwrap(),
        None
    );

    let sent = flow.send().await.expect("the email is sent");
    let message = flow.last_message();
    assert_eq!(message.to_address, user.email);
    assert!(sent.expires_at > Utc::now() + Duration::minutes(9));
    assert!(
        flow.login().expires_at >= sent.expires_at,
        "the login lasts as long as the code"
    );
    assert_eq!(
        flow.service
            .email_code_resend_available_at(&flow.login())
            .await
            .unwrap(),
        Some(sent.resend_available_at)
    );

    match flow
        .verify(&message.subject)
        .await
        .expect("the code signs in")
    {
        ChallengeOutcome::Authenticated { .. } => {}
        other => panic!("expected authentication, got {other:?}"),
    }
    assert_eq!(flow.login().amr, vec![AMR_EMAIL.to_owned()]);
}

#[tokio::test]
async fn the_emailed_link_works_once() {
    let user = test_user();
    let flow = email_flow(user.clone(), true, identified(&user));
    flow.send().await.unwrap();
    let token = flow
        .last_message()
        .html
        .strip_prefix(LINK_PREFIX)
        .unwrap()
        .to_owned();

    // An enrolled second factor is still required after the email.
    assert!(matches!(
        flow.verify(&token).await.unwrap(),
        ChallengeOutcome::MfaRequired { .. }
    ));

    let mut login = flow.login();
    login.status = LoginStatus::IDENTIFIER_VERIFIED;
    flow.login_repo.state.lock().unwrap().logins[0] = login;
    assert_error_code(
        flow.verify(&token).await.unwrap_err(),
        AuthErrorCode::InvalidOtp,
    );
}

#[tokio::test]
async fn a_resend_replaces_the_code_and_respects_the_interval_and_limit() {
    let user = test_user();
    let flow = email_flow(user.clone(), false, identified(&user));
    flow.send().await.unwrap();
    let first = flow.last_message().subject;

    let too_soon = flow.send().await.unwrap_err();
    assert_error_code(too_soon, AuthErrorCode::EmailCodeResendTooSoon);

    flow.forget_last_send();
    flow.send().await.unwrap();
    let second = flow.last_message().subject;
    if first != second {
        assert_error_code(
            flow.verify(&first).await.unwrap_err(),
            AuthErrorCode::InvalidOtp,
        );
    }

    for _ in 2..MAX_EMAIL_CODE_SENDS {
        flow.forget_last_send();
        flow.send().await.unwrap();
    }
    flow.forget_last_send();
    assert_error_code(
        flow.send().await.unwrap_err(),
        AuthErrorCode::TooManyAttempts,
    );
}

#[tokio::test]
async fn wrong_codes_end_the_login_after_the_attempt_limit() {
    let user = test_user();
    let flow = email_flow(user.clone(), false, identified(&user));
    flow.send().await.unwrap();
    for _ in 1..MAX_OTP_ATTEMPTS {
        assert_error_code(
            flow.verify("000000").await.unwrap_err(),
            AuthErrorCode::InvalidOtp,
        );
    }
    assert_error_code(
        flow.verify("000000").await.unwrap_err(),
        AuthErrorCode::TooManyAttempts,
    );
    assert_eq!(flow.login().status, LoginStatus::FAILED);
}

#[tokio::test]
async fn only_a_verified_address_is_offered_and_only_before_the_second_factor() {
    let mut unverified = test_user();
    unverified.email_verified = false;
    let flow = email_flow(unverified.clone(), false, identified(&unverified));
    let types = flow.service.credential_types(unverified.oid).await.unwrap();
    assert!(!types.contains(&CredentialType::EmailOtp));
    assert_error_code(
        flow.send().await.unwrap_err(),
        AuthErrorCode::CredentialTypeUnsupported,
    );
    assert!(flow.sender.sent.lock().unwrap().is_empty());

    let user = test_user();
    let flow = email_flow(user.clone(), true, identified(&user));
    let types = flow.service.credential_types(user.oid).await.unwrap();
    assert!(types.contains(&CredentialType::EmailOtp));
    let first_factor = challenge_credential_types(&identified(&user), &types);
    assert!(first_factor.contains(&CredentialType::EmailOtp));
    let second_factor = challenge_credential_types(&test_login(user.oid.into(), 0), &types);
    assert!(!second_factor.contains(&CredentialType::EmailOtp));
}

#[tokio::test]
async fn email_sign_in_is_not_offered_while_turned_off() {
    let user = test_user();
    let mut flow = email_flow(user.clone(), false, identified(&user));
    flow.service.settings = settings(false, false);
    let types = flow.service.credential_types(user.oid).await.unwrap();
    assert!(!types.contains(&CredentialType::EmailOtp));
    assert_error_code(
        flow.send().await.unwrap_err(),
        AuthErrorCode::CredentialTypeUnsupported,
    );
}

#[tokio::test]
async fn a_concealed_unknown_identifier_is_answered_like_a_real_account() {
    let user = test_user();
    let login = Login {
        user_oid: None,
        status: LoginStatus::IDENTIFIER_VERIFIED,
        submitted_identifier: Some(UNKNOWN_IDENTIFIER.to_owned()),
        ..test_login(Uuid::nil(), 0)
    };
    let mut flow = email_flow(user, false, login);
    flow.service.settings = settings(true, true);
    assert_eq!(
        flow.service.concealed_credential_types(),
        vec![CredentialType::Password, CredentialType::EmailOtp]
    );

    let sent = flow
        .send()
        .await
        .expect("the answer does not reveal the missing account");
    assert_eq!(
        flow.service
            .email_code_resend_available_at(&flow.login())
            .await
            .unwrap(),
        Some(sent.resend_available_at)
    );
    assert!(flow.sender.sent.lock().unwrap().is_empty());
    assert_error_code(
        flow.send().await.unwrap_err(),
        AuthErrorCode::EmailCodeResendTooSoon,
    );
    assert_error_code(
        flow.verify("123456").await.unwrap_err(),
        AuthErrorCode::InvalidOtp,
    );
}

#[tokio::test]
async fn an_expired_email_code_is_rejected_even_while_the_login_is_alive() {
    let user = test_user();
    let mut login = identified(&user);
    login.expires_at = Utc::now() + Duration::minutes(30);
    let flow = email_flow(user, false, login);
    flow.send().await.unwrap();
    let code = flow.last_message().subject;

    {
        let mut stored = flow.challenges.stored.lock().unwrap();
        for item in stored.values_mut() {
            let mut state: DeliveryChallengeState =
                serde_json::from_value(item.state.clone()).unwrap();
            state.code_expires_at = Utc::now() - Duration::seconds(1);
            item.state = serde_json::to_value(state).unwrap();
        }
    }

    assert_error_code(
        flow.verify(&code).await.unwrap_err(),
        AuthErrorCode::InvalidOtp,
    );
}
