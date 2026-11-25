//! A sign-in held at a required password change, password expiry, and the
//! recent-password check.
use super::*;
use crate::setting::{
    BreachedPasswordCheckEnabledSetting, PasswordHistoryCountSetting, PasswordMaxAgeDaysSetting,
    SettingDefinition as _,
};
use identity_domain::user::RequiredAction;

/// `correct-password` matches the stored password; a password recorded by
/// [`RecordingPasswordHasher`] matches itself.
struct PolicyHasher;

impl PasswordHasher for PolicyHasher {
    fn hash(&self, password: &str, options: &HashOptions) -> Result<Password, PasswordHashError> {
        RecordingPasswordHasher.hash(password, options)
    }

    fn verify(
        &self,
        password: &str,
        stored: &Password,
        _options: &HashOptions,
    ) -> Result<VerifyResult, PasswordHashError> {
        let Password::Argon2(stored) = stored;
        let matches = stored.hash == password
            || (stored.hash == "stored-hash" && password == "correct-password");
        Ok(if matches {
            VerifyResult::Success
        } else {
            VerifyResult::Failure
        })
    }
}

struct PolicyFlow {
    service: LoginService,
    credentials: Arc<TestCredentialRepo>,
    login_repo: Arc<TestLoginRepo>,
    login_oid: Uuid,
}

fn policy_flow(user: User, max_age_days: u32, history_count: u32) -> PolicyFlow {
    let login = Login {
        status: LoginStatus::IDENTIFIER_VERIFIED,
        ..test_login(user.oid.into(), 0)
    };
    let login_oid = login.oid;
    let login_repo = Arc::new(TestLoginRepo {
        state: Arc::new(Mutex::new(TestLoginRepoState {
            logins: vec![login],
            ..Default::default()
        })),
    });
    let (mut service, _) = otp_service(Arc::clone(&login_repo), user);
    let credentials = Arc::new(TestCredentialRepo::new(sign_in_credentials(false)));
    service.credential_repo = Arc::clone(&credentials) as Arc<dyn UserCredentialRepository>;
    service.password_hasher = Arc::new(PolicyHasher);
    service.settings = Arc::new(
        SettingsSnapshot::default()
            .with::<PasswordHashSetting>(PasswordHashSetting::default_value())
            .with::<BreachedPasswordCheckEnabledSetting>(false)
            .with::<PasswordMaxAgeDaysSetting>(max_age_days)
            .with::<PasswordHistoryCountSetting>(history_count),
    );
    PolicyFlow {
        service,
        credentials,
        login_repo,
        login_oid,
    }
}

impl PolicyFlow {
    async fn sign_in(&self) -> ChallengeOutcome {
        self.service
            .challenge(
                self.login_oid,
                CredentialType::Password,
                "correct-password",
                SessionContext::default(),
            )
            .await
            .unwrap()
    }

    async fn change(&self, password: &str) -> Result<ChallengeOutcome, AppError> {
        self.service
            .complete_required_password_change(self.login_oid, password, SessionContext::default())
            .await
    }

    fn login(&self) -> Login {
        self.login_repo.state.lock().unwrap().logins[0].clone()
    }

    fn replacements(&self) -> Vec<PasswordReplacement> {
        self.credentials
            .resets
            .lock()
            .unwrap()
            .iter()
            .map(|(_, replacement)| *replacement)
            .collect()
    }
}

fn required_user() -> User {
    User {
        required_actions: [RequiredAction::ChangePassword].into(),
        ..test_user()
    }
}

#[tokio::test]
async fn a_required_change_holds_the_sign_in_until_the_password_is_replaced() {
    let flow = policy_flow(required_user(), 0, 0);
    assert!(matches!(
        flow.sign_in().await,
        ChallengeOutcome::PasswordChangeRequired { .. }
    ));
    let login = flow.login();
    assert_eq!(login.status, LoginStatus::PASSWORD_CHANGE_REQUIRED);
    assert_eq!(login.acr, Some(AuthenticationContextClass::SingleFactor));
    assert_eq!(login.amr, vec![AMR_PASSWORD.to_owned()]);

    let outcome = flow
        .change("a-new-sufficiently-long-password")
        .await
        .unwrap();
    let ChallengeOutcome::Authenticated { session, .. } = outcome else {
        panic!("expected the sign-in to finish");
    };
    assert_eq!(session.acr, Some(AuthenticationContextClass::SingleFactor));
    assert_eq!(session.amr, vec![AMR_PASSWORD.to_owned()]);
    assert_eq!(flow.login().status, LoginStatus::AUTHENTICATED);
    assert_eq!(
        flow.replacements(),
        vec![PasswordReplacement {
            kind: PasswordReplacementKind::Required {
                login: flow.login_oid,
                keep: None,
            },
            keep_history: 0,
        }]
    );
}

#[tokio::test]
async fn a_required_change_refuses_the_current_password_and_other_states() {
    let flow = policy_flow(required_user(), 0, 0);
    let early = flow
        .change("a-new-sufficiently-long-password")
        .await
        .unwrap_err();
    assert_error_code(early, AuthErrorCode::InvalidLoginState);

    flow.sign_in().await;
    let unchanged = flow.change("correct-password").await.unwrap_err();
    assert_eq!(
        unchanged.validation().unwrap().fields()[0].code(),
        AuthErrorCode::PasswordUnchanged.code()
    );
    assert_eq!(flow.login().status, LoginStatus::PASSWORD_CHANGE_REQUIRED);
    assert!(flow.replacements().is_empty());
}

#[tokio::test]
async fn an_expired_password_must_be_replaced_and_a_current_one_need_not() {
    let flow = policy_flow(test_user(), 30, 0);
    *flow.credentials.password_set_at.lock().unwrap() = Utc::now() - Duration::days(31);
    assert!(matches!(
        flow.sign_in().await,
        ChallengeOutcome::PasswordChangeRequired { .. }
    ));

    let flow = policy_flow(test_user(), 30, 0);
    *flow.credentials.password_set_at.lock().unwrap() = Utc::now() - Duration::days(29);
    assert!(matches!(
        flow.sign_in().await,
        ChallengeOutcome::Authenticated { .. }
    ));

    // Expiry off: however old the password is.
    let flow = policy_flow(test_user(), 0, 0);
    *flow.credentials.password_set_at.lock().unwrap() = Utc::now() - Duration::days(3_000);
    assert!(matches!(
        flow.sign_in().await,
        ChallengeOutcome::Authenticated { .. }
    ));
}

#[tokio::test]
async fn a_recent_password_cannot_be_reused() {
    let flow = policy_flow(required_user(), 0, 3);
    *flow.credentials.history.lock().unwrap() = ["older-password-one", "older-password-two"]
        .into_iter()
        .map(|hash| {
            RecordingPasswordHasher
                .hash(hash, &PasswordHashSetting::default_value())
                .unwrap()
        })
        .collect();
    flow.sign_in().await;

    let reused = flow.change("older-password-two").await.unwrap_err();
    let field = &reused.validation().unwrap().fields()[0];
    assert_eq!(field.code(), AuthErrorCode::PasswordReused.code());
    assert_eq!(field.field(), "newPassword");

    flow.change("a-new-sufficiently-long-password")
        .await
        .unwrap();
    // The current password and two earlier ones are covered; two are kept.
    assert_eq!(flow.replacements()[0].keep_history, 2);
}

#[tokio::test]
async fn an_account_without_a_password_is_never_held() {
    let flow = policy_flow(required_user(), 1, 0);
    flow.credentials.credentials.lock().unwrap().clear();
    assert!(
        !flow
            .service
            .password_change_due(flow.login().user_oid.unwrap().into())
            .await
            .unwrap()
    );
}
