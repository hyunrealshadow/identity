//! Sign-in that does not reveal whether an entered identifier has an account.
use super::*;
use crate::setting::IdentifierEnumerationAllowedSetting;

struct Concealed {
    service: LoginService,
    login_repo: Arc<TestLoginRepo>,
    user: Arc<Mutex<User>>,
    login_oid: Uuid,
}

fn concealed(user: User) -> Concealed {
    let login = Login {
        user_oid: None,
        status: LoginStatus::CREATED,
        ..test_login(Uuid::nil(), 0)
    };
    let login_oid = login.oid;
    let login_repo = Arc::new(TestLoginRepo {
        state: Arc::new(Mutex::new(TestLoginRepoState {
            logins: vec![login],
            ..Default::default()
        })),
    });
    let (mut service, user) = otp_service(Arc::clone(&login_repo), user);
    service.credential_repo = Arc::new(TestCredentialRepo::new(sign_in_credentials(true)));
    service.password_hasher = Arc::new(TestSignInHasher);
    service.settings = Arc::new(
        SettingsSnapshot::default()
            .with::<PasswordHashSetting>(PasswordHashSetting::default_value())
            .with::<IdentifierEnumerationAllowedSetting>(false),
    );
    Concealed {
        service,
        login_repo,
        user,
        login_oid,
    }
}

impl Concealed {
    async fn password(&self, password: &str) -> Result<ChallengeOutcome, AppError> {
        self.service
            .challenge(
                self.login_oid,
                CredentialType::Password,
                password,
                SessionContext::default(),
            )
            .await
    }

    fn identification_failures(&self) -> Vec<(Uuid, Option<Uuid>, AuditFailureReason)> {
        self.login_repo
            .state
            .lock()
            .unwrap()
            .identification_failures
            .clone()
    }
}

use crate::setting::SettingDefinition as _;

#[tokio::test]
async fn an_unknown_identifier_continues_to_the_password_and_fails_like_a_wrong_password() {
    let flow = concealed(test_user());

    let result = flow
        .service
        .identify(flow.login_oid, UNKNOWN_IDENTIFIER)
        .await
        .expect("an unknown identifier continues");
    assert!(result.user.is_none());
    assert_eq!(result.credential_types, vec![CredentialType::Password]);
    assert_eq!(
        result.preferred_credential_type,
        Some(CredentialType::Password)
    );
    assert_eq!(
        result.login.concealed_identifier(),
        Some(UNKNOWN_IDENTIFIER)
    );
    assert_eq!(
        flow.identification_failures(),
        vec![(flow.login_oid, None, AuditFailureReason::UnknownAccount)]
    );

    let error = flow.password("correct-password").await.unwrap_err();
    assert_error_code(error, AuthErrorCode::InvalidAccountOrPassword);
}

#[tokio::test]
async fn an_existing_account_shows_nothing_before_the_password_succeeds() {
    let flow = concealed(test_user());

    let result = flow.service.identify(flow.login_oid, "user").await.unwrap();
    assert!(result.user.is_none());
    assert_eq!(result.credential_types, vec![CredentialType::Password]);
    assert!(flow.identification_failures().is_empty());

    let error = flow.password("wrong-password").await.unwrap_err();
    assert_error_code(error, AuthErrorCode::InvalidAccountOrPassword);
    assert_eq!(flow.user.lock().unwrap().failed_attempts, 1);

    let outcome = flow.password("correct-password").await.unwrap();
    assert!(matches!(outcome, ChallengeOutcome::MfaRequired { .. }));
}

#[tokio::test]
async fn reaching_the_lock_threshold_is_not_disclosed() {
    let flow = concealed(User {
        failed_attempts: MAX_FAILED_ATTEMPTS - 1,
        ..test_user()
    });
    flow.service.identify(flow.login_oid, "user").await.unwrap();

    let error = flow.password("wrong-password").await.unwrap_err();
    assert_error_code(error, AuthErrorCode::InvalidAccountOrPassword);
    assert!(flow.user.lock().unwrap().locked);
}

#[tokio::test]
async fn a_locked_account_is_disclosed_only_after_its_correct_password() {
    let flow = concealed(User {
        locked: true,
        locked_until: Some(Utc::now() + Duration::minutes(10)),
        failed_attempts: MAX_FAILED_ATTEMPTS,
        ..test_user()
    });
    let user_oid = Uuid::from(flow.user.lock().unwrap().oid);

    flow.service.identify(flow.login_oid, "user").await.unwrap();
    assert_eq!(
        flow.identification_failures(),
        vec![(
            flow.login_oid,
            Some(user_oid),
            AuditFailureReason::AccountLocked
        )]
    );

    let error = flow.password("wrong-password").await.unwrap_err();
    assert_error_code(error, AuthErrorCode::InvalidAccountOrPassword);
    assert_eq!(
        flow.user.lock().unwrap().failed_attempts,
        MAX_FAILED_ATTEMPTS
    );

    let error = flow.password("correct-password").await.unwrap_err();
    assert_error_code(error, AuthErrorCode::UserLocked);
}

#[tokio::test]
async fn other_methods_are_refused_alike_whether_or_not_an_account_matched() {
    for identifier in ["user", UNKNOWN_IDENTIFIER] {
        let flow = concealed(test_user());
        flow.service
            .identify(flow.login_oid, identifier)
            .await
            .unwrap();
        for credential_type in [
            CredentialType::Passkey,
            CredentialType::Otp,
            CredentialType::RecoveryCode,
        ] {
            let error = flow
                .service
                .challenge(
                    flow.login_oid,
                    credential_type,
                    "000000",
                    SessionContext::default(),
                )
                .await
                .unwrap_err();
            assert_error_code(error, AuthErrorCode::InvalidLoginState);
        }
    }
}

#[tokio::test]
async fn switching_accounts_forgets_the_entered_identifier() {
    let flow = concealed(test_user());
    flow.service
        .identify(flow.login_oid, UNKNOWN_IDENTIFIER)
        .await
        .unwrap();

    flow.login_repo
        .reset_identity(flow.login_oid)
        .await
        .unwrap();

    let login = flow.service.get(flow.login_oid).await.unwrap();
    assert_eq!(login.status, LoginStatus::CREATED);
    assert!(login.submitted_identifier.is_none());
}
