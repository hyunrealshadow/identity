use super::*;

fn password_change_service() -> (LoginService, UserUserOid) {
    let user = test_user();
    let user_oid = Uuid::from(user.oid);
    let login_repo = Arc::new(TestLoginRepo {
        state: Arc::new(Mutex::new(TestLoginRepoState {
            logins: vec![test_login(user_oid, 0)],
            update_status_calls: Vec::new(),
        })),
    });
    let argon2_options = Argon2Options {
        variant: Argon2Variant::Argon2id,
        version: Argon2Version::Argon2013,
        time_cost: 1,
        memory_cost: 19_456,
        parallelism: 1,
    };
    let options = HashOptions::Argon2(argon2_options.clone());
    let service = LoginService::new(
        Arc::new(TestUserRepo {
            user: Arc::new(Mutex::new(user)),
        }),
        Arc::new(TestCredentialRepo {
            credentials: vec![UserCredential {
                oid: UserCredentialOid(Uuid::new_v4()),
                r#type: CredentialType::Password,
                data: CredentialData::Password(Password::Argon2(Argon2Password {
                    hash: "stored-hash".to_owned(),
                    salt: "stored-salt".to_owned(),
                    options: argon2_options.clone(),
                })),
            }],
        }),
        Arc::new(TestSessionRepo),
        login_repo,
        Arc::new(RecordingPasswordHasher),
        Arc::new(AlwaysInvalidTotp),
        fixed_hash_options(options),
    );

    (service, UserUserOid(user_oid))
}

struct Breaches(bool);
#[async_trait]
impl crate::auth::password_policy::BreachedPasswordChecker for Breaches {
    async fn is_breached(&self, _: &str) -> Result<bool, AppError> {
        Ok(self.0)
    }
}

#[tokio::test]
async fn password_change_uses_the_atomic_repository_transition() {
    let (service, user_oid) = password_change_service();
    let service = service.with_breach_checker(Arc::new(Breaches(false)));
    let outcome = service
        .change_password_with_session_revocation(
            user_oid,
            "a-sufficiently-long-password",
            SessionOid(Uuid::new_v4()),
        )
        .await
        .unwrap();
    assert!(outcome.password_changed);
    assert_eq!(outcome.revoked_other_sessions, 2);
    assert_eq!(outcome.session_revocation_failures, 0);
}

#[tokio::test]
async fn breached_password_or_failed_check_never_reaches_the_password_transition() {
    let (service, user_oid) = password_change_service();
    let unavailable = service
        .change_password(user_oid, "a-sufficiently-long-password")
        .await
        .unwrap_err();
    assert_eq!(unavailable.code(), 11026);
    let service = service.with_breach_checker(Arc::new(Breaches(true)));
    let breached = service
        .change_password(user_oid, "a-sufficiently-long-password")
        .await
        .unwrap_err();
    assert_eq!(breached.validation().unwrap().fields()[0].code(), 11025);
    let short_unicode = service
        .change_password(user_oid, "安全密码")
        .await
        .unwrap_err();
    assert_eq!(
        short_unicode.validation().unwrap().fields()[0].code(),
        11013
    );
    let similar = service
        .change_password(user_oid, "user-example-19038!")
        .await
        .unwrap_err();
    assert_eq!(similar.validation().unwrap().fields()[0].code(), 11024);
}
