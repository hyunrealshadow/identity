use super::*;

#[tokio::test]
async fn password_change_withdraws_every_device_authorization() {
    let user_oid = Uuid::new_v4();
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
            user: Arc::new(Mutex::new(test_user())),
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

    let mut device_repo = MockDeviceAuthorizationRepository::new();
    let (sender, mut revoked_users) = unbounded_channel();
    device_repo
        .expect_revoke_device_authorizations_for_user()
        .returning(move |user_oid, _| {
            let _ = sender.send(user_oid);

            Ok(2)
        });
    let service = service.with_device_repository(Arc::new(device_repo));

    let outcome = service
        .change_password_with_session_revocation(
            UserUserOid(user_oid),
            "a-sufficiently-long-password",
            SessionOid(Uuid::new_v4()),
        )
        .await
        .unwrap();

    assert!(outcome.password_changed);
    assert_eq!(
        revoked_users.try_recv().unwrap(),
        user_oid,
        "account level revocation reaches the device authorizations"
    );
}
