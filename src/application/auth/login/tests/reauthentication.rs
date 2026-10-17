use super::*;

#[tokio::test]
async fn forced_reauthentication_reuses_the_bound_session() {
    let user = test_user();
    let mut login = test_login(Uuid::from(user.oid), 0);
    let bound_session_oid = SessionOid(Uuid::new_v4());
    login.session_oid = Some(bound_session_oid);
    let login_repo = Arc::new(TestLoginRepo {
        state: Arc::new(Mutex::new(TestLoginRepoState {
            logins: vec![login.clone()],
            ..Default::default()
        })),
    });
    let (service, _) = otp_service(login_repo, user);

    let session = service
        .complete_session(
            &login,
            login.user_oid.unwrap(),
            SessionContext {
                browser_session_oids: Vec::new(),
                device_name: None,
                device_type: None,
                os_name: None,
                os_version: None,
                browser_name: None,
                browser_version: None,
                user_agent: None,
                ip_address: None,
            },
            ACR_AAL2,
            &[
                AMR_PASSWORD.to_owned(),
                AMR_OTP.to_owned(),
                AMR_MFA.to_owned(),
            ],
        )
        .await
        .unwrap();

    assert_eq!(session.oid, bound_session_oid);
    assert_eq!(session.acr.as_deref(), Some(ACR_AAL2));
}

#[tokio::test]
async fn browser_session_does_not_bypass_password_or_mfa() {
    for mfa in [false, true] {
        let user = test_user();
        let existing = browser_session(user.oid.into());
        let mut login = test_login(user.oid.into(), 0);
        login.status = LoginStatus::IDENTIFIER_VERIFIED;
        let login_oid = login.oid;
        let mut service = sign_in_service(user, vec![login], mfa);
        // No session lookup, renewal, or creation may occur yet.
        service.session_repo = Arc::new(MockSessionRepository::new());
        let result = service
            .challenge(
                login_oid,
                CredentialType::Password,
                if mfa {
                    "correct-password"
                } else {
                    "wrong-password"
                },
                SessionContext {
                    browser_session_oids: vec![existing.session_oid],
                    ..Default::default()
                },
            )
            .await;
        if mfa {
            assert!(matches!(
                result.unwrap(),
                ChallengeOutcome::MfaRequired { .. }
            ));
        } else {
            assert_error_code(result.unwrap_err(), AuthErrorCode::InvalidCredential);
        }
    }
}

#[tokio::test]
async fn bound_reauthentication_can_challenge_otp_without_password() {
    let user = test_user();
    let mut login = test_login(Uuid::from(user.oid), 0);
    login.status = LoginStatus::IDENTIFIER_VERIFIED;
    login.session_oid = Some(SessionOid(Uuid::new_v4()));
    let login_oid = login.oid;
    let login_repo = Arc::new(TestLoginRepo {
        state: Arc::new(Mutex::new(TestLoginRepoState {
            logins: vec![login],
            ..Default::default()
        })),
    });
    let (service, _) = otp_service(login_repo, user);

    let error = service
        .challenge(
            login_oid,
            CredentialType::Otp,
            "000000",
            SessionContext {
                browser_session_oids: Vec::new(),
                device_name: None,
                device_type: None,
                os_name: None,
                os_version: None,
                browser_name: None,
                browser_version: None,
                user_agent: None,
                ip_address: None,
            },
        )
        .await
        .expect_err("the test verifier rejects the code after state validation");

    assert_error_code(error, AuthErrorCode::InvalidOtp);
}

#[tokio::test]
async fn unbound_login_cannot_use_otp_as_a_password_replacement() {
    let user = test_user();
    let mut login = test_login(Uuid::from(user.oid), 0);
    login.status = LoginStatus::IDENTIFIER_VERIFIED;
    let login_oid = login.oid;
    let login_repo = Arc::new(TestLoginRepo {
        state: Arc::new(Mutex::new(TestLoginRepoState {
            logins: vec![login],
            ..Default::default()
        })),
    });
    let (service, _) = otp_service(login_repo, user);

    let error = service
        .challenge(
            login_oid,
            CredentialType::Otp,
            "000000",
            SessionContext {
                browser_session_oids: Vec::new(),
                device_name: None,
                device_type: None,
                os_name: None,
                os_version: None,
                browser_name: None,
                browser_version: None,
                user_agent: None,
                ip_address: None,
            },
        )
        .await
        .expect_err("unbound login must still verify the password first");

    assert_error_code(error, AuthErrorCode::InvalidLoginState);
}

#[tokio::test]
async fn expired_challenge_transitions_login_to_expired() {
    let user = test_user();
    let mut login = test_login(Uuid::from(user.oid), 0);
    login.expires_at = Utc::now() - Duration::seconds(1);
    let login_oid = login.oid;
    let login_repo = Arc::new(TestLoginRepo {
        state: Arc::new(Mutex::new(TestLoginRepoState {
            logins: vec![login],
            ..Default::default()
        })),
    });
    let (service, _) = otp_service(login_repo.clone(), user);

    let error = service
        .challenge(
            login_oid,
            CredentialType::Otp,
            "000000",
            SessionContext {
                browser_session_oids: Vec::new(),
                device_name: None,
                device_type: None,
                os_name: None,
                os_version: None,
                browser_name: None,
                browser_version: None,
                user_agent: None,
                ip_address: None,
            },
        )
        .await
        .expect_err("expired login must not evaluate the credential");

    assert_error_code(error, AuthErrorCode::LoginExpired);
    let state = login_repo.state.lock().unwrap();
    assert_eq!(state.update_status_calls.len(), 1);
    assert_eq!(state.update_status_calls[0].1, LoginStatus::EXPIRED);
}
