use super::*;

#[tokio::test]
async fn otp_rejects_when_attempt_limit_already_reached() {
    let user = test_user();
    let login = test_login(Uuid::from(user.oid), MAX_OTP_ATTEMPTS);
    let login_oid = login.oid;
    let login_repo = Arc::new(TestLoginRepo {
        state: Arc::new(Mutex::new(TestLoginRepoState {
            logins: vec![login],
            ..Default::default()
        })),
    });
    let (service, _) = otp_service(Arc::clone(&login_repo), user);

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
        .expect_err("expected too many attempts");

    assert_error_code(error, AuthErrorCode::TooManyAttempts);
    let state = login_repo.state.lock().unwrap();
    assert_eq!(state.update_status_calls.len(), 1);
    assert_eq!(state.update_status_calls[0].1, LoginStatus::FAILED);
}

#[tokio::test]
async fn otp_invalid_code_returns_invalid_otp_before_limit() {
    let user = test_user();
    let login = test_login(Uuid::from(user.oid), MAX_OTP_ATTEMPTS - 2);
    let login_oid = login.oid;
    let login_repo = Arc::new(TestLoginRepo {
        state: Arc::new(Mutex::new(TestLoginRepoState {
            logins: vec![login],
            ..Default::default()
        })),
    });
    let (service, _) = otp_service(Arc::clone(&login_repo), user);

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
        .expect_err("expected invalid otp");

    assert_error_code(error, AuthErrorCode::InvalidOtp);
    assert_eq!(
        login_repo.state.lock().unwrap().logins[0].failed_attempts,
        MAX_OTP_ATTEMPTS - 1
    );
}

#[tokio::test]
async fn otp_last_allowed_failure_returns_too_many_attempts() {
    let user = test_user();
    let login = test_login(Uuid::from(user.oid), MAX_OTP_ATTEMPTS - 1);
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
        .expect_err("expected too many attempts");

    assert_error_code(error, AuthErrorCode::TooManyAttempts);
    let state = login_repo.state.lock().unwrap();
    assert_eq!(state.logins[0].failed_attempts, MAX_OTP_ATTEMPTS);
    assert_eq!(state.update_status_calls[0].1, LoginStatus::FAILED);
}

#[tokio::test]
async fn otp_failures_across_fresh_logins_lock_the_user() {
    let user = test_user();
    let user_oid = Uuid::from(user.oid);
    let logins: Vec<_> = (0..=MAX_FAILED_ATTEMPTS)
        .map(|_| test_login(user_oid, 0))
        .collect();
    let login_oids: Vec<_> = logins.iter().map(|login| login.oid).collect();
    let login_repo = Arc::new(TestLoginRepo {
        state: Arc::new(Mutex::new(TestLoginRepoState {
            logins,
            ..Default::default()
        })),
    });
    let (service, user_state) = otp_service(login_repo, user);

    for login_oid in &login_oids[..usize::try_from(MAX_FAILED_ATTEMPTS - 1).unwrap()] {
        let error = service
            .challenge(
                *login_oid,
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
            .expect_err("expected invalid otp");
        assert_error_code(error, AuthErrorCode::InvalidOtp);
    }

    let threshold_index = usize::try_from(MAX_FAILED_ATTEMPTS - 1).unwrap();
    let error = service
        .challenge(
            login_oids[threshold_index],
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
        .expect_err("expected threshold failure");
    assert_error_code(error, AuthErrorCode::TooManyAttempts);
    {
        let user = user_state.lock().unwrap();
        assert_eq!(user.failed_attempts, MAX_FAILED_ATTEMPTS);
        assert!(user.locked);
    }

    let error = service
        .challenge(
            login_oids[threshold_index + 1],
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
        .expect_err("expected user lock to apply to another login");
    assert_error_code(error, AuthErrorCode::UserLocked);
}
