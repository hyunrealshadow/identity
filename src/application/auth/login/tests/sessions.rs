use super::*;

#[tokio::test]
async fn repeated_fresh_logins_for_different_clients_reuse_the_browser_session() {
    let user = test_user();
    let user_oid = Uuid::from(user.oid);
    let existing = browser_session(user_oid);
    // An account with identical display data must not be matched by email.
    let foreign = browser_session(Uuid::new_v4());
    let presented = vec![foreign.session_oid, existing.session_oid];
    let mut logins = vec![test_login(user_oid, 0), test_login(user_oid, 0)];
    for login in &mut logins {
        login.status = LoginStatus::IDENTIFIER_VERIFIED;
    }
    assert_ne!(logins[0].client_oid, logins[1].client_oid);
    let login_oids: Vec<_> = logins.iter().map(|login| login.oid).collect();
    let mut service = sign_in_service(user, logins, false);
    let mut repo = MockSessionRepository::new();
    repo.expect_find_active_accounts_by_oids()
        .withf({
            let presented = presented.clone();
            move |oids| oids == presented
        })
        .times(2)
        .returning({
            let existing = existing.clone();
            move |_| Ok(vec![existing.clone(), foreign.clone()])
        });
    repo.expect_reauthenticate_by_oid()
        .withf({
            let oid = existing.session_oid;
            move |session_oid, owner, acr, _, amr| {
                *session_oid == oid
                    && *owner == user_oid
                    && acr == ACR_AAL1
                    && amr == [AMR_PASSWORD.to_owned()]
            }
        })
        .times(2)
        .returning(move |oid, owner, acr, acr_expires_at, amr| {
            Ok(Session {
                oid,
                user_oid: owner,
                status: SessionStatus::ACTIVE,
                device_name: None,
                device_type: None,
                os_name: None,
                os_version: None,
                browser_name: None,
                browser_version: None,
                user_agent: None,
                ip_address: None,
                last_active_at: Some(Utc::now()),
                expires_at: Some(Utc::now() + Duration::days(7)),
                revoked_at: None,
                created_at: existing.created_at,
                acr: Some(acr.to_owned()),
                acr_expires_at: Some(acr_expires_at),
                amr: amr.to_vec(),
            })
        });
    // Any attempt to create a session is rejected by the mock.
    service.session_repo = Arc::new(repo);
    for login_oid in login_oids {
        let outcome = service
            .challenge(
                login_oid,
                CredentialType::Password,
                "correct-password",
                SessionContext {
                    browser_session_oids: presented.clone(),
                    ..Default::default()
                },
            )
            .await
            .unwrap();
        let ChallengeOutcome::Authenticated { session, .. } = outcome else {
            panic!("expected completed password authentication");
        };
        assert_eq!(session.oid, existing.session_oid);
    }
}

#[tokio::test]
async fn fresh_login_creates_a_session_when_no_valid_same_user_session_is_presented() {
    for missing in [false, true] {
        let user = test_user();
        let user_oid = Uuid::from(user.oid);
        let login = test_login(user_oid, 0);
        let mut expired = browser_session(user_oid);
        expired.expires_at = Some(Utc::now() - Duration::seconds(1));
        let foreign = browser_session(Uuid::new_v4());
        let presented = vec![expired.session_oid, foreign.session_oid];
        let mut service = sign_in_service(user, vec![login.clone()], false);
        let mut repo = MockSessionRepository::new();
        repo.expect_find_active_accounts_by_oids()
            .times(1)
            .return_once(move |_| {
                Ok(if missing {
                    Vec::new()
                } else {
                    vec![expired, foreign]
                })
            });
        repo.expect_create().times(1).returning(|input| {
            // Match the normal creation contract without a database.
            Ok(Session {
                oid: SessionOid(Uuid::new_v4()),
                user_oid: input.user_oid,
                status: SessionStatus::ACTIVE,
                device_name: input.device_name,
                device_type: input.device_type,
                os_name: input.os_name,
                os_version: input.os_version,
                browser_name: input.browser_name,
                browser_version: input.browser_version,
                user_agent: input.user_agent,
                ip_address: input.ip_address,
                last_active_at: Some(Utc::now()),
                expires_at: input.expires_at,
                revoked_at: None,
                created_at: Utc::now(),
                acr: input.acr,
                acr_expires_at: input.acr_expires_at,
                amr: input.amr,
            })
        });
        service.session_repo = Arc::new(repo);
        let session = service
            .complete_session(
                &login,
                user_oid,
                SessionContext {
                    browser_session_oids: presented.clone(),
                    ..Default::default()
                },
                ACR_AAL1,
                &[AMR_PASSWORD.to_owned()],
            )
            .await
            .unwrap();
        assert_eq!(session.user_oid, user_oid);
        assert!(!presented.contains(&session.oid));
    }
}
