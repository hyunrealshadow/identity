use super::*;

#[tokio::test]
async fn passkey_completes_mfa_without_password_and_protects_password_fallback() {
    for password_first in [false, true] {
        let user = test_user();
        let user_oid = user.oid;
        let mut login = test_login(user.oid.into(), 0);
        login.status = LoginStatus::IDENTIFIER_VERIFIED;
        let login_oid = login.oid;
        let (passkeys, sign) = crate::auth::passkey::tests::enrolled_passkey(user_oid).await;
        let mut service = sign_in_service(user, vec![login], false).with_passkeys(passkeys);
        if password_first {
            // Password alone must not create or renew any session.
            service.session_repo = Arc::new(MockSessionRepository::new());
            assert!(matches!(
                service
                    .challenge(
                        login_oid,
                        CredentialType::Password,
                        "correct-password",
                        SessionContext::default()
                    )
                    .await
                    .unwrap(),
                ChallengeOutcome::MfaRequired { .. }
            ));
        }
        service.session_repo = Arc::new(TestSessionRepo);
        let options = service.passkey_options(login_oid).await.unwrap();
        let result = service
            .challenge(
                login_oid,
                CredentialType::Passkey,
                &sign(&options),
                SessionContext::default(),
            )
            .await
            .unwrap();
        let ChallengeOutcome::Authenticated { session, .. } = result else {
            panic!("passkey must complete MFA");
        };
        assert_eq!(session.acr.as_deref(), Some(ACR_AAL2));
        assert!(session.amr.contains(&"passkey".to_owned()));
        assert_eq!(
            session.amr.contains(&AMR_PASSWORD.to_owned()),
            password_first
        );
    }
}
