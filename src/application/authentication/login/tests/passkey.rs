use super::*;
use crate::authentication::passkey::tests;

#[tokio::test]
async fn passkey_completes_mfa_without_password_and_protects_password_fallback() {
    for password_first in [false, true] {
        let user = test_user();
        let user_oid = user.oid;
        let mut login = test_login(user.oid.into(), 0);
        login.status = LoginStatus::IDENTIFIER_VERIFIED;
        let login_oid = login.oid;
        let (passkeys, sign) = tests::enrolled_passkey(user_oid).await;
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
            panic!("passkey must complete phishing-resistant authentication");
        };
        assert_eq!(
            session.acr,
            Some(AuthenticationContextClass::PhishingResistant)
        );
        assert!(session.amr.contains(&"passkey".to_owned()));
        assert_eq!(
            session.amr.contains(&AMR_PASSWORD.to_owned()),
            password_first
        );
    }
}

#[tokio::test]
async fn has_second_factor_reports_otp_and_passkey_enrollment() {
    let user = test_user();
    let user_oid = user.oid;

    let password_only = sign_in_service(user.clone(), Vec::new(), false);
    assert!(!password_only.has_second_factor(user_oid).await.unwrap());

    let with_otp = sign_in_service(user.clone(), Vec::new(), true);
    assert!(with_otp.has_second_factor(user_oid).await.unwrap());

    let (passkeys, _) = tests::enrolled_passkey(user_oid).await;
    let with_passkey = password_only.with_passkeys(passkeys);
    assert!(with_passkey.has_second_factor(user_oid).await.unwrap());
}
