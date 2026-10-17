use super::*;
use crate::error::{code::AppErrorCode, codes::auth::AuthErrorCode};
use crate::user::credential::PasskeyCredentialData;

fn fixture() -> (MfaService, Arc<TestCredentialRepo>, UserOid) {
    let repo = Arc::new(TestCredentialRepo::default());
    (
        MfaService::new(
            repo.clone(),
            Arc::new(AlwaysValid),
            Arc::new(TestGenerator),
            Arc::new(TestProtector),
        ),
        repo,
        UserOid(Uuid::new_v4()),
    )
}

fn add(repo: &TestCredentialRepo, data: CredentialData) {
    repo.credentials.lock().unwrap().push(UserCredential {
        oid: UserCredentialOid(Uuid::new_v4()),
        r#type: data.credential_type(),
        data,
    });
}

fn passkey() -> CredentialData {
    CredentialData::Passkey(PasskeyCredentialData {
        name: "Laptop".to_owned(),
        credential_id: "key".to_owned(),
        key: serde_json::json!({}),
    })
}

#[tokio::test]
async fn recovery_preparation_is_account_bound_and_does_not_persist_until_mfa_is_added() {
    let (service, repo, user) = fixture();
    let enrollment = service
        .prepare_recovery_code_enrollment(user)
        .await
        .unwrap();
    assert_eq!(enrollment.recovery_codes.len(), 10);
    assert!(repo.credentials.lock().unwrap().is_empty());
    let token = enrollment.enrollment_token.as_deref();
    let credentials = service
        .registration_recovery_codes(user, token)
        .await
        .unwrap();
    assert_eq!(credentials.len(), 10);
    for (code, stored) in enrollment.recovery_codes.iter().zip(credentials) {
        assert_eq!(recovery_code_hash(code), stored.hash);
    }
    assert_eq!(
        service
            .registration_recovery_codes(UserOid(Uuid::new_v4()), token)
            .await
            .unwrap_err()
            .code(),
        AuthErrorCode::InvalidMfaEnrollment.code()
    );
    assert_eq!(
        service
            .registration_recovery_codes(user, None)
            .await
            .unwrap_err()
            .code(),
        AuthErrorCode::InvalidMfaEnrollment.code()
    );
}

#[tokio::test]
async fn recovery_enrollment_rejects_expired_or_invalid_tokens() {
    let (service, _, user) = fixture();
    let enrollment = service
        .prepare_recovery_code_enrollment(user)
        .await
        .unwrap();
    let mut pending: serde_json::Value = serde_json::from_slice(
        &STANDARD
            .decode(enrollment.enrollment_token.unwrap())
            .unwrap(),
    )
    .unwrap();
    pending["expires_at"] =
        serde_json::json!((chrono::Utc::now() - chrono::Duration::minutes(1)).to_rfc3339());
    let expired = STANDARD.encode(serde_json::to_vec(&pending).unwrap());
    for token in [&*expired, "not a protected payload"] {
        assert_eq!(
            service
                .registration_recovery_codes(user, Some(token))
                .await
                .unwrap_err()
                .code(),
            AuthErrorCode::InvalidMfaEnrollment.code()
        );
    }
}

#[tokio::test]
async fn adding_totp_preserves_recovery_codes_already_used_by_passkeys() {
    let (service, repo, user) = fixture();
    add(&repo, passkey());
    add(
        &repo,
        CredentialData::RecoveryCode(RecoveryCodeCredentialData {
            hash: "existing-batch".to_owned(),
        }),
    );
    let prepared = service
        .prepare_recovery_code_enrollment(user)
        .await
        .unwrap();
    assert!(prepared.recovery_codes.is_empty());
    assert!(prepared.enrollment_token.is_none());
    assert!(
        service
            .registration_recovery_codes(user, None)
            .await
            .unwrap()
            .is_empty()
    );
    let enrollment = service
        .begin_totp_enrollment(user, "example", "person")
        .await
        .unwrap();
    assert!(enrollment.recovery_codes.is_empty());
    service
        .confirm_totp_enrollment(user, &enrollment.enrollment_token, "123456")
        .await
        .unwrap();
    let codes = repo
        .find_by_user_oid_and_type(user, CredentialType::RecoveryCode)
        .await
        .unwrap();
    assert_eq!(codes.len(), 1);
    assert!(
        matches!(&codes[0].data, CredentialData::RecoveryCode(code) if code.hash == "existing-batch")
    );
}

#[tokio::test]
async fn removing_totp_preserves_codes_while_a_passkey_remains() {
    for has_passkey in [false, true] {
        let (service, repo, user) = fixture();
        let enrollment = service
            .begin_totp_enrollment(user, "example", "person")
            .await
            .unwrap();
        service
            .confirm_totp_enrollment(user, &enrollment.enrollment_token, "123456")
            .await
            .unwrap();
        if has_passkey {
            add(&repo, passkey());
        }
        service.disable_totp(user).await.unwrap();
        let status = service.status(user).await.unwrap();
        assert!(!status.totp_enabled);
        assert_eq!(
            status.recovery_codes_remaining,
            if has_passkey { 10 } else { 0 }
        );
    }
}

#[tokio::test]
async fn passkey_only_accounts_can_regenerate_recovery_codes() {
    let (service, repo, user) = fixture();
    assert_eq!(
        service
            .regenerate_recovery_codes(user)
            .await
            .unwrap_err()
            .code(),
        AuthErrorCode::MfaNotEnabled.code()
    );
    add(&repo, passkey());
    let regenerated = service.regenerate_recovery_codes(user).await.unwrap();
    assert_eq!(regenerated.recovery_codes.len(), 10);
    let status = service.status(user).await.unwrap();
    assert!(!status.totp_enabled);
    assert_eq!(status.recovery_codes_remaining, 10);
    assert_eq!(
        repo.find_by_user_oid_and_type(user, CredentialType::Passkey)
            .await
            .unwrap()
            .len(),
        1
    );
}
