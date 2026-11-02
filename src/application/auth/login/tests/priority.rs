use super::*;

#[test]
fn bound_mfa_challenge_excludes_password_and_keeps_enrolled_second_factors() {
    use crate::auth::login::{challenge_credential_types, preferred_credential_type};
    use identity_domain::user::MfaMethod;
    let mut login = test_login(Uuid::new_v4(), 0);
    login.status = LoginStatus::MFA_REQUIRED;
    login.session_oid = Some(SessionOid(Uuid::new_v4()));
    let credentials = [
        CredentialType::Password,
        CredentialType::Otp,
        CredentialType::RecoveryCode,
        CredentialType::Passkey,
    ];
    assert_eq!(
        challenge_credential_types(&login, &credentials),
        [
            CredentialType::Otp,
            CredentialType::RecoveryCode,
            CredentialType::Passkey
        ]
    );
    assert_eq!(
        preferred_credential_type(&login, &credentials, MfaMethod::Otp),
        Some(CredentialType::Otp)
    );
    assert_eq!(
        preferred_credential_type(&login, &credentials, MfaMethod::Passkey),
        Some(CredentialType::Passkey)
    );
    assert_eq!(
        preferred_credential_type(
            &login,
            &[CredentialType::Password, CredentialType::RecoveryCode],
            MfaMethod::Otp
        ),
        Some(CredentialType::RecoveryCode)
    );
    assert!(challenge_credential_types(&login, &[CredentialType::Password]).is_empty());
    assert_eq!(
        preferred_credential_type(&login, &[CredentialType::Password], MfaMethod::Otp),
        None
    );
}

#[test]
fn mfa_priority_selects_a_complete_authentication_path() {
    use crate::auth::login::preferred_credential_type;
    use identity_domain::user::MfaMethod;
    let mut login = test_login(Uuid::new_v4(), 0);
    login.status = LoginStatus::IDENTIFIER_VERIFIED;
    let credentials = [
        CredentialType::Password,
        CredentialType::Otp,
        CredentialType::Passkey,
    ];
    assert_eq!(
        preferred_credential_type(&login, &credentials, MfaMethod::Passkey),
        Some(CredentialType::Passkey)
    );
    assert_eq!(
        preferred_credential_type(&login, &credentials, MfaMethod::Otp),
        Some(CredentialType::Password)
    );
    login.session_oid = Some(SessionOid(Uuid::new_v4()));
    login.status = LoginStatus::MFA_REQUIRED;
    assert_eq!(
        preferred_credential_type(&login, &credentials, MfaMethod::Otp),
        Some(CredentialType::Otp)
    );
    assert_eq!(
        preferred_credential_type(&login, &credentials, MfaMethod::Passkey),
        Some(CredentialType::Passkey)
    );
    login.session_oid = None;
    assert_eq!(
        preferred_credential_type(&login, &credentials, MfaMethod::Passkey),
        Some(CredentialType::Otp)
    );
}

#[test]
fn mfa_priority_ignores_unavailable_methods_and_unidentified_logins() {
    use crate::auth::login::preferred_credential_type;
    use identity_domain::user::MfaMethod;
    let mut login = test_login(Uuid::new_v4(), 0);
    login.status = LoginStatus::IDENTIFIER_VERIFIED;
    assert_eq!(
        preferred_credential_type(
            &login,
            &[CredentialType::Password, CredentialType::Otp],
            MfaMethod::Passkey,
        ),
        Some(CredentialType::Password)
    );
    assert_eq!(
        preferred_credential_type(
            &login,
            &[CredentialType::Password, CredentialType::Passkey],
            MfaMethod::Otp,
        ),
        Some(CredentialType::Passkey)
    );
    assert_eq!(
        preferred_credential_type(&login, &[CredentialType::Otp], MfaMethod::Otp),
        None
    );
    login.status = LoginStatus::CREATED;
    assert_eq!(
        preferred_credential_type(&login, &[CredentialType::Passkey], MfaMethod::Passkey),
        None
    );
    login.status = LoginStatus::IDENTIFIER_VERIFIED;
    login.user_oid = None;
    assert_eq!(
        preferred_credential_type(&login, &[CredentialType::Passkey], MfaMethod::Passkey),
        None
    );
}

#[test]
fn passkey_requires_identifier_verified_and_unexpired_login() {
    let mut login = test_login(Uuid::new_v4(), 0);
    for status in [
        LoginStatus::CREATED,
        LoginStatus::AUTHENTICATED,
        LoginStatus::FAILED,
        LoginStatus::EXPIRED,
    ] {
        login.status = status;
        assert!(crate::auth::login::validate_passkey_login(&login).is_err());
    }
    login.status = LoginStatus::MFA_REQUIRED;
    assert!(crate::auth::login::validate_passkey_login(&login).is_ok());
    login.status = LoginStatus::IDENTIFIER_VERIFIED;
    assert!(crate::auth::login::validate_passkey_login(&login).is_ok());
    login.user_oid = None;
    assert!(crate::auth::login::validate_passkey_login(&login).is_err());
    login.user_oid = Some(Uuid::new_v4());
    login.expires_at = Utc::now() - Duration::seconds(1);
    assert!(crate::auth::login::validate_passkey_login(&login).is_err());
    login.expires_at = Utc::now() + Duration::minutes(1);
    login.failed_attempts = MAX_FAILED_ATTEMPTS;
    assert!(crate::auth::login::validate_passkey_login(&login).is_err());
}
