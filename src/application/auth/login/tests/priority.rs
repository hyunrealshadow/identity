use super::*;

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
        preferred_credential_type(&login, &credentials, MfaMethod::Passkey, false),
        Some(CredentialType::Passkey)
    );
    assert_eq!(
        preferred_credential_type(&login, &credentials, MfaMethod::Otp, false),
        Some(CredentialType::Password)
    );
    // An OTP preference never lets a fresh login skip its password.
    assert_eq!(
        preferred_credential_type(&login, &credentials, MfaMethod::Otp, true),
        Some(CredentialType::Password)
    );
    login.session_oid = Some(SessionOid(Uuid::new_v4()));
    assert_eq!(
        preferred_credential_type(&login, &credentials, MfaMethod::Otp, true),
        Some(CredentialType::Otp)
    );
    assert_eq!(
        preferred_credential_type(&login, &credentials, MfaMethod::Passkey, true),
        Some(CredentialType::Passkey)
    );
    login.status = LoginStatus::MFA_REQUIRED;
    assert_eq!(
        preferred_credential_type(&login, &credentials, MfaMethod::Passkey, false),
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
            false
        ),
        Some(CredentialType::Password)
    );
    assert_eq!(
        preferred_credential_type(
            &login,
            &[CredentialType::Password, CredentialType::Passkey],
            MfaMethod::Otp,
            false
        ),
        Some(CredentialType::Passkey)
    );
    assert_eq!(
        preferred_credential_type(&login, &[CredentialType::Otp], MfaMethod::Otp, false),
        None
    );
    login.status = LoginStatus::CREATED;
    assert_eq!(
        preferred_credential_type(
            &login,
            &[CredentialType::Passkey],
            MfaMethod::Passkey,
            false
        ),
        None
    );
    login.status = LoginStatus::IDENTIFIER_VERIFIED;
    login.user_oid = None;
    assert_eq!(
        preferred_credential_type(
            &login,
            &[CredentialType::Passkey],
            MfaMethod::Passkey,
            false
        ),
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
