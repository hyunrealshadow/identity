use std::collections::HashMap;

use base64::{Engine as _, engine::general_purpose::STANDARD};
use identity_domain::{
    auth::challenge::{
        AuthenticationChallenge, ChallengeBinding, ChallengeContext, ChallengeMethod,
        ChallengePurpose, DeliveryChallengeAdmission, DeliveryChallengeContext,
        DeliveryChallengeRequest, DeliveryChallengeStatus,
    },
    data_protection::DataProtectionError,
};

use super::*;
use crate::{
    authentication::{
        challenge::ChallengeRepository,
        login::LoginMfaEnrollmentDependencies,
        mfa::{GeneratedTotpEnrollment, MfaService, TotpEnrollmentGenerator},
    },
    data_protection::DataProtector,
};

const VALID_CODE: &str = "123456";

struct CodeVerifier;

impl TotpVerifier for CodeVerifier {
    fn verify(&self, _otp_data: &OtpCredentialData, code: &str) -> Result<Option<u64>, TotpError> {
        Ok((code == VALID_CODE).then_some(1))
    }
}

struct RandomSecretGenerator;

impl TotpEnrollmentGenerator for RandomSecretGenerator {
    fn generate(
        &self,
        _issuer: &str,
        _account_name: &str,
    ) -> Result<GeneratedTotpEnrollment, TotpError> {
        let credential = OtpCredentialData {
            secret: Uuid::new_v4().simple().to_string(),
            digits: 6,
            period: 30,
            algorithm: OtpAlgorithm::Sha256,
            last_used_counter: None,
        };
        Ok(GeneratedTotpEnrollment {
            otp_auth_uri: self.otp_auth_uri("", "", &credential)?,
            credential,
        })
    }

    fn otp_auth_uri(
        &self,
        _issuer: &str,
        _account_name: &str,
        credential: &OtpCredentialData,
    ) -> Result<String, TotpError> {
        Ok(format!(
            "otpauth://totp/example?secret={}&algorithm={}",
            credential.secret, credential.algorithm
        ))
    }
}

struct EncodingProtector;

#[async_trait]
impl DataProtector for EncodingProtector {
    async fn protect(
        &self,
        _purpose: &str,
        plaintext: &[u8],
    ) -> Result<String, DataProtectionError> {
        Ok(STANDARD.encode(plaintext))
    }

    async fn unprotect(&self, _purpose: &str, token: &str) -> Result<Vec<u8>, DataProtectionError> {
        STANDARD
            .decode(token)
            .map_err(|_| DataProtectionError::InvalidProtectedPayload)
    }
}

/// Context, state, expiry and insertion order of a stored challenge.
type StoredChallenge = (ChallengeContext, serde_json::Value, DateTime<Utc>, u64);

#[derive(Default)]
struct MemoryChallenges {
    items: Mutex<HashMap<Uuid, StoredChallenge>>,
    sequence: Mutex<u64>,
}

#[async_trait]
impl ChallengeRepository for MemoryChallenges {
    async fn store(
        &self,
        context: ChallengeContext,
        challenge: AuthenticationChallenge,
    ) -> Result<(), AppError> {
        let mut sequence = self.sequence.lock().unwrap();
        *sequence += 1;
        self.items.lock().unwrap().insert(
            challenge.id,
            (context, challenge.state, challenge.expires_at, *sequence),
        );
        Ok(())
    }

    async fn admit_delivery(
        &self,
        _context: DeliveryChallengeContext,
        _request: DeliveryChallengeRequest,
    ) -> Result<DeliveryChallengeAdmission, AppError> {
        Ok(DeliveryChallengeAdmission::InvalidState)
    }

    async fn delivery_status(
        &self,
        _binding: ChallengeBinding,
        _method: ChallengeMethod,
        _purpose: ChallengePurpose,
    ) -> Result<Option<DeliveryChallengeStatus>, AppError> {
        Ok(None)
    }

    async fn take(
        &self,
        context: ChallengeContext,
        id: Uuid,
    ) -> Result<Option<AuthenticationChallenge>, AppError> {
        let mut items = self.items.lock().unwrap();
        if !items.get(&id).is_some_and(|item| item.0 == context) {
            return Ok(None);
        }
        Ok(items.remove(&id).map(|item| AuthenticationChallenge {
            id,
            state: item.1,
            expires_at: item.2,
        }))
    }

    async fn latest(
        &self,
        context: ChallengeContext,
    ) -> Result<Option<AuthenticationChallenge>, AppError> {
        let items = self.items.lock().unwrap();
        Ok(items
            .iter()
            .filter(|(_, item)| item.0 == context && item.2 > Utc::now())
            .max_by_key(|(_, item)| item.3)
            .map(|(id, item)| AuthenticationChallenge {
                id: *id,
                state: item.1.clone(),
                expires_at: item.2,
            }))
    }
}

fn aal2_login(user: &User) -> Login {
    let mut login = test_login(user.oid.into(), 0);
    login.status = LoginStatus::IDENTIFIER_VERIFIED;
    login.requested_acr_values = vec![AuthenticationContextClass::MultiFactor];
    login
}

/// A password-only account whose login service can enroll a TOTP factor.
fn enrollment_service(user: User, login: Login) -> (LoginService, Arc<TestCredentialRepo>) {
    let mut service = sign_in_service(user, vec![login], false);
    let credentials = Arc::new(TestCredentialRepo::new(sign_in_credentials(false)));
    service.credential_repo = credentials.clone();
    let mfa = Arc::new(MfaService::new(
        credentials.clone(),
        Arc::new(CodeVerifier),
        Arc::new(RandomSecretGenerator),
        Arc::new(EncodingProtector),
    ));
    let service = service.with_mfa_enrollment(LoginMfaEnrollmentDependencies {
        mfa,
        challenges: Arc::new(MemoryChallenges::default()),
    });
    (service, credentials)
}

async fn sign_in_with_password(service: &LoginService, login_oid: Uuid) -> ChallengeOutcome {
    service
        .challenge(
            login_oid,
            CredentialType::Password,
            "correct-password",
            SessionContext::default(),
        )
        .await
        .unwrap()
}

#[tokio::test]
async fn aal2_password_without_second_factor_requires_enrollment() {
    let user = test_user();
    let login = aal2_login(&user);
    let (service, _) = enrollment_service(user, login.clone());

    let outcome = sign_in_with_password(&service, login.oid).await;

    assert!(matches!(
        outcome,
        ChallengeOutcome::MfaEnrollmentRequired { .. }
    ));
    let current = service.get(login.oid).await.unwrap();
    assert_eq!(current.status, LoginStatus::MFA_ENROLLMENT_REQUIRED);
    assert!(
        super::super::challenge_credential_types(&current, &[CredentialType::Password]).is_empty(),
        "no credential challenge may bypass the enrollment"
    );
}

#[tokio::test]
async fn enrollment_resumes_the_same_secret_and_completes_aal2() {
    let user = test_user();
    let login = aal2_login(&user);
    let (service, credentials) = enrollment_service(user, login.clone());
    sign_in_with_password(&service, login.oid).await;

    let first = service.mfa_enrollment(login.oid, "issuer").await.unwrap();
    let resumed = service.mfa_enrollment(login.oid, "issuer").await.unwrap();
    assert_eq!(first.secret, resumed.secret);
    assert_eq!(first.recovery_codes, resumed.recovery_codes);
    assert!(!first.recovery_codes.is_empty());

    let rejected = service
        .confirm_mfa_enrollment(login.oid, "000000", SessionContext::default())
        .await
        .expect_err("a wrong code must not enroll the authenticator");
    assert_error_code(rejected, AuthErrorCode::InvalidOtp);
    let after_rejection = service.mfa_enrollment(login.oid, "issuer").await.unwrap();
    assert_eq!(after_rejection.secret, first.secret);

    let outcome = service
        .confirm_mfa_enrollment(login.oid, VALID_CODE, SessionContext::default())
        .await
        .unwrap();
    let ChallengeOutcome::Authenticated { session, .. } = outcome else {
        panic!("a confirmed enrollment must authenticate the login")
    };
    assert_eq!(session.acr, Some(AuthenticationContextClass::MultiFactor));
    assert_eq!(
        service.get(login.oid).await.unwrap().status,
        LoginStatus::AUTHENTICATED
    );
    let enrolled = credentials
        .find_by_user_oid_and_type(UserUserOid(Uuid::nil()), CredentialType::Otp)
        .await
        .unwrap();
    let [enrolled] = enrolled.as_slice() else {
        panic!("exactly one authenticator must be enrolled")
    };
    let CredentialData::Otp(otp) = &enrolled.data else {
        panic!("the enrolled credential must be TOTP")
    };
    assert_eq!(otp.secret, first.secret);
    let mut enrolled_codes = credentials
        .find_by_user_oid_and_type(UserUserOid(Uuid::nil()), CredentialType::RecoveryCode)
        .await
        .unwrap()
        .into_iter()
        .filter_map(|credential| match credential.data {
            CredentialData::RecoveryCode(code) => Some(code.hash),
            _ => None,
        })
        .collect::<Vec<_>>();
    let mut shown_codes = first
        .recovery_codes
        .iter()
        .map(|code| crate::authentication::mfa::recovery_code_hash(code))
        .collect::<Vec<_>>();
    enrolled_codes.sort();
    shown_codes.sort();
    assert_eq!(
        enrolled_codes, shown_codes,
        "the recovery codes saved before confirmation are the ones enrolled"
    );
}

#[tokio::test]
async fn rejected_enrollment_codes_fail_the_login_at_the_limit() {
    let user = test_user();
    let login = aal2_login(&user);
    let (service, credentials) = enrollment_service(user, login.clone());
    sign_in_with_password(&service, login.oid).await;
    service.mfa_enrollment(login.oid, "issuer").await.unwrap();

    let mut last = None;
    for _ in 0..MAX_OTP_ATTEMPTS {
        last = Some(
            service
                .confirm_mfa_enrollment(login.oid, "000000", SessionContext::default())
                .await
                .expect_err("wrong codes are rejected"),
        );
    }

    assert_error_code(last.unwrap(), AuthErrorCode::TooManyAttempts);
    assert_eq!(
        service.get(login.oid).await.unwrap().status,
        LoginStatus::FAILED
    );
    assert!(
        credentials
            .find_by_user_oid_and_type(UserUserOid(Uuid::nil()), CredentialType::Otp)
            .await
            .unwrap()
            .is_empty()
    );
}

#[tokio::test]
async fn enrollment_is_unavailable_outside_its_phase() {
    let user = test_user();
    let login = aal2_login(&user);
    let (service, _) = enrollment_service(user, login.clone());

    for result in [
        service
            .mfa_enrollment(login.oid, "issuer")
            .await
            .map(|_| ()),
        service
            .confirm_mfa_enrollment(login.oid, VALID_CODE, SessionContext::default())
            .await
            .map(|_| ()),
    ] {
        assert_error_code(
            result.expect_err("enrollment requires the enrollment phase"),
            AuthErrorCode::InvalidLoginState,
        );
    }
}

#[tokio::test]
async fn aal1_requests_do_not_ask_password_only_users_to_enroll() {
    let user = test_user();
    let mut login = aal2_login(&user);
    login.requested_acr_values.clear();
    let (service, _) = enrollment_service(user, login.clone());

    assert!(matches!(
        sign_in_with_password(&service, login.oid).await,
        ChallengeOutcome::Authenticated { .. }
    ));
}

#[tokio::test]
async fn session_bound_aal2_login_without_factor_asks_for_the_password() {
    let user = test_user();
    let mut login = aal2_login(&user);
    login.session_oid = Some(SessionOid(Uuid::new_v4()));
    let (service, _) = enrollment_service(user, login.clone());

    assert_eq!(
        service.prepare_challenge(login.oid).await.unwrap().status,
        LoginStatus::IDENTIFIER_VERIFIED,
        "the existing session alone does not authorize an enrollment"
    );
    assert!(matches!(
        sign_in_with_password(&service, login.oid).await,
        ChallengeOutcome::MfaEnrollmentRequired { .. }
    ));
}

#[tokio::test]
async fn factor_enrolled_elsewhere_moves_the_login_to_a_challenge() {
    let user = test_user();
    let login = aal2_login(&user);
    let (service, credentials) = enrollment_service(user, login.clone());
    sign_in_with_password(&service, login.oid).await;
    assert!(
        credentials
            .enable_totp_if_disabled(
                UserUserOid(Uuid::nil()),
                OtpCredentialData {
                    secret: "elsewhere".to_owned(),
                    digits: 6,
                    period: 30,
                    algorithm: OtpAlgorithm::Sha256,
                    last_used_counter: None,
                },
                Vec::new(),
                None,
            )
            .await
            .unwrap()
    );

    assert_eq!(
        service.prepare_challenge(login.oid).await.unwrap().status,
        LoginStatus::MFA_REQUIRED
    );
    assert_error_code(
        service
            .mfa_enrollment(login.oid, "issuer")
            .await
            .expect_err("an enrolled factor is challenged, not replaced"),
        AuthErrorCode::InvalidLoginState,
    );
}

fn phr_login(user: &User) -> Login {
    let mut login = aal2_login(user);
    login.requested_acr_values = vec![AuthenticationContextClass::PhishingResistant];
    login
}

#[tokio::test]
async fn phr_without_a_passkey_registers_one_then_signs_in_with_it() {
    let user = test_user();
    let login = phr_login(&user);
    let (passkeys, sign) = crate::authentication::passkey::tests::passkeys_without_keys();
    let (service, _) = enrollment_service(user, login.clone());
    let service = service.with_passkeys(passkeys);

    assert!(matches!(
        sign_in_with_password(&service, login.oid).await,
        ChallengeOutcome::MfaEnrollmentRequired { .. }
    ));
    let current = service.get(login.oid).await.unwrap();
    assert_eq!(
        super::super::enrollment_method(&current),
        CredentialType::Passkey
    );
    assert_error_code(
        service
            .mfa_enrollment(login.oid, "issuer")
            .await
            .expect_err("a phr login enrolls a passkey, not an authenticator app"),
        AuthErrorCode::InvalidLoginState,
    );

    let enrollment = service.passkey_enrollment(login.oid).await.unwrap();
    assert!(!enrollment.recovery_codes.is_empty());
    let registered = service
        .confirm_passkey_enrollment(
            login.oid,
            enrollment.options.challenge_id,
            "Laptop",
            serde_json::json!({}),
        )
        .await
        .unwrap();
    assert_eq!(
        registered.status,
        LoginStatus::MFA_REQUIRED,
        "registration alone must not authenticate"
    );

    let options = service.passkey_options(login.oid).await.unwrap();
    let outcome = service
        .challenge(
            login.oid,
            CredentialType::Passkey,
            &sign(&options),
            SessionContext::default(),
        )
        .await
        .unwrap();
    let ChallengeOutcome::Authenticated { session, .. } = outcome else {
        panic!("the new passkey must complete the phr login")
    };
    assert_eq!(
        session.acr,
        Some(AuthenticationContextClass::PhishingResistant)
    );
}

#[tokio::test]
async fn phr_after_a_one_time_code_still_asks_for_a_passkey() {
    let user = test_user();
    let login = phr_login(&user);
    let (passkeys, _) = crate::authentication::passkey::tests::passkeys_without_keys();
    let (mut service, _) = enrollment_service(user, login.clone());
    service.credential_repo = Arc::new(TestCredentialRepo::new(sign_in_credentials(true)));
    service.totp_verifier = Arc::new(CodeVerifier);
    let service = service.with_passkeys(passkeys);

    assert!(matches!(
        sign_in_with_password(&service, login.oid).await,
        ChallengeOutcome::MfaRequired { .. }
    ));
    let outcome = service
        .challenge(
            login.oid,
            CredentialType::Otp,
            VALID_CODE,
            SessionContext::default(),
        )
        .await
        .unwrap();
    assert!(
        matches!(outcome, ChallengeOutcome::MfaEnrollmentRequired { .. }),
        "a one-time code is multi-factor but not phishing resistant"
    );
    assert_eq!(
        service.get(login.oid).await.unwrap().status,
        LoginStatus::MFA_ENROLLMENT_REQUIRED
    );
}

#[test]
fn phr_prefers_an_enrolled_passkey() {
    let user = test_user();
    let mut login = phr_login(&user);
    login.status = LoginStatus::MFA_REQUIRED;
    assert_eq!(
        super::super::preferred_credential_type(
            &login,
            &[
                CredentialType::Password,
                CredentialType::Otp,
                CredentialType::Passkey
            ],
            identity_domain::user::MfaMethod::Otp,
        ),
        Some(CredentialType::Passkey)
    );
}

#[test]
fn a_phr_preference_offers_a_passkey_first_without_requiring_it() {
    let user = test_user();
    let mut login = aal2_login(&user);
    login.requested_acr_values = vec![
        AuthenticationContextClass::PhishingResistant,
        AuthenticationContextClass::MultiFactor,
    ];
    assert_eq!(
        login.required_acr(),
        Some(AuthenticationContextClass::MultiFactor)
    );
    let credentials = [
        CredentialType::Password,
        CredentialType::Otp,
        CredentialType::Passkey,
    ];
    for status in [LoginStatus::IDENTIFIER_VERIFIED, LoginStatus::MFA_REQUIRED] {
        login.status = status;
        assert_eq!(
            super::super::preferred_credential_type(
                &login,
                &credentials,
                identity_domain::user::MfaMethod::Otp,
            ),
            Some(CredentialType::Passkey),
            "{status:?}"
        );
    }
    // Without that preference the user's own order applies.
    login.requested_acr_values = vec![AuthenticationContextClass::MultiFactor];
    assert_eq!(
        super::super::preferred_credential_type(
            &login,
            &credentials,
            identity_domain::user::MfaMethod::Otp,
        ),
        Some(CredentialType::Otp)
    );
}
