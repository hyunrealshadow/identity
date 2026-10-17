use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use chrono::{DateTime, Duration, Utc};
use identity_domain::{
    auth::{
        ACR_AAL1, ACR_AAL2, AMR_MFA, AMR_OTP, AMR_PASSWORD, LoginFailureReason, LoginStatus,
        MAX_FAILED_ATTEMPTS, MAX_OTP_ATTEMPTS, SessionStatus,
        model::{ActiveSession, Login, Session, SessionOid},
        repository::{
            CreateSessionInput, LoginRepository, LoginRepositoryError, SessionPage,
            SessionPageDirection, SessionRepository, SessionRepositoryError, SessionSortKey,
        },
    },
    user::{
        User, UserOid,
        repository::{UserRepository, UserRepositoryError},
    },
};
use tokio::sync::mpsc::unbounded_channel;
use uuid::Uuid;

use super::{ChallengeOutcome, LoginService, SessionContext};
use crate::{
    application::error::{AppError, code::AppErrorCode, codes::auth::AuthErrorCode},
    auth::{
        password::{HashOptions, PasswordHashError, PasswordHasher, VerifyResult},
        totp::{TotpError, TotpVerifier},
    },
    openid_connect::tests::fixtures::mocks::{
        MockDeviceAuthorizationRepository, session::MockSessionRepository,
    },
    setting::{PasswordHashSetting, SettingsSnapshot},
    user::{
        CredentialData, CredentialType, OtpAlgorithm, OtpCredentialData,
        RecoveryCodeCredentialData, UserCredential, UserCredentialOid, UserOid as UserUserOid,
        model::{Argon2Options, Argon2Password, Argon2Variant, Argon2Version, Password},
        repository::{
            UserCredentialRepository, UserCredentialRepositoryError, UserIdentifierUpdate,
            UserProfilePatch,
        },
    },
};

fn fixed_hash_options(options: HashOptions) -> Arc<SettingsSnapshot> {
    Arc::new(SettingsSnapshot::default().with::<PasswordHashSetting>(options))
}

struct AlwaysInvalidTotp;

impl TotpVerifier for AlwaysInvalidTotp {
    fn verify(&self, _otp_data: &OtpCredentialData, _code: &str) -> Result<Option<u64>, TotpError> {
        Ok(None)
    }
}

struct StubPasswordHasher;

struct TestSignInHasher;

impl PasswordHasher for TestSignInHasher {
    fn hash(&self, password: &str, options: &HashOptions) -> Result<Password, PasswordHashError> {
        StubPasswordHasher.hash(password, options)
    }

    fn verify(
        &self,
        password: &str,
        _stored: &Password,
        _options: &HashOptions,
    ) -> Result<VerifyResult, PasswordHashError> {
        Ok(if password == "correct-password" {
            VerifyResult::Success
        } else {
            VerifyResult::Failure
        })
    }
}

/// Minimal hasher for tests that change a password: it records the
/// password instead of running the (deliberately expensive) KDF.
struct RecordingPasswordHasher;

impl PasswordHasher for RecordingPasswordHasher {
    fn hash(&self, password: &str, options: &HashOptions) -> Result<Password, PasswordHashError> {
        let HashOptions::Argon2(argon2) = options;

        Ok(Password::Argon2(Argon2Password {
            hash: password.to_owned(),
            salt: "test-salt".to_owned(),
            options: argon2.clone(),
        }))
    }

    fn verify(
        &self,
        _password: &str,
        _stored: &Password,
        _options: &HashOptions,
    ) -> Result<VerifyResult, PasswordHashError> {
        Ok(VerifyResult::Failure)
    }
}

impl PasswordHasher for StubPasswordHasher {
    fn hash(&self, _password: &str, _options: &HashOptions) -> Result<Password, PasswordHashError> {
        Err(PasswordHashError::HashFailed(
            "not used in OTP tests".to_owned(),
        ))
    }

    fn verify(
        &self,
        _password: &str,
        _stored: &Password,
        _options: &HashOptions,
    ) -> Result<VerifyResult, PasswordHashError> {
        Err(PasswordHashError::HashFailed(
            "not used in OTP tests".to_owned(),
        ))
    }
}

fn test_user() -> User {
    User {
        oid: UserOid(Uuid::new_v4()),
        email: "user@example.com".to_owned(),
        email_normalized: "user@example.com".to_owned(),
        name: "user".to_owned(),
        name_normalized: "user".to_owned(),
        given_name: None,
        family_name: None,
        middle_name: None,
        nickname: None,
        profile: None,
        picture: None,
        website: None,
        gender: None,
        birthdate: None,
        zoneinfo: None,
        locale: None,
        theme: None,
        preferred_mfa_method: Default::default(),
        email_verified: true,
        phone_number: None,
        phone_number_verified: None,
        address_formatted: None,
        address_street_address: None,
        address_locality: None,
        address_region: None,
        address_postal_code: None,
        address_country: None,
        failed_attempts: 0,
        enabled: true,
        locked: false,
        locked_until: None,
        created_at: Utc::now(),
        updated_at: None,
    }
}

fn test_login(user_oid: Uuid, failed_attempts: i32) -> Login {
    Login {
        oid: Uuid::new_v4(),
        client_oid: Uuid::new_v4(),
        client_authorization_oid: Uuid::new_v4(),
        session_oid: None,
        user_oid: Some(user_oid),
        status: LoginStatus::MFA_REQUIRED,
        failed_attempts,
        created_at: Utc::now(),
        expires_at: Utc::now() + Duration::minutes(5),
        acr: None,
        requested_acr: None,
    }
}

fn otp_service(login_repo: Arc<TestLoginRepo>, user: User) -> (LoginService, Arc<Mutex<User>>) {
    let user = Arc::new(Mutex::new(user));
    let service = LoginService::new(
        Arc::new(TestUserRepo {
            user: Arc::clone(&user),
        }),
        Arc::new(TestCredentialRepo {
            credentials: vec![UserCredential {
                oid: UserCredentialOid(Uuid::new_v4()),
                r#type: CredentialType::Otp,
                data: CredentialData::Otp(OtpCredentialData {
                    secret: "secret".to_owned(),
                    digits: 6,
                    period: 30,
                    algorithm: OtpAlgorithm::Sha1,
                    last_used_counter: None,
                }),
            }],
        }),
        Arc::new(TestSessionRepo),
        login_repo,
        Arc::new(StubPasswordHasher),
        Arc::new(AlwaysInvalidTotp),
        fixed_hash_options(HashOptions::Argon2(Argon2Options {
            variant: Argon2Variant::Argon2id,
            version: Argon2Version::Argon2013,
            time_cost: 3,
            memory_cost: 65_536,
            parallelism: 4,
        })),
    );
    (service, user)
}

fn assert_error_code(error: AppError, expected: AuthErrorCode) {
    assert_eq!(error.code(), expected.code());
}

fn browser_session(user_oid: Uuid) -> ActiveSession {
    let now = Utc::now();
    ActiveSession {
        session_oid: SessionOid(Uuid::new_v4()),
        user_oid,
        user_name: "user".to_owned(),
        user_email: "user@example.com".to_owned(),
        user_picture: None,
        last_active_at: Some(now),
        expires_at: Some(now + Duration::hours(1)),
        created_at: now - Duration::days(6),
        authenticated_at: now - Duration::days(6),
        acr: Some(ACR_AAL1.to_owned()),
        amr: vec![AMR_PASSWORD.to_owned()],
    }
}

fn sign_in_service(user: User, logins: Vec<Login>, mfa: bool) -> LoginService {
    let login_repo = Arc::new(TestLoginRepo {
        state: Arc::new(Mutex::new(TestLoginRepoState {
            logins,
            ..Default::default()
        })),
    });
    let (mut service, _) = otp_service(login_repo, user);
    let mut credentials = if mfa {
        vec![UserCredential {
            oid: UserCredentialOid(Uuid::new_v4()),
            r#type: CredentialType::Otp,
            data: CredentialData::Otp(OtpCredentialData {
                secret: "secret".to_owned(),
                digits: 6,
                period: 30,
                algorithm: OtpAlgorithm::Sha1,
                last_used_counter: None,
            }),
        }]
    } else {
        Vec::new()
    };
    credentials.push(UserCredential {
        oid: UserCredentialOid(Uuid::new_v4()),
        r#type: CredentialType::Password,
        data: CredentialData::Password(Password::Argon2(Argon2Password {
            hash: "stored-hash".to_owned(),
            salt: "stored-salt".to_owned(),
            options: Argon2Options {
                variant: Argon2Variant::Argon2id,
                version: Argon2Version::Argon2013,
                time_cost: 3,
                memory_cost: 65_536,
                parallelism: 4,
            },
        })),
    });
    service.credential_repo = Arc::new(TestCredentialRepo { credentials });
    service.password_hasher = Arc::new(TestSignInHasher);
    service
}

mod attempts;
mod passkey;
mod password_change;
mod priority;
mod reauthentication;
mod sessions;

mod repositories;
use repositories::{
    TestCredentialRepo, TestLoginRepo, TestLoginRepoState, TestSessionRepo, TestUserRepo,
};
