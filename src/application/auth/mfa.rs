use std::sync::Arc;

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::{Duration, Utc};
use rand::RngExt;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use identity_domain::{
    auth::{totp::TotpError, totp::TotpVerifier},
    user::{
        CredentialData, CredentialType, OtpCredentialData, RecoveryCodeCredentialData, UserOid,
        repository::UserCredentialRepository,
    },
};

use crate::{
    data_protection::DataProtector,
    error::{AppError, codes::auth::AuthErrorCode},
};

const ENROLLMENT_PURPOSE: &str = "identity.mfa.totp-enrollment.v1";
const ENROLLMENT_LIFETIME: Duration = Duration::minutes(10);
const RECOVERY_CODE_COUNT: usize = 10;

pub struct GeneratedTotpEnrollment {
    pub credential: OtpCredentialData,
    pub otpauth_uri: String,
}

pub trait TotpEnrollmentGenerator: Send + Sync {
    fn generate(
        &self,
        issuer: &str,
        account_name: &str,
    ) -> Result<GeneratedTotpEnrollment, TotpError>;
}

#[derive(Debug, Clone)]
pub struct MfaStatus {
    pub totp_enabled: bool,
    pub recovery_codes_remaining: usize,
}

#[derive(Debug, Clone)]
pub struct BeginTotpEnrollment {
    pub secret: String,
    pub otpauth_uri: String,
    pub enrollment_token: String,
}

#[derive(Debug, Clone)]
pub struct ConfirmTotpEnrollment {
    pub recovery_codes: Vec<String>,
}

#[derive(Serialize, Deserialize)]
struct PendingTotpEnrollment {
    user_oid: UserOid,
    expires_at: chrono::DateTime<Utc>,
    credential: OtpCredentialData,
}

pub struct MfaService {
    credential_repo: Arc<dyn UserCredentialRepository>,
    verifier: Arc<dyn TotpVerifier>,
    generator: Arc<dyn TotpEnrollmentGenerator>,
    data_protector: Arc<dyn DataProtector>,
}

impl MfaService {
    #[must_use]
    pub fn new(
        credential_repo: Arc<dyn UserCredentialRepository>,
        verifier: Arc<dyn TotpVerifier>,
        generator: Arc<dyn TotpEnrollmentGenerator>,
        data_protector: Arc<dyn DataProtector>,
    ) -> Self {
        Self {
            credential_repo,
            verifier,
            generator,
            data_protector,
        }
    }

    pub async fn status(&self, user_oid: UserOid) -> Result<MfaStatus, AppError> {
        let totp_enabled = !self
            .credential_repo
            .find_by_user_oid_and_type(user_oid, CredentialType::Otp)
            .await?
            .is_empty();
        let recovery_codes_remaining = self
            .credential_repo
            .find_by_user_oid_and_type(user_oid, CredentialType::RecoveryCode)
            .await?
            .len();
        Ok(MfaStatus {
            totp_enabled,
            recovery_codes_remaining,
        })
    }

    pub async fn begin_totp_enrollment(
        &self,
        user_oid: UserOid,
        issuer: &str,
        account_name: &str,
    ) -> Result<BeginTotpEnrollment, AppError> {
        if self.status(user_oid).await?.totp_enabled {
            return Err(AppError::from_code(AuthErrorCode::TotpAlreadyEnabled));
        }
        let generated = self.generator.generate(issuer, account_name)?;
        let pending = PendingTotpEnrollment {
            user_oid,
            expires_at: Utc::now() + ENROLLMENT_LIFETIME,
            credential: generated.credential.clone(),
        };
        let plaintext = serde_json::to_vec(&pending).map_err(|error| {
            AppError::from_code(crate::error::codes::common::CommonErrorCode::InternalError)
                .with_source(error)
        })?;
        let enrollment_token = self
            .data_protector
            .protect(ENROLLMENT_PURPOSE, &plaintext)
            .await?;
        Ok(BeginTotpEnrollment {
            secret: generated.credential.secret,
            otpauth_uri: generated.otpauth_uri,
            enrollment_token,
        })
    }

    pub async fn confirm_totp_enrollment(
        &self,
        user_oid: UserOid,
        enrollment_token: &str,
        code: &str,
    ) -> Result<ConfirmTotpEnrollment, AppError> {
        if self.status(user_oid).await?.totp_enabled {
            return Err(AppError::from_code(AuthErrorCode::TotpAlreadyEnabled));
        }
        let plaintext = self
            .data_protector
            .unprotect(ENROLLMENT_PURPOSE, enrollment_token)
            .await
            .map_err(|_| AppError::from_code(AuthErrorCode::InvalidTotpEnrollment))?;
        let pending: PendingTotpEnrollment = serde_json::from_slice(&plaintext)
            .map_err(|_| AppError::from_code(AuthErrorCode::InvalidTotpEnrollment))?;
        if pending.user_oid != user_oid || pending.expires_at < Utc::now() {
            return Err(AppError::from_code(AuthErrorCode::InvalidTotpEnrollment));
        }
        if !self.verifier.verify(&pending.credential, code)? {
            return Err(AppError::from_code(AuthErrorCode::InvalidOtp).with_field("code"));
        }
        let (recovery_codes, recovery_credentials) = generate_recovery_codes();
        self.credential_repo
            .replace_by_user_oid(
                user_oid,
                vec![
                    (
                        CredentialType::Otp,
                        vec![CredentialData::Otp(pending.credential)],
                    ),
                    (CredentialType::RecoveryCode, recovery_credentials),
                ],
            )
            .await?;
        Ok(ConfirmTotpEnrollment { recovery_codes })
    }

    pub async fn disable_totp(&self, user_oid: UserOid) -> Result<(), AppError> {
        if !self.status(user_oid).await?.totp_enabled {
            return Err(AppError::from_code(AuthErrorCode::TotpNotEnabled));
        }
        self.credential_repo
            .replace_by_user_oid(
                user_oid,
                vec![
                    (CredentialType::Otp, Vec::new()),
                    (CredentialType::RecoveryCode, Vec::new()),
                ],
            )
            .await?;
        Ok(())
    }

    pub async fn regenerate_recovery_codes(
        &self,
        user_oid: UserOid,
    ) -> Result<Vec<String>, AppError> {
        if !self.status(user_oid).await?.totp_enabled {
            return Err(AppError::from_code(AuthErrorCode::TotpNotEnabled));
        }
        let (codes, credentials) = generate_recovery_codes();
        self.credential_repo
            .replace_by_user_oid(user_oid, vec![(CredentialType::RecoveryCode, credentials)])
            .await?;
        Ok(codes)
    }
}

pub fn recovery_code_hash(code: &str) -> String {
    let normalized: String = code
        .chars()
        .filter(|character| *character != '-' && !character.is_whitespace())
        .map(|character| character.to_ascii_uppercase())
        .collect();
    URL_SAFE_NO_PAD.encode(Sha256::digest(normalized.as_bytes()))
}

fn generate_recovery_codes() -> (Vec<String>, Vec<CredentialData>) {
    let codes = (0..RECOVERY_CODE_COUNT)
        .map(|_| {
            const ALPHABET: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";
            let mut bytes = [0u8; 16];
            rand::rng().fill(&mut bytes);
            let encoded = bytes
                .into_iter()
                .map(|byte| ALPHABET[(byte & 31) as usize] as char)
                .collect::<String>();
            format!(
                "{}-{}-{}-{}",
                &encoded[0..4],
                &encoded[4..8],
                &encoded[8..12],
                &encoded[12..16]
            )
        })
        .collect::<Vec<_>>();
    let credentials = codes
        .iter()
        .map(|code| {
            CredentialData::RecoveryCode(RecoveryCodeCredentialData {
                hash: recovery_code_hash(code),
            })
        })
        .collect();
    (codes, credentials)
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use async_trait::async_trait;
    use base64::{Engine as _, engine::general_purpose::STANDARD};
    use identity_domain::{
        auth::totp::{TotpError, TotpVerifier},
        data_protection::DataProtectionError,
        user::{
            CredentialData, CredentialType, OtpAlgorithm, OtpCredentialData, Password,
            UserCredential, UserCredentialOid, UserOid,
            repository::{UserCredentialRepository, UserCredentialRepositoryError},
        },
    };
    use uuid::Uuid;

    use super::{GeneratedTotpEnrollment, MfaService, TotpEnrollmentGenerator, recovery_code_hash};
    use crate::data_protection::DataProtector;

    #[test]
    fn recovery_code_hash_ignores_case_and_separators() {
        assert_eq!(
            recovery_code_hash("abcd-efgh-ijkl-mnop"),
            recovery_code_hash("ABCDEFGHIJKLMNOP")
        );
    }

    struct TestGenerator;

    impl TotpEnrollmentGenerator for TestGenerator {
        fn generate(
            &self,
            _issuer: &str,
            _account_name: &str,
        ) -> Result<GeneratedTotpEnrollment, TotpError> {
            Ok(GeneratedTotpEnrollment {
                credential: OtpCredentialData {
                    secret: "JBSWY3DPEHPK3PXP".to_owned(),
                    digits: 6,
                    period: 30,
                    algorithm: OtpAlgorithm::Sha1,
                },
                otpauth_uri: "otpauth://totp/example".to_owned(),
            })
        }
    }

    struct AlwaysValid;

    impl TotpVerifier for AlwaysValid {
        fn verify(&self, _otp_data: &OtpCredentialData, _code: &str) -> Result<bool, TotpError> {
            Ok(true)
        }
    }

    struct TestProtector;

    #[async_trait]
    impl DataProtector for TestProtector {
        async fn protect(
            &self,
            _purpose: &str,
            plaintext: &[u8],
        ) -> Result<String, DataProtectionError> {
            Ok(STANDARD.encode(plaintext))
        }

        async fn unprotect(
            &self,
            _purpose: &str,
            token: &str,
        ) -> Result<Vec<u8>, DataProtectionError> {
            STANDARD
                .decode(token)
                .map_err(|_| DataProtectionError::InvalidProtectedPayload)
        }
    }

    #[derive(Default)]
    struct TestCredentialRepo {
        credentials: Mutex<Vec<UserCredential>>,
    }

    #[async_trait]
    impl UserCredentialRepository for TestCredentialRepo {
        async fn find_by_user_oid_and_type(
            &self,
            _user_oid: UserOid,
            credential_type: CredentialType,
        ) -> Result<Vec<UserCredential>, UserCredentialRepositoryError> {
            Ok(self
                .credentials
                .lock()
                .unwrap()
                .iter()
                .filter(|credential| credential.r#type == credential_type)
                .cloned()
                .collect())
        }

        async fn update_password_by_oid(
            &self,
            _credential_oid: UserCredentialOid,
            _password: &Password,
        ) -> Result<(), UserCredentialRepositoryError> {
            Ok(())
        }

        async fn replace_by_user_oid(
            &self,
            _user_oid: UserOid,
            replacements: Vec<(CredentialType, Vec<CredentialData>)>,
        ) -> Result<(), UserCredentialRepositoryError> {
            let mut credentials = self.credentials.lock().unwrap();
            for (credential_type, values) in replacements {
                credentials.retain(|credential| credential.r#type != credential_type);
                credentials.extend(values.into_iter().map(|data| UserCredential {
                    oid: UserCredentialOid(Uuid::new_v4()),
                    r#type: credential_type.clone(),
                    data,
                }));
            }
            Ok(())
        }

        async fn delete_by_oid(
            &self,
            credential_oid: UserCredentialOid,
        ) -> Result<bool, UserCredentialRepositoryError> {
            let mut credentials = self.credentials.lock().unwrap();
            let before = credentials.len();
            credentials.retain(|credential| credential.oid != credential_oid);
            Ok(credentials.len() + 1 == before)
        }
    }

    #[tokio::test]
    async fn confirmation_enables_totp_and_creates_hashed_recovery_codes() {
        let repo = Arc::new(TestCredentialRepo::default());
        let service = MfaService::new(
            repo.clone(),
            Arc::new(AlwaysValid),
            Arc::new(TestGenerator),
            Arc::new(TestProtector),
        );
        let user_oid = UserOid(Uuid::new_v4());
        let enrollment = service
            .begin_totp_enrollment(user_oid, "example.com", "user@example.com")
            .await
            .unwrap();
        let confirmed = service
            .confirm_totp_enrollment(user_oid, &enrollment.enrollment_token, "123456")
            .await
            .unwrap();

        assert_eq!(confirmed.recovery_codes.len(), 10);
        assert!(service.status(user_oid).await.unwrap().totp_enabled);
        assert_eq!(
            service
                .status(user_oid)
                .await
                .unwrap()
                .recovery_codes_remaining,
            10
        );
        let stored = repo.credentials.lock().unwrap();
        assert!(stored.iter().all(|credential| match &credential.data {
            CredentialData::RecoveryCode(data) => !confirmed.recovery_codes.contains(&data.hash),
            _ => true,
        }));
    }
}
