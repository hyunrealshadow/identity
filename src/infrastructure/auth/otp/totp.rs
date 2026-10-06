use std::time::{SystemTime, UNIX_EPOCH};

use identity_application::{
    auth::{
        mfa::{GeneratedTotpEnrollment, TotpEnrollmentGenerator},
        totp::{TotpError, TotpVerifier},
    },
    user::model::{OtpAlgorithm, OtpCredentialData},
};
use subtle::ConstantTimeEq as _;
use totp_rs::{Algorithm, Builder, Secret, Totp};

const TOTP_ALLOWED_SKEW_STEPS: u8 = 1;

fn to_totp_algorithm(alg: &OtpAlgorithm) -> Algorithm {
    match alg {
        OtpAlgorithm::Sha1 => Algorithm::SHA1,
        OtpAlgorithm::Sha256 => Algorithm::SHA256,
        OtpAlgorithm::Sha512 => Algorithm::SHA512,
    }
}

pub struct TotpVerifierImpl;

impl TotpVerifier for TotpVerifierImpl {
    fn verify(&self, otp_data: &OtpCredentialData, code: &str) -> Result<Option<u64>, TotpError> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|error| TotpError::Internal(error.to_string()))?
            .as_secs();
        verify_at(otp_data, code, now)
    }
}

fn verify_at(
    otp_data: &OtpCredentialData,
    code: &str,
    unix_time: u64,
) -> Result<Option<u64>, TotpError> {
    if otp_data.period == 0 {
        return Err(TotpError::InvalidCredentialData(
            "TOTP period must be greater than zero".to_owned(),
        ));
    }
    let algorithm = to_totp_algorithm(&otp_data.algorithm);

    let secret = Secret::try_from_base32(&otp_data.secret)
        .map_err(|e| TotpError::InvalidCredentialData(e.to_string()))?;

    let totp = build_totp(algorithm, otp_data.digits, otp_data.period, secret)?;
    let current_counter = unix_time / u64::from(otp_data.period);
    let candidates = [
        Some(current_counter),
        current_counter.checked_sub(1),
        current_counter.checked_add(1),
    ];
    for counter in candidates.into_iter().flatten() {
        let Some(candidate_time) = counter.checked_mul(u64::from(otp_data.period)) else {
            continue;
        };
        let expected = totp.generate(candidate_time).to_string();
        if bool::from(expected.as_bytes().ct_eq(code.as_bytes())) {
            return Ok(Some(counter));
        }
    }
    Ok(None)
}

impl TotpEnrollmentGenerator for TotpVerifierImpl {
    fn generate(
        &self,
        issuer: &str,
        account_name: &str,
    ) -> Result<GeneratedTotpEnrollment, TotpError> {
        let algorithm = OtpAlgorithm::default();
        let secret = Secret::generate().to_base32();
        let credential = OtpCredentialData {
            secret,
            digits: 6,
            period: 30,
            algorithm,
            last_used_counter: None,
        };
        let otp_auth_uri = self.otp_auth_uri(issuer, account_name, &credential)?;
        Ok(GeneratedTotpEnrollment {
            credential,
            otp_auth_uri,
        })
    }

    fn otp_auth_uri(
        &self,
        issuer: &str,
        account_name: &str,
        credential: &OtpCredentialData,
    ) -> Result<String, TotpError> {
        let secret = Secret::try_from_base32(&credential.secret)
            .map_err(|error| TotpError::InvalidCredentialData(error.to_string()))?;
        totp_builder(
            to_totp_algorithm(&credential.algorithm),
            credential.digits,
            credential.period,
            secret,
        )
        .with_issuer(Some(issuer))
        .with_account_name(account_name)
        .build()
        .and_then(|totp| totp.to_url())
        .map_err(|error| TotpError::InvalidCredentialData(error.to_string()))
    }
}

fn build_totp(
    algorithm: Algorithm,
    digits: u8,
    period: u32,
    secret: impl Into<Secret>,
) -> Result<Totp, TotpError> {
    totp_builder(algorithm, digits, period, secret)
        .build()
        .map_err(|e| TotpError::InvalidCredentialData(e.to_string()))
}

fn totp_builder(
    algorithm: Algorithm,
    digits: u8,
    period: u32,
    secret: impl Into<Secret>,
) -> Builder {
    Builder::new()
        .with_algorithm(algorithm)
        .with_digits(digits)
        .with_skew(u16::from(TOTP_ALLOWED_SKEW_STEPS))
        .with_step_duration(u64::from(period))
        .with_secret(secret)
}

#[cfg(test)]
mod tests {
    use identity_application::{
        auth::mfa::TotpEnrollmentGenerator,
        user::{OtpAlgorithm, OtpCredentialData},
    };
    use totp_rs::{Algorithm, Secret};

    use super::{TotpVerifierImpl, build_totp, verify_at};

    #[test]
    fn verifier_accepts_previous_and_next_time_steps() {
        let totp = build_totp(Algorithm::SHA1, 6, 30, b"01234567890123456789".to_vec()).unwrap();
        let credential = OtpCredentialData {
            secret: Secret::from(b"01234567890123456789".as_slice()).to_base32(),
            digits: 6,
            period: 30,
            algorithm: OtpAlgorithm::Sha1,
            last_used_counter: None,
        };
        let now = 1_700_000_010;
        for timestamp in [now - 60, now - 30, now, now + 30, now + 60] {
            let code = totp.generate(timestamp).to_string();
            let expected = (timestamp.abs_diff(now) <= 30).then_some(timestamp / 30);
            assert_eq!(verify_at(&credential, &code, now).unwrap(), expected);
        }
    }

    #[test]
    fn verifier_returns_the_exact_matching_counter() {
        let credential = OtpCredentialData {
            secret: Secret::from(b"01234567890123456789".as_slice()).to_base32(),
            digits: 6,
            period: 30,
            algorithm: OtpAlgorithm::Sha1,
            last_used_counter: None,
        };
        let now = 1_700_000_010;
        let counter = (now - 30) / 30;
        let totp = build_totp(Algorithm::SHA1, 6, 30, b"01234567890123456789".to_vec()).unwrap();
        let code = totp.generate(counter * 30).to_string();

        assert_eq!(verify_at(&credential, &code, now).unwrap(), Some(counter));
        assert_eq!(verify_at(&credential, "000000", now).unwrap(), None);
    }

    #[test]
    fn enrollment_defaults_to_sha256() {
        let enrollment = TotpVerifierImpl
            .generate("Identity", "user@example.com")
            .unwrap();

        assert_eq!(enrollment.credential.algorithm, OtpAlgorithm::Sha256);
        assert!(enrollment.otp_auth_uri.contains("algorithm=SHA256"));
    }
}
