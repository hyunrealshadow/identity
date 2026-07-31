use totp_rs::{Algorithm, Secret, TOTP};

use identity_domain::{
    auth::totp::{TotpError, TotpVerifier},
    user::model::{OtpAlgorithm, OtpCredentialData},
};

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
    fn verify(&self, otp_data: &OtpCredentialData, code: &str) -> Result<bool, TotpError> {
        let algorithm = to_totp_algorithm(&otp_data.algorithm);

        let secret = Secret::Encoded(otp_data.secret.clone())
            .to_bytes()
            .map_err(|e| TotpError::InvalidCredentialData(e.to_string()))?;

        let totp = build_totp(algorithm, otp_data.digits, otp_data.period, secret)?;

        totp.check_current(code)
            .map_err(|e| TotpError::Internal(e.to_string()))
    }
}

fn build_totp(
    algorithm: Algorithm,
    digits: u8,
    period: u32,
    secret: Vec<u8>,
) -> Result<TOTP, TotpError> {
    TOTP::new(
        algorithm,
        digits as usize,
        TOTP_ALLOWED_SKEW_STEPS,
        period as u64,
        secret,
        None,
        String::new(),
    )
    .map_err(|e| TotpError::InvalidCredentialData(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::{TOTP_ALLOWED_SKEW_STEPS, build_totp};
    use totp_rs::Algorithm;

    #[test]
    fn verifier_accepts_previous_and_next_time_steps() {
        assert_eq!(TOTP_ALLOWED_SKEW_STEPS, 1);
        let totp = build_totp(Algorithm::SHA1, 6, 30, b"01234567890123456789".to_vec()).unwrap();
        let now = 1_700_000_010;

        assert!(totp.check(&totp.generate(now - 30), now));
        assert!(totp.check(&totp.generate(now), now));
        assert!(totp.check(&totp.generate(now + 30), now));
        assert!(!totp.check(&totp.generate(now + 60), now));
    }
}
