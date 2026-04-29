use totp_rs::{Algorithm, Secret, TOTP};

use identity_domain::{
    auth::totp::{TotpError, TotpVerifier},
    user::model::{OtpAlgorithm, OtpCredentialData},
};

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

        let totp = TOTP::new(
            algorithm,
            otp_data.digits as usize,
            1,
            otp_data.period as u64,
            secret,
            None,
            String::new(),
        )
        .map_err(|e| TotpError::InvalidCredentialData(e.to_string()))?;

        totp.check_current(code)
            .map_err(|e| TotpError::Internal(e.to_string()))
    }
}
