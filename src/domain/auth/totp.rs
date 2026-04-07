//! TOTP verification abstraction.

use thiserror::Error;

use crate::domain::user::model::OtpCredentialData;

#[derive(Debug, Error)]
pub enum TotpError {
    #[error("invalid TOTP credential data: {0}")]
    InvalidCredentialData(String),

    #[error("TOTP internal error: {0}")]
    Internal(String),
}

pub trait TotpVerifier: Send + Sync {
    fn verify(&self, otp_data: &OtpCredentialData, code: &str) -> Result<bool, TotpError>;
}

#[cfg(test)]
mod tests {
    use super::TotpError;

    #[test]
    fn invalid_credential_error_formats_human_readable_message() {
        let error = TotpError::InvalidCredentialData("bad secret".to_owned());

        assert_eq!(
            error.to_string(),
            "invalid TOTP credential data: bad secret"
        );
    }

    #[test]
    fn internal_error_formats_human_readable_message() {
        let error = TotpError::Internal("clock failure".to_owned());

        assert_eq!(error.to_string(), "TOTP internal error: clock failure");
    }
}
