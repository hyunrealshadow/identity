//! TOTP verification abstraction.

use thiserror::Error;

use crate::user::OtpCredentialData;

#[derive(Debug, Error)]
pub enum TotpError {
    #[error("invalid TOTP credential data: {0}")]
    InvalidCredentialData(String),

    #[error("TOTP internal error: {0}")]
    Internal(String),
}

pub trait TotpVerifier: Send + Sync {
    /// Returns the matching TOTP counter. Persistence must atomically consume
    /// this counter before authentication is considered successful.
    fn verify(&self, otp_data: &OtpCredentialData, code: &str) -> Result<Option<u64>, TotpError>;
}
