use serde::{Deserialize, Serialize};
use strum::{AsRefStr, Display};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default, Display, AsRefStr)]
#[serde(rename_all = "UPPERCASE")]
#[strum(serialize_all = "UPPERCASE")]
pub enum OtpAlgorithm {
    Sha1,
    #[default]
    Sha256,
    Sha512,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OtpCredentialData {
    pub secret: String,
    pub digits: u8,
    #[serde(default = "default_period")]
    pub period: u32,
    #[serde(default)]
    pub algorithm: OtpAlgorithm,
    /// Highest TOTP time-step successfully consumed by the verifier.
    #[serde(default)]
    pub last_used_counter: Option<u64>,
}

fn default_period() -> u32 {
    30
}

#[cfg(test)]
mod tests {
    use super::OtpAlgorithm;

    #[test]
    fn otp_algorithm_defaults_to_sha256() {
        assert_eq!(OtpAlgorithm::default(), OtpAlgorithm::Sha256);
    }
}
