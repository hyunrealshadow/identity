use std::str::FromStr;

use serde::{Deserialize, Serialize};
use strum::{
    AsRefStr, Display, EnumIter, IntoEnumIterator, IntoStaticStr, VariantArray,
};

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AsymmetricKeyAlgorithm {
    Rsa { bits: usize },
    EcdsaP256,
    EcdsaP384,
    EcdsaP521,
    EcdsaSecp256k1,
    Ed25519,
    Ed448,
    X25519,
    X448,
}

impl AsymmetricKeyAlgorithm {
    pub fn validate(&self) -> Result<(), String> {
        match self {
            Self::Rsa { bits } if *bits < 2048 => Err("rsa bits must be at least 2048".to_owned()),
            _ => Ok(()),
        }
    }
}

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Hash, Display, AsRefStr, IntoStaticStr, EnumIter, VariantArray,
)]
pub enum JwaSigningAlgorithm {
    #[strum(serialize = "RS256")]
    Rs256,
    #[strum(serialize = "RS384")]
    Rs384,
    #[strum(serialize = "RS512")]
    Rs512,
    #[strum(serialize = "PS256")]
    Ps256,
    #[strum(serialize = "PS384")]
    Ps384,
    #[strum(serialize = "PS512")]
    Ps512,
    #[strum(serialize = "ES256")]
    Es256,
    #[strum(serialize = "ES384")]
    Es384,
    #[strum(serialize = "ES512")]
    Es512,
    #[strum(serialize = "ES256K")]
    Es256k,
    #[strum(serialize = "EdDSA")]
    EdDsa,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JwaAlgorithmParseError(pub String);

impl std::fmt::Display for JwaAlgorithmParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "unsupported JWA algorithm: {}", self.0)
    }
}

impl JwaSigningAlgorithm {
    pub fn as_str(self) -> &'static str {
        self.into()
    }

    pub fn all() -> &'static [Self] {
        Self::VARIANTS
    }

    /// Returns algorithm labels that should be trialed for a given key type.
    /// Trials are needed because RSA and RSA-PSS keys are both `Rsa { .. }`
    /// but support different algorithm subsets.
    pub fn trials_for_key_type(algo: &AsymmetricKeyAlgorithm) -> &'static [Self] {
        match algo {
            AsymmetricKeyAlgorithm::Rsa { .. } => &[
                Self::Ps256,
                Self::Ps384,
                Self::Ps512,
                Self::Rs256,
                Self::Rs384,
                Self::Rs512,
            ],
            AsymmetricKeyAlgorithm::EcdsaP256 => &[Self::Es256],
            AsymmetricKeyAlgorithm::EcdsaP384 => &[Self::Es384],
            AsymmetricKeyAlgorithm::EcdsaP521 => &[Self::Es512],
            AsymmetricKeyAlgorithm::EcdsaSecp256k1 => &[Self::Es256k],
            AsymmetricKeyAlgorithm::Ed25519 | AsymmetricKeyAlgorithm::Ed448 => &[Self::EdDsa],
            AsymmetricKeyAlgorithm::X25519 | AsymmetricKeyAlgorithm::X448 => &[],
        }
    }

    /// Best algorithm name for a given key type (used for signing key selection).
    pub fn primary_for_key_type(algo: &AsymmetricKeyAlgorithm) -> Self {
        match algo {
            AsymmetricKeyAlgorithm::Rsa { bits } if *bits >= 4096 => Self::Rs512,
            AsymmetricKeyAlgorithm::Rsa { bits } if *bits >= 3072 => Self::Rs384,
            AsymmetricKeyAlgorithm::Rsa { .. } => Self::Rs256,
            AsymmetricKeyAlgorithm::EcdsaP256 => Self::Es256,
            AsymmetricKeyAlgorithm::EcdsaP384 => Self::Es384,
            AsymmetricKeyAlgorithm::EcdsaP521 => Self::Es512,
            AsymmetricKeyAlgorithm::EcdsaSecp256k1 => Self::Es256k,
            AsymmetricKeyAlgorithm::Ed25519 | AsymmetricKeyAlgorithm::Ed448 => Self::EdDsa,
            AsymmetricKeyAlgorithm::X25519 | AsymmetricKeyAlgorithm::X448 => Self::EdDsa,
        }
    }

    pub fn at_hash_bits(self) -> usize {
        match self {
            Self::Rs384 | Self::Ps384 | Self::Es384 => 384,
            Self::Rs512 | Self::Ps512 | Self::Es512 | Self::EdDsa => 512,
            _ => 256,
        }
    }
}

impl FromStr for JwaSigningAlgorithm {
    type Err = JwaAlgorithmParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::iter()
            .find(|variant| variant.as_ref() == s)
            .ok_or_else(|| JwaAlgorithmParseError(s.to_owned()))
    }
}

#[cfg(test)]
mod tests {
    use super::AsymmetricKeyAlgorithm;

    #[test]
    fn rejects_rsa_below_2048_bits() {
        let result = AsymmetricKeyAlgorithm::Rsa { bits: 1024 }.validate();

        assert_eq!(result, Err("rsa bits must be at least 2048".to_owned()));
    }

    #[test]
    fn parses_all_jwa_algorithms() {
        use super::JwaSigningAlgorithm;
        for alg in JwaSigningAlgorithm::all() {
            let parsed: JwaSigningAlgorithm = alg.as_str().parse().unwrap();
            assert_eq!(parsed, *alg);
        }
    }

    #[test]
    fn rejects_unknown_algorithm() {
        use super::JwaSigningAlgorithm;
        let result: Result<JwaSigningAlgorithm, _> = "FOO".parse();
        assert!(result.is_err());
    }
}
