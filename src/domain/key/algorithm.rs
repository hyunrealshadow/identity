use std::str::FromStr;

use serde::{Deserialize, Serialize};
use strum::{AsRefStr, Display, EnumIter, IntoEnumIterator, IntoStaticStr, VariantArray};

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

/// Every algorithm the installation accepts, in the order they are offered.
pub const ALL_ASYMMETRIC_KEY_ALGORITHMS: &[AsymmetricKeyAlgorithm] = &[
    AsymmetricKeyAlgorithm::EcdsaP256,
    AsymmetricKeyAlgorithm::EcdsaP384,
    AsymmetricKeyAlgorithm::EcdsaP521,
    AsymmetricKeyAlgorithm::EcdsaSecp256k1,
    AsymmetricKeyAlgorithm::Ed25519,
    AsymmetricKeyAlgorithm::Ed448,
    AsymmetricKeyAlgorithm::Rsa { bits: 2048 },
    AsymmetricKeyAlgorithm::Rsa { bits: 3072 },
    AsymmetricKeyAlgorithm::Rsa { bits: 4096 },
    AsymmetricKeyAlgorithm::X25519,
    AsymmetricKeyAlgorithm::X448,
];

impl std::fmt::Display for AsymmetricKeyAlgorithm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let name = match self {
            Self::Rsa { bits } => return write!(f, "rsa-{bits}"),
            Self::EcdsaP256 => "ecdsa-p256",
            Self::EcdsaP384 => "ecdsa-p384",
            Self::EcdsaP521 => "ecdsa-p521",
            Self::EcdsaSecp256k1 => "ecdsa-secp256k1",
            Self::Ed25519 => "ed25519",
            Self::Ed448 => "ed448",
            Self::X25519 => "x25519",
            Self::X448 => "x448",
        };

        f.write_str(name)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AsymmetricKeyAlgorithmParseError(pub String);

impl std::fmt::Display for AsymmetricKeyAlgorithmParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "unsupported asymmetric key algorithm: {} (expected one of {})",
            self.0,
            ALL_ASYMMETRIC_KEY_ALGORITHMS
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join(", ")
        )
    }
}

impl std::error::Error for AsymmetricKeyAlgorithmParseError {}

impl FromStr for AsymmetricKeyAlgorithm {
    type Err = AsymmetricKeyAlgorithmParseError;

    /// Parses the name an operator or API client writes: `ecdsa-p256`,
    /// `rsa-2048`, `ed25519`, …, matching [`std::fmt::Display`].
    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "ecdsa-p256" => Ok(Self::EcdsaP256),
            "ecdsa-p384" => Ok(Self::EcdsaP384),
            "ecdsa-p521" => Ok(Self::EcdsaP521),
            "ecdsa-secp256k1" => Ok(Self::EcdsaSecp256k1),
            "ed25519" => Ok(Self::Ed25519),
            "ed448" => Ok(Self::Ed448),
            "x25519" => Ok(Self::X25519),
            "x448" => Ok(Self::X448),
            "rsa-2048" => Ok(Self::Rsa { bits: 2048 }),
            "rsa-3072" => Ok(Self::Rsa { bits: 3072 }),
            "rsa-4096" => Ok(Self::Rsa { bits: 4096 }),
            _ => Err(AsymmetricKeyAlgorithmParseError(value.to_owned())),
        }
    }
}

#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    Hash,
    Display,
    AsRefStr,
    IntoStaticStr,
    EnumIter,
    VariantArray,
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

impl std::error::Error for JwaAlgorithmParseError {}

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

/// Algorithms accepted in a JOSE `alg` header, including symmetric signing
/// and the explicitly unsecured value used by request objects.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum JwsAlgorithm {
    None,
    Hs256,
    Hs384,
    Hs512,
    Asymmetric(JwaSigningAlgorithm),
}

impl JwsAlgorithm {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Hs256 => "HS256",
            Self::Hs384 => "HS384",
            Self::Hs512 => "HS512",
            Self::Asymmetric(value) => value.as_str(),
        }
    }
}

impl std::fmt::Display for JwsAlgorithm {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl FromStr for JwsAlgorithm {
    type Err = JwaAlgorithmParseError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "none" => Ok(Self::None),
            "HS256" => Ok(Self::Hs256),
            "HS384" => Ok(Self::Hs384),
            "HS512" => Ok(Self::Hs512),
            _ => value.parse().map(Self::Asymmetric),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::AsymmetricKeyAlgorithm;

    #[test]
    fn names_round_trip_through_the_parser() {
        for algorithm in super::ALL_ASYMMETRIC_KEY_ALGORITHMS {
            let name = algorithm.to_string();
            let parsed: AsymmetricKeyAlgorithm = name.parse().unwrap_or_else(|error| {
                panic!("{name} should parse back: {error}");
            });

            assert_eq!(&parsed, algorithm, "{name} must round-trip");
        }
    }

    #[test]
    fn unknown_names_report_the_accepted_ones() {
        let error = "rsa-1024".parse::<AsymmetricKeyAlgorithm>().unwrap_err();
        let message = error.to_string();

        assert!(message.contains("rsa-1024"), "{message}");
        assert!(message.contains("ecdsa-p256"), "{message}");
        assert!(message.contains("rsa-4096"), "{message}");
    }

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
