use std::{
    error::Error,
    fmt::{Display as FmtDisplay, Formatter, Result as FmtResult},
    str::FromStr,
};

use serde::{Deserialize, Serialize};
use strum::{AsRefStr, Display, EnumIter, IntoEnumIterator, IntoStaticStr, VariantArray};

/// Every key type this instance generates. A closed set: RSA comes in the
/// three offered sizes only.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, EnumIter, VariantArray,
)]
pub enum AsymmetricKeyAlgorithm {
    #[serde(rename = "RSA_2048")]
    Rsa2048,
    #[serde(rename = "RSA_3072")]
    Rsa3072,
    #[serde(rename = "RSA_4096")]
    Rsa4096,
    #[serde(rename = "ECDSA_P256")]
    EcdsaP256,
    #[serde(rename = "ECDSA_P384")]
    EcdsaP384,
    #[serde(rename = "ECDSA_P521")]
    EcdsaP521,
    #[serde(rename = "ECDSA_SECP256K1")]
    EcdsaSecp256k1,
    #[serde(rename = "ED25519")]
    Ed25519,
    #[serde(rename = "ED448")]
    Ed448,
    #[serde(rename = "X25519")]
    X25519,
    #[serde(rename = "X448")]
    X448,
}

impl AsymmetricKeyAlgorithm {
    /// The key type as an operator reads it, such as `ECDSA P-256` or `RSA 2048`.
    #[must_use]
    pub const fn display_name(self) -> &'static str {
        match self {
            Self::Rsa2048 => "RSA 2048",
            Self::Rsa3072 => "RSA 3072",
            Self::Rsa4096 => "RSA 4096",
            Self::EcdsaP256 => "ECDSA P-256",
            Self::EcdsaP384 => "ECDSA P-384",
            Self::EcdsaP521 => "ECDSA P-521",
            Self::EcdsaSecp256k1 => "ECDSA secp256k1",
            Self::Ed25519 => "Ed25519",
            Self::Ed448 => "Ed448",
            Self::X25519 => "X25519",
            Self::X448 => "X448",
        }
    }

    /// The modulus size of an RSA key.
    #[must_use]
    pub const fn rsa_bits(self) -> Option<usize> {
        match self {
            Self::Rsa2048 => Some(2048),
            Self::Rsa3072 => Some(3072),
            Self::Rsa4096 => Some(4096),
            _ => None,
        }
    }

    /// The RSA key type of a modulus size, if it is one of the offered sizes.
    #[must_use]
    pub const fn from_rsa_bits(bits: usize) -> Option<Self> {
        match bits {
            2048 => Some(Self::Rsa2048),
            3072 => Some(Self::Rsa3072),
            4096 => Some(Self::Rsa4096),
            _ => None,
        }
    }

    #[must_use]
    pub const fn is_rsa(self) -> bool {
        self.rsa_bits().is_some()
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
    AsymmetricKeyAlgorithm::Rsa2048,
    AsymmetricKeyAlgorithm::Rsa3072,
    AsymmetricKeyAlgorithm::Rsa4096,
    AsymmetricKeyAlgorithm::X25519,
    AsymmetricKeyAlgorithm::X448,
];

impl FmtDisplay for AsymmetricKeyAlgorithm {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        let name = match self {
            Self::Rsa2048 => "rsa-2048",
            Self::Rsa3072 => "rsa-3072",
            Self::Rsa4096 => "rsa-4096",
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

impl FmtDisplay for AsymmetricKeyAlgorithmParseError {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
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

impl Error for AsymmetricKeyAlgorithmParseError {}

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
            "rsa-2048" => Ok(Self::Rsa2048),
            "rsa-3072" => Ok(Self::Rsa3072),
            "rsa-4096" => Ok(Self::Rsa4096),
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
    Serialize,
    Deserialize,
)]
pub enum JwaSigningAlgorithm {
    #[strum(serialize = "RS256")]
    #[serde(rename = "RS256")]
    Rs256,
    #[strum(serialize = "RS384")]
    #[serde(rename = "RS384")]
    Rs384,
    #[strum(serialize = "RS512")]
    #[serde(rename = "RS512")]
    Rs512,
    #[strum(serialize = "PS256")]
    #[serde(rename = "PS256")]
    Ps256,
    #[strum(serialize = "PS384")]
    #[serde(rename = "PS384")]
    Ps384,
    #[strum(serialize = "PS512")]
    #[serde(rename = "PS512")]
    Ps512,
    #[strum(serialize = "ES256")]
    #[serde(rename = "ES256")]
    Es256,
    #[strum(serialize = "ES384")]
    #[serde(rename = "ES384")]
    Es384,
    #[strum(serialize = "ES512")]
    #[serde(rename = "ES512")]
    Es512,
    #[strum(serialize = "ES256K")]
    #[serde(rename = "ES256K")]
    Es256k,
    #[strum(serialize = "EdDSA")]
    #[serde(rename = "EdDSA")]
    EdDsa,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JwaAlgorithmParseError(pub String);

impl FmtDisplay for JwaAlgorithmParseError {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        write!(f, "unsupported JWA algorithm: {}", self.0)
    }
}

impl Error for JwaAlgorithmParseError {}

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
            AsymmetricKeyAlgorithm::Rsa2048
            | AsymmetricKeyAlgorithm::Rsa3072
            | AsymmetricKeyAlgorithm::Rsa4096 => &[
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

    /// The algorithm a key of this type signs with when none was chosen.
    /// Key agreement curves (X25519, X448) cannot sign and have none.
    #[must_use]
    pub const fn primary_for_key_type(algo: &AsymmetricKeyAlgorithm) -> Option<Self> {
        match algo {
            AsymmetricKeyAlgorithm::Rsa4096 => Some(Self::Rs512),
            AsymmetricKeyAlgorithm::Rsa3072 => Some(Self::Rs384),
            AsymmetricKeyAlgorithm::Rsa2048 => Some(Self::Rs256),
            AsymmetricKeyAlgorithm::EcdsaP256 => Some(Self::Es256),
            AsymmetricKeyAlgorithm::EcdsaP384 => Some(Self::Es384),
            AsymmetricKeyAlgorithm::EcdsaP521 => Some(Self::Es512),
            AsymmetricKeyAlgorithm::EcdsaSecp256k1 => Some(Self::Es256k),
            AsymmetricKeyAlgorithm::Ed25519 | AsymmetricKeyAlgorithm::Ed448 => Some(Self::EdDsa),
            AsymmetricKeyAlgorithm::X25519 | AsymmetricKeyAlgorithm::X448 => None,
        }
    }

    /// The keys a new signing key for this algorithm can be generated as,
    /// the default first. RSA sizes follow the hash strength; EdDSA can use
    /// either Edwards curve.
    #[must_use]
    pub const fn key_algorithms(self) -> &'static [AsymmetricKeyAlgorithm] {
        match self {
            Self::Rs256 | Self::Ps256 => &[AsymmetricKeyAlgorithm::Rsa2048],
            Self::Rs384 | Self::Ps384 => &[AsymmetricKeyAlgorithm::Rsa3072],
            Self::Rs512 | Self::Ps512 => &[AsymmetricKeyAlgorithm::Rsa4096],
            Self::Es256 => &[AsymmetricKeyAlgorithm::EcdsaP256],
            Self::Es384 => &[AsymmetricKeyAlgorithm::EcdsaP384],
            Self::Es512 => &[AsymmetricKeyAlgorithm::EcdsaP521],
            Self::Es256k => &[AsymmetricKeyAlgorithm::EcdsaSecp256k1],
            Self::EdDsa => &[
                AsymmetricKeyAlgorithm::Ed25519,
                AsymmetricKeyAlgorithm::Ed448,
            ],
        }
    }

    /// The key a new signing key uses: `requested` when this algorithm can
    /// sign with it, the default when none was requested, `None` otherwise.
    #[must_use]
    pub fn key_algorithm_for_new_key(
        self,
        requested: Option<AsymmetricKeyAlgorithm>,
    ) -> Option<AsymmetricKeyAlgorithm> {
        let offered = self.key_algorithms();
        match requested {
            None => offered.first().copied(),
            Some(key) => offered.contains(&key).then_some(key),
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

impl FmtDisplay for JwsAlgorithm {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> FmtResult {
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
    use super::{ALL_ASYMMETRIC_KEY_ALGORITHMS, AsymmetricKeyAlgorithm, JwaSigningAlgorithm};

    #[test]
    fn names_round_trip_through_the_parser() {
        for algorithm in ALL_ASYMMETRIC_KEY_ALGORITHMS {
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
    fn only_offered_rsa_sizes_have_a_key_type() {
        assert_eq!(
            AsymmetricKeyAlgorithm::from_rsa_bits(3072),
            Some(AsymmetricKeyAlgorithm::Rsa3072)
        );
        assert_eq!(AsymmetricKeyAlgorithm::from_rsa_bits(1024), None);
        assert_eq!(AsymmetricKeyAlgorithm::from_rsa_bits(8192), None);
    }

    #[test]
    fn rejects_unknown_algorithm() {
        let result: Result<JwaSigningAlgorithm, _> = "FOO".parse();
        assert!(result.is_err());
    }
}
