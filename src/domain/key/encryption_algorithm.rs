use std::{fmt, str::FromStr};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum JwaEncryptionAlgorithm {
    RsaOaep,
    RsaOaep256,
    RsaOaep384,
    RsaOaep512,
    EcdhEs,
    EcdhEsA128Kw,
    EcdhEsA192Kw,
    EcdhEsA256Kw,
    A128Kw,
    A192Kw,
    A256Kw,
    Dir,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("invalid JWA encryption algorithm")]
pub struct ParseJwaEncryptionAlgorithmError;

impl fmt::Display for JwaEncryptionAlgorithm {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl FromStr for JwaEncryptionAlgorithm {
    type Err = ParseJwaEncryptionAlgorithmError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "RSA-OAEP" => Ok(Self::RsaOaep),
            "RSA-OAEP-256" => Ok(Self::RsaOaep256),
            "RSA-OAEP-384" => Ok(Self::RsaOaep384),
            "RSA-OAEP-512" => Ok(Self::RsaOaep512),
            "ECDH-ES" => Ok(Self::EcdhEs),
            "ECDH-ES+A128KW" => Ok(Self::EcdhEsA128Kw),
            "ECDH-ES+A192KW" => Ok(Self::EcdhEsA192Kw),
            "ECDH-ES+A256KW" => Ok(Self::EcdhEsA256Kw),
            "A128KW" => Ok(Self::A128Kw),
            "A192KW" => Ok(Self::A192Kw),
            "A256KW" => Ok(Self::A256Kw),
            "dir" => Ok(Self::Dir),
            _ => Err(ParseJwaEncryptionAlgorithmError),
        }
    }
}

impl JwaEncryptionAlgorithm {
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::RsaOaep => "RSA-OAEP",
            Self::RsaOaep256 => "RSA-OAEP-256",
            Self::RsaOaep384 => "RSA-OAEP-384",
            Self::RsaOaep512 => "RSA-OAEP-512",
            Self::EcdhEs => "ECDH-ES",
            Self::EcdhEsA128Kw => "ECDH-ES+A128KW",
            Self::EcdhEsA192Kw => "ECDH-ES+A192KW",
            Self::EcdhEsA256Kw => "ECDH-ES+A256KW",
            Self::A128Kw => "A128KW",
            Self::A192Kw => "A192KW",
            Self::A256Kw => "A256KW",
            Self::Dir => "dir",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum JweContentEncryption {
    A128CbcHs256,
    A192CbcHs384,
    A256CbcHs512,
    A128Gcm,
    A192Gcm,
    A256Gcm,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("invalid JWE content encryption algorithm")]
pub struct ParseJweContentEncryptionError;

impl JweContentEncryption {
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::A128CbcHs256 => "A128CBC-HS256",
            Self::A192CbcHs384 => "A192CBC-HS384",
            Self::A256CbcHs512 => "A256CBC-HS512",
            Self::A128Gcm => "A128GCM",
            Self::A192Gcm => "A192GCM",
            Self::A256Gcm => "A256GCM",
        }
    }
}

impl fmt::Display for JweContentEncryption {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl FromStr for JweContentEncryption {
    type Err = ParseJweContentEncryptionError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "A128CBC-HS256" => Ok(Self::A128CbcHs256),
            "A192CBC-HS384" => Ok(Self::A192CbcHs384),
            "A256CBC-HS512" => Ok(Self::A256CbcHs512),
            "A128GCM" => Ok(Self::A128Gcm),
            "A192GCM" => Ok(Self::A192Gcm),
            "A256GCM" => Ok(Self::A256Gcm),
            _ => Err(ParseJweContentEncryptionError),
        }
    }
}
