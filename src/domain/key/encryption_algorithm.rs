#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JweContentEncryption {
    A128CbcHs256,
    A192CbcHs384,
    A256CbcHs512,
    A128Gcm,
    A192Gcm,
    A256Gcm,
}

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
