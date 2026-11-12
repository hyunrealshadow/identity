use std::error::Error as StdError;

use thiserror::Error;

use crate::key::{AsymmetricKeyAlgorithm, AsymmetricKeyData, JwaSigningAlgorithm};

#[derive(Debug, Error)]
pub enum KeyMaterialError {
    #[error("invalid key material: {0}")]
    InvalidInput(String),

    #[error(transparent)]
    Internal(#[from] Box<dyn StdError + Send + Sync + 'static>),
}

#[derive(Debug, Clone)]
pub struct AsymmetricKeySpec {
    pub algorithm: AsymmetricKeyAlgorithm,
    /// The algorithm the key will sign with, when it constrains the key
    /// itself: RSA-PSS signing needs a key restricted to its PSS parameters.
    pub signing: Option<JwaSigningAlgorithm>,
}

impl AsymmetricKeySpec {
    #[must_use]
    pub const fn new(algorithm: AsymmetricKeyAlgorithm) -> Self {
        Self {
            algorithm,
            signing: None,
        }
    }

    /// A key of type `algorithm` generated to sign with `signing` only.
    #[must_use]
    pub const fn for_signing(
        signing: JwaSigningAlgorithm,
        algorithm: AsymmetricKeyAlgorithm,
    ) -> Self {
        Self {
            algorithm,
            signing: Some(signing),
        }
    }
}

pub trait AsymmetricKeyGenerator: Send + Sync {
    fn generate(&self, spec: &AsymmetricKeySpec) -> Result<AsymmetricKeyData, KeyMaterialError>;
}
