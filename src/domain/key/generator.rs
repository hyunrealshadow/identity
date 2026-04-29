use thiserror::Error;

use crate::key::{AsymmetricKeyAlgorithm, AsymmetricKeyData};

#[derive(Debug, Error)]
pub enum KeyMaterialError {
    #[error("invalid key material: {0}")]
    InvalidInput(String),

    #[error(transparent)]
    Internal(#[from] Box<dyn std::error::Error + Send + Sync + 'static>),
}

#[derive(Debug, Clone)]
pub struct AsymmetricKeySpec {
    pub algorithm: AsymmetricKeyAlgorithm,
}

pub trait AsymmetricKeyGenerator: Send + Sync {
    fn generate(&self, spec: &AsymmetricKeySpec) -> Result<AsymmetricKeyData, KeyMaterialError>;
}
