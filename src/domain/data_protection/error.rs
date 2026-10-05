use std::error::Error as StdError;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum DataProtectionError {
    #[error("invalid protected payload")]
    InvalidProtectedPayload,

    #[error("no active key in key ring")]
    KeyRingEmpty,

    #[error("encryption failed")]
    EncryptionFailed,

    #[error(transparent)]
    Internal(#[from] Box<dyn StdError + Send + Sync + 'static>),
}
