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
    Internal(#[from] Box<dyn std::error::Error + Send + Sync + 'static>),
}
