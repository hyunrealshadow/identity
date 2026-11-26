use identity_domain::data_protection::DataProtectionError;

use crate::error::{
    AppError,
    codes::{common, data_protection},
};

impl From<DataProtectionError> for AppError {
    fn from(error: DataProtectionError) -> Self {
        match error {
            DataProtectionError::InvalidProtectedPayload => {
                data_protection::error::InvalidProtectedPayload.into()
            }
            DataProtectionError::KeyRingEmpty => data_protection::error::KeyRingEmpty.into(),
            DataProtectionError::EncryptionFailed => {
                data_protection::error::EncryptionFailed.into()
            }
            DataProtectionError::Internal(_) => common::error::InternalError.with_source(error),
        }
    }
}
