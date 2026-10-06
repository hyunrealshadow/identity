use identity_domain::data_protection::DataProtectionError;

use crate::error::{
    AppError,
    codes::{common::CommonErrorCode, data_protection::DataProtectionErrorCode},
};

impl From<DataProtectionError> for AppError {
    fn from(error: DataProtectionError) -> Self {
        match error {
            DataProtectionError::InvalidProtectedPayload => {
                AppError::from_code(DataProtectionErrorCode::InvalidProtectedPayload)
            }
            DataProtectionError::KeyRingEmpty => {
                AppError::from_code(DataProtectionErrorCode::KeyRingEmpty)
            }
            DataProtectionError::EncryptionFailed => {
                AppError::from_code(DataProtectionErrorCode::EncryptionFailed)
            }
            DataProtectionError::Internal(_) => {
                AppError::from_code(CommonErrorCode::InternalError).with_source(error)
            }
        }
    }
}
