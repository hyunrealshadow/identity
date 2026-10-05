use serde_json::Error as SerdeJsonError;
use thiserror::Error;

use crate::application::error::{AppError, codes::common::CommonErrorCode};

#[derive(Debug, Error)]
pub enum SettingError {
    #[error("failed to serialize setting value")]
    Serialize(#[source] SerdeJsonError),

    #[error("failed to deserialize setting value")]
    Deserialize(#[source] SerdeJsonError),

    #[error("invalid setting value: {0}")]
    Validation(String),
}

impl From<SettingError> for AppError {
    fn from(error: SettingError) -> Self {
        match error {
            SettingError::Validation(_) => AppError::from_code(CommonErrorCode::InvalidRequest),
            other => AppError::from_code(CommonErrorCode::InternalError).with_source(other),
        }
    }
}
