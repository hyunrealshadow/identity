use crate::{
    application::error::{AppError, codes::common::CommonErrorCode},
    domain::setting::repository::SettingRepositoryError,
};

impl From<SettingRepositoryError> for AppError {
    fn from(error: SettingRepositoryError) -> Self {
        match error {
            SettingRepositoryError::Validation(_) => {
                AppError::from_code(CommonErrorCode::InvalidRequest)
            }
            other => AppError::from_code(CommonErrorCode::InternalError).with_source(other),
        }
    }
}
