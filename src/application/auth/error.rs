use crate::{
    application::error::{
        AppError,
        codes::{auth::AuthErrorCode, common::CommonErrorCode},
    },
    domain::{
        auth::{
            password::PasswordHashError,
            repository::{LoginRepositoryError, SessionRepositoryError},
            totp::TotpError,
        },
        user::repository::{UserCredentialRepositoryError, UserRepositoryError},
    },
};

impl From<UserRepositoryError> for AppError {
    fn from(error: UserRepositoryError) -> Self {
        match error {
            UserRepositoryError::UserNotFound => AppError::from_code(AuthErrorCode::UserNotFound),
            other => AppError::from_code(CommonErrorCode::InternalError).with_source(other),
        }
    }
}

impl From<UserCredentialRepositoryError> for AppError {
    fn from(error: UserCredentialRepositoryError) -> Self {
        match error {
            UserCredentialRepositoryError::CredentialNotFound => {
                AppError::from_code(AuthErrorCode::CredentialTypeUnsupported)
            }
            other => AppError::from_code(CommonErrorCode::InternalError).with_source(other),
        }
    }
}

impl From<LoginRepositoryError> for AppError {
    fn from(error: LoginRepositoryError) -> Self {
        match error {
            LoginRepositoryError::LoginNotFound => {
                AppError::from_code(AuthErrorCode::InvalidLoginState)
            }
            other => AppError::from_code(CommonErrorCode::InternalError).with_source(other),
        }
    }
}

impl From<SessionRepositoryError> for AppError {
    fn from(error: SessionRepositoryError) -> Self {
        match error {
            SessionRepositoryError::SessionNotFound => {
                AppError::from_code(AuthErrorCode::SessionNotFound)
            }
            other => AppError::from_code(CommonErrorCode::InternalError).with_source(other),
        }
    }
}

impl From<PasswordHashError> for AppError {
    fn from(error: PasswordHashError) -> Self {
        AppError::from_code(CommonErrorCode::InternalError).with_source(error)
    }
}

impl From<TotpError> for AppError {
    fn from(error: TotpError) -> Self {
        AppError::from_code(CommonErrorCode::InternalError).with_source(error)
    }
}
