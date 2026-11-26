use crate::{
    application::error::{
        AppError,
        codes::{auth, common},
    },
    authentication::{password::PasswordHashError, totp::TotpError},
    domain::{
        auth::repository::{LoginRepositoryError, SessionRepositoryError},
        user::repository::UserRepositoryError,
    },
    user::repository::UserCredentialRepositoryError,
};

impl From<UserRepositoryError> for AppError {
    fn from(error: UserRepositoryError) -> Self {
        match error {
            UserRepositoryError::UserNotFound => auth::error::UserNotFound.into(),
            other => common::error::InternalError.with_source(other),
        }
    }
}

impl From<UserCredentialRepositoryError> for AppError {
    fn from(error: UserCredentialRepositoryError) -> Self {
        match error {
            UserCredentialRepositoryError::InvalidMfaEnrollment => {
                auth::error::InvalidMfaEnrollment.into()
            }
            UserCredentialRepositoryError::CredentialNotFound => {
                auth::error::CredentialTypeUnsupported::new("unknown").into()
            }
            other => common::error::InternalError.with_source(other),
        }
    }
}

impl From<LoginRepositoryError> for AppError {
    fn from(error: LoginRepositoryError) -> Self {
        match error {
            LoginRepositoryError::LoginNotFound => auth::error::InvalidLoginState.into(),
            other => common::error::InternalError.with_source(other),
        }
    }
}

impl From<SessionRepositoryError> for AppError {
    fn from(error: SessionRepositoryError) -> Self {
        match error {
            SessionRepositoryError::SessionNotFound => {
                auth::error::SessionNotFound::new("current").into()
            }
            other => common::error::InternalError.with_source(other),
        }
    }
}

impl From<PasswordHashError> for AppError {
    fn from(error: PasswordHashError) -> Self {
        common::error::InternalError.with_source(error)
    }
}

impl From<TotpError> for AppError {
    fn from(error: TotpError) -> Self {
        common::error::InternalError.with_source(error)
    }
}
