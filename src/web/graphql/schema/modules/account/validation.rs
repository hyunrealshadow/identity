use async_graphql::{Context, Error};
use identity_application::error::{AppError, codes::account::AccountErrorCode};
use identity_domain::user::{
    normalization::{EmailNormalizationError, UsernameValidationError},
    repository::UserRepositoryError,
};
use identity_infrastructure::database::repository::user::UserIdentifierUpdate;

use super::types::{UpdateEmailInput, UpdateUsernameInput};
use crate::graphql::schema::error::{app_error, internal_error};

pub(crate) fn validate_username(
    input: &UpdateUsernameInput,
) -> std::result::Result<UserIdentifierUpdate, AppError> {
    let mut error = AppError::from_code(AccountErrorCode::ValidationFailed);
    let username = match identity_domain::user::normalization::validate_username(&input.username) {
        Ok(normalized) => Some((input.username.trim().to_owned(), normalized)),
        Err(UsernameValidationError::Empty) => {
            error.push_field_error(
                "username",
                AppError::from_code(AccountErrorCode::UsernameRequired),
            );
            None
        }
        Err(UsernameValidationError::InvalidLength | UsernameValidationError::InvalidCharacter) => {
            error.push_field_error(
                "username",
                AppError::from_code(AccountErrorCode::UsernameInvalid),
            );
            None
        }
    };
    if error
        .validation()
        .is_some_and(|validation| !validation.is_empty())
    {
        Err(error)
    } else {
        let (value, normalized) = username.expect("validated username must be present");
        Ok(UserIdentifierUpdate::Username { value, normalized })
    }
}

pub(crate) fn validate_email(
    input: &UpdateEmailInput,
) -> std::result::Result<UserIdentifierUpdate, AppError> {
    let mut error = AppError::from_code(AccountErrorCode::ValidationFailed);
    let email = match identity_domain::user::normalization::normalize_email(&input.email) {
        Ok(normalized) => Some((input.email.trim().to_owned(), normalized)),
        Err(EmailNormalizationError::Empty) => {
            error.push_field_error(
                "email",
                AppError::from_code(AccountErrorCode::EmailRequired),
            );
            None
        }
        Err(EmailNormalizationError::InvalidFormat | EmailNormalizationError::InvalidDomain) => {
            error.push_field_error("email", AppError::from_code(AccountErrorCode::EmailInvalid));
            None
        }
    };
    if error
        .validation()
        .is_some_and(|validation| !validation.is_empty())
    {
        Err(error)
    } else {
        let (value, normalized) = email.expect("validated email must be present");
        Ok(UserIdentifierUpdate::Email { value, normalized })
    }
}

pub(super) fn account_repository_error(ctx: &Context<'_>, error: UserRepositoryError) -> Error {
    match error {
        UserRepositoryError::UsernameExists => app_error(
            ctx,
            AppError::from_code(AccountErrorCode::UsernameExists).with_field("username"),
        ),
        UserRepositoryError::EmailExists => app_error(
            ctx,
            AppError::from_code(AccountErrorCode::EmailExists).with_field("email"),
        ),
        error => internal_error(error),
    }
}
