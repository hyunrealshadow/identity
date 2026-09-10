//! Account profile and identifier changes.
//!
//! The use case owns identifier validation, uniqueness error mapping and the
//! repository call so every adapter (GraphQL, HTTP) gets the same business
//! rules. Patches and identifiers are domain types; the repository port keeps
//! persistence details out of this layer.

use std::sync::Arc;

use identity_domain::user::{
    User, UserOid,
    normalization::{EmailNormalizationError, UsernameValidationError},
    repository::{UserIdentifierUpdate, UserProfilePatch, UserRepository, UserRepositoryError},
};

use crate::error::{
    AppError,
    codes::{account::AccountErrorCode, common::CommonErrorCode},
};

pub struct AccountService {
    user_repo: Arc<dyn UserRepository>,
    events: Arc<dyn crate::observability::EventSink>,
}

impl AccountService {
    #[must_use]
    pub fn new(user_repo: Arc<dyn UserRepository>) -> Self {
        Self {
            user_repo,
            events: Arc::new(crate::observability::NoopEventSink),
        }
    }

    /// Attach the key event and audit sink.
    #[must_use]
    pub fn with_events(mut self, events: Arc<dyn crate::observability::EventSink>) -> Self {
        self.events = events;
        self
    }

    #[tracing::instrument(skip_all, name = "account.update")]
    pub async fn update_username(
        &self,
        user_oid: UserOid,
        username: &str,
    ) -> Result<User, AppError> {
        let update = validate_username(username)?;
        let user = self
            .user_repo
            .update_identifier(user_oid, update)
            .await
            .map_err(map_identifier_error)?
            .ok_or_else(|| AppError::from_code(CommonErrorCode::NotFound))?;
        self.record_account_change("username", user_oid, "success");
        Ok(user)
    }

    #[tracing::instrument(skip_all, name = "account.update")]
    pub async fn update_email(&self, user_oid: UserOid, email: &str) -> Result<User, AppError> {
        let update = validate_email(email)?;
        let user = self
            .user_repo
            .update_identifier(user_oid, update)
            .await
            .map_err(map_identifier_error)?
            .ok_or_else(|| AppError::from_code(CommonErrorCode::NotFound))?;
        self.record_account_change("email", user_oid, "success");
        Ok(user)
    }

    #[tracing::instrument(skip_all, name = "account.update")]
    pub async fn update_profile(
        &self,
        user_oid: UserOid,
        patch: UserProfilePatch,
    ) -> Result<User, AppError> {
        let user = self
            .user_repo
            .update_profile(user_oid, patch)
            .await
            .map_err(AppError::from)?
            .ok_or_else(|| AppError::from_code(CommonErrorCode::NotFound))?;
        self.record_account_change("profile", user_oid, "success");
        Ok(user)
    }

    /// Record an account mutation in the audit stream. Only the actor, the
    /// change category and the outcome are recorded; before/after values are
    /// never emitted.
    fn record_account_change(
        &self,
        category: &'static str,
        user_oid: UserOid,
        outcome: &'static str,
    ) {
        use crate::observability::{BusinessEvent, EventValue};
        self.events.emit(
            BusinessEvent::audit("account.changed")
                .outcome(outcome)
                .attribute("change_category", EventValue::Text(category.to_owned()))
                .attribute(
                    "user_oid",
                    EventValue::Pseudonymized {
                        purpose: "user_oid",
                        value: uuid::Uuid::from(user_oid).to_string(),
                    },
                ),
        );
    }

    pub async fn find_user(&self, user_oid: UserOid) -> Result<Option<User>, AppError> {
        self.user_repo
            .find_by_oid(user_oid)
            .await
            .map_err(AppError::from)
    }
}

fn validate_username(username: &str) -> Result<UserIdentifierUpdate, AppError> {
    match identity_domain::user::normalization::validate_username(username) {
        Ok(normalized) => Ok(UserIdentifierUpdate::Username {
            value: username.trim().to_owned(),
            normalized,
        }),
        Err(error) => {
            let field_error = match error {
                UsernameValidationError::Empty => {
                    AppError::from_code(AccountErrorCode::UsernameRequired)
                }
                UsernameValidationError::InvalidLength
                | UsernameValidationError::InvalidCharacter => {
                    AppError::from_code(AccountErrorCode::UsernameInvalid)
                }
            };
            Err(AppError::from_code(AccountErrorCode::ValidationFailed)
                .with_field_error("username", field_error))
        }
    }
}

fn validate_email(email: &str) -> Result<UserIdentifierUpdate, AppError> {
    match identity_domain::user::normalization::normalize_email(email) {
        Ok(normalized) => Ok(UserIdentifierUpdate::Email {
            value: email.trim().to_owned(),
            normalized,
        }),
        Err(error) => {
            let field_error = match error {
                EmailNormalizationError::Empty => {
                    AppError::from_code(AccountErrorCode::EmailRequired)
                }
                EmailNormalizationError::InvalidFormat | EmailNormalizationError::InvalidDomain => {
                    AppError::from_code(AccountErrorCode::EmailInvalid)
                }
            };
            Err(AppError::from_code(AccountErrorCode::ValidationFailed)
                .with_field_error("email", field_error))
        }
    }
}

fn map_identifier_error(error: UserRepositoryError) -> AppError {
    match error {
        UserRepositoryError::UsernameExists => {
            AppError::from_code(AccountErrorCode::UsernameExists).with_field("username")
        }
        UserRepositoryError::EmailExists => {
            AppError::from_code(AccountErrorCode::EmailExists).with_field("email")
        }
        other => AppError::from(other),
    }
}

#[cfg(test)]
mod tests {
    use identity_domain::user::repository::UserIdentifierUpdate;

    use super::{validate_email, validate_username};

    #[test]
    fn username_validation_reports_missing_and_invalid_values() {
        let missing = validate_username("  ").unwrap_err();
        assert_eq!(missing.code(), 15000);
        assert_eq!(missing.validation().unwrap().fields()[0].code(), 15001);

        let invalid = validate_username("a").unwrap_err();
        assert_eq!(invalid.validation().unwrap().fields()[0].code(), 15002);

        let valid = validate_username(" Ada ").unwrap();
        assert_eq!(
            valid,
            UserIdentifierUpdate::Username {
                value: "Ada".to_owned(),
                normalized: "ada".to_owned(),
            }
        );
    }

    #[test]
    fn email_validation_normalizes_valid_values() {
        let valid = validate_email("Ada@Example.com").unwrap();
        assert_eq!(
            valid,
            UserIdentifierUpdate::Email {
                value: "Ada@Example.com".to_owned(),
                normalized: "ada@example.com".to_owned(),
            }
        );
        assert_eq!(validate_email("").unwrap_err().code(), 15000);
    }
}
