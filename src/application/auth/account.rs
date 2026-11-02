//! Account profile and identifier changes.
//!
//! The use case owns identifier validation, uniqueness error mapping and the
//! repository call so every adapter (GraphQL, HTTP) gets the same business
//! rules. Patches and identifiers are domain types; the repository port keeps
//! persistence details out of this layer.

use std::sync::Arc;

use identity_domain::{
    time_zone::TimeZone,
    user::{
        User, UserOid,
        normalization::{
            EmailNormalizationError, UsernameValidationError, normalize_email,
            validate_username as normalization_validate_username,
        },
        repository::{UserIdentifierUpdate, UserProfilePatch, UserRepository, UserRepositoryError},
    },
};
use uuid::Uuid;

use crate::{
    error::{
        AppError,
        codes::{account::AccountErrorCode, common::CommonErrorCode},
    },
    observability::{BusinessEvent, EventSink, EventValue, NoopEventSink},
};

pub struct AccountService {
    user_repo: Arc<dyn UserRepository>,
    events: Arc<dyn EventSink>,
}

impl AccountService {
    #[must_use]
    pub fn new(user_repo: Arc<dyn UserRepository>) -> Self {
        Self {
            user_repo,
            events: Arc::new(NoopEventSink),
        }
    }

    /// Attach the key event and audit sink.
    #[must_use]
    pub fn with_events(mut self, events: Arc<dyn EventSink>) -> Self {
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
        mut patch: UserProfilePatch,
    ) -> Result<User, AppError> {
        patch.zone_info = normalize_zone_info(patch.zone_info)?;
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
        self.events.emit(
            BusinessEvent::audit("account.changed")
                .outcome(outcome)
                .attribute("change_category", EventValue::Text(category.to_owned()))
                .attribute(
                    "user_oid",
                    EventValue::Pseudonymized {
                        purpose: "user_oid",
                        value: Uuid::from(user_oid).to_string(),
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
    match normalization_validate_username(username) {
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
    match normalize_email(email) {
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

/// Omitted stays omitted, null clears, empty/whitespace clears, and a valid
/// IANA identifier is stored under its canonical name.
fn normalize_zone_info(
    zone_info: Option<Option<String>>,
) -> Result<Option<Option<String>>, AppError> {
    let Some(value) = zone_info else {
        return Ok(None);
    };
    let Some(raw) = value else {
        return Ok(Some(None));
    };
    TimeZone::profile_patch_value(&raw)
        .map(Some)
        .map_err(|_| invalid_time_zone())
}

fn invalid_time_zone() -> AppError {
    AppError::from_code(AccountErrorCode::ValidationFailed).with_field_error(
        "zoneInfo",
        AppError::from_code(CommonErrorCode::InvalidTimeZone),
    )
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

    use super::{normalize_zone_info, validate_email, validate_username};

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

    #[test]
    fn zone_info_patch_preserves_omission_clears_empty_and_canonicalizes_valid_input() {
        assert_eq!(normalize_zone_info(None).unwrap(), None);
        assert_eq!(normalize_zone_info(Some(None)).unwrap(), Some(None));
        assert_eq!(
            normalize_zone_info(Some(Some(String::new()))).unwrap(),
            Some(None)
        );
        assert_eq!(
            normalize_zone_info(Some(Some("   ".to_owned()))).unwrap(),
            Some(None)
        );
        // Omitted and explicit-null cases are asserted above; empty strings
        // must become an explicit clear rather than a stored empty value.
        assert_eq!(
            normalize_zone_info(Some(Some("europe/paris".to_owned()))).unwrap(),
            Some(Some("Europe/Paris".to_owned()))
        );
    }

    #[test]
    fn invalid_zone_info_is_a_localized_zone_info_field_error() {
        let error = normalize_zone_info(Some(Some("+02:00".to_owned()))).unwrap_err();

        assert_eq!(error.code(), 15000);
        let field = &error.validation().unwrap().fields()[0];
        assert_eq!(field.field(), "zoneInfo");
        assert_eq!(field.code(), 10010);
    }
}
