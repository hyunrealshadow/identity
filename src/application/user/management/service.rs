//! Instance user management use cases.
//!
//! Entry guards only establish that a caller had a scope when the request
//! started. Every write therefore passes an immutable [`UserManagementAuthority`]
//! to the repository, which re-loads the authoritative binding/grant, policy
//! version, owner state and target row inside the mutation transaction.
//!
//! Reads remain guarded by the adapter (`management.user.read`). Read methods
//! intentionally do not start a write transaction or emit fake audit facts.

use std::sync::Arc;

use identity_domain::{
    authorization::OwnerProtectionError,
    user::{
        UserManagementRecord, UserOid,
        normalization::{
            EmailNormalizationError, UsernameValidationError, normalize_email, validate_username,
        },
    },
};
use uuid::Uuid;

use crate::{
    auth::{
        hash::PasswordHasher,
        password::run_password_hashing,
        password_policy::{BreachedPasswordChecker, validate_breached_password, validate_password},
    },
    data_protection::DataProtector,
    error::{
        AppError,
        codes::{
            account::AccountErrorCode, authorization::AuthorizationErrorCode,
            user_management::UserManagementErrorCode,
        },
    },
    observability::{BusinessEvent, EventSink, EventValue, NoopEventSink, error_outcome},
    setting::{PasswordHashSetting, SettingsSource},
    user::management::{
        cursor::{NormalizedFilter, decode_cursor, encode_cursor},
        model::{
            CreateUserCommand, UpdateUserCommand, UserFilter, UserManagementAuthority,
            UserManagementPage, UserManagementPageItem, UserPageRequest, UserStateCommand,
            domain_profile_patch,
        },
        repository::{
            CreateUserTransaction, UpdateUserTransaction, UserIdentifierValue,
            UserManagementMutationOutcome, UserManagementQuery, UserManagementRepository,
            UserManagementRepositoryError, UserPageDirection, UserStateTransaction,
        },
    },
};

pub const DEFAULT_PAGE_SIZE: u32 = 20;
pub const MAX_PAGE_SIZE: u32 = 100;
pub const MAX_REASON_LENGTH: usize = 1_000;
pub const MAX_CLIENT_MUTATION_ID_LENGTH: usize = 255;
pub const MAX_QUERY_FILTER_LENGTH: usize = 255;
pub const MAX_USERNAME_FILTER_LENGTH: usize = 64;
pub const MAX_EMAIL_FILTER_LENGTH: usize = 320;

pub struct UserManagementService {
    repository: Arc<dyn UserManagementRepository>,
    password_hasher: Arc<dyn PasswordHasher>,
    breach_checker: Arc<dyn BreachedPasswordChecker>,
    settings: Arc<dyn SettingsSource>,
    data_protector: Arc<dyn DataProtector>,
    events: Arc<dyn EventSink>,
}

impl UserManagementService {
    #[must_use]
    pub fn new(
        repository: Arc<dyn UserManagementRepository>,
        password_hasher: Arc<dyn PasswordHasher>,
        breach_checker: Arc<dyn BreachedPasswordChecker>,
        settings: Arc<dyn SettingsSource>,
        data_protector: Arc<dyn DataProtector>,
    ) -> Self {
        Self {
            repository,
            password_hasher,
            breach_checker,
            settings,
            data_protector,
            events: Arc::new(NoopEventSink),
        }
    }

    #[must_use]
    pub fn with_events(mut self, events: Arc<dyn EventSink>) -> Self {
        self.events = events;
        self
    }

    /// Count the full normalized directory filter, without page boundaries.
    #[tracing::instrument(skip_all, name = "user.management.count")]
    pub async fn count_users(&self, filter: UserFilter) -> Result<u64, AppError> {
        let (_, query) = self
            .prepare_query(UserPageRequest {
                filter,
                ..Default::default()
            })
            .await?;
        self.repository
            .count_users(query.filter)
            .await
            .map_err(map_repository_error)
    }

    /// Read one management record for a root already admitted with
    /// `management.user.read`.
    #[tracing::instrument(skip_all, name = "user.management.find")]
    pub async fn find_user(
        &self,
        user_oid: UserOid,
    ) -> Result<Option<UserManagementRecord>, AppError> {
        self.repository
            .find_user(user_oid)
            .await
            .map_err(map_repository_error)
    }

    /// Users referenced by one page of relation edges, for a field already
    /// admitted with `management.user.read`.
    #[tracing::instrument(skip_all, name = "user.management.find_many")]
    pub async fn find_users(
        &self,
        user_oids: Vec<UserOid>,
    ) -> Result<Vec<UserManagementRecord>, AppError> {
        let user_oids = user_oids
            .into_iter()
            .map(Uuid::from)
            .collect::<std::collections::BTreeSet<_>>();
        if user_oids.len() > MAX_PAGE_SIZE as usize {
            return Err(AppError::from_code(
                UserManagementErrorCode::ValidationFailed,
            ));
        }
        self.repository
            .find_users(user_oids.into_iter().map(UserOid).collect())
            .await
            .map_err(map_repository_error)
    }

    /// Read a keyset page for a root already admitted with
    /// `management.user.read`.
    #[tracing::instrument(skip_all, name = "user.management.list")]
    pub async fn list_users(
        &self,
        request: UserPageRequest,
    ) -> Result<UserManagementPage, AppError> {
        let order = request.order;
        let (filter, query) = self.prepare_query(request).await?;
        let data = self
            .repository
            .list_users(query)
            .await
            .map_err(map_repository_error)?;
        let mut items = Vec::with_capacity(data.items.len());
        for entry in data.items {
            let cursor = encode_cursor(
                self.data_protector.as_ref(),
                &filter,
                order,
                &entry.sort_key,
            )
            .await?;
            items.push(UserManagementPageItem {
                record: entry.record,
                cursor,
            });
        }
        Ok(UserManagementPage {
            items,
            has_previous_page: data.has_previous_page,
            has_next_page: data.has_next_page,
        })
    }

    #[tracing::instrument(skip_all, name = "user.management.create")]
    pub async fn create_user(
        &self,
        authority: &UserManagementAuthority,
        command: CreateUserCommand,
    ) -> Result<UserManagementRecord, AppError> {
        let result = self.create_user_inner(authority, command).await;
        self.emit_mutation("user.management.create", &result);
        result
    }

    #[tracing::instrument(skip_all, name = "user.management.update")]
    pub async fn update_user(
        &self,
        authority: &UserManagementAuthority,
        command: UpdateUserCommand,
    ) -> Result<UserManagementRecord, AppError> {
        let result = self.update_user_inner(authority, command).await;
        self.emit_mutation("user.management.update", &result);
        result
    }

    #[tracing::instrument(skip_all, name = "user.management.enable")]
    pub async fn enable_user(
        &self,
        authority: &UserManagementAuthority,
        command: UserStateCommand,
    ) -> Result<UserManagementRecord, AppError> {
        let result = self.state_user_inner(authority, command, true).await;
        self.emit_mutation("user.management.enable", &result);
        result
    }

    #[tracing::instrument(skip_all, name = "user.management.disable")]
    pub async fn disable_user(
        &self,
        authority: &UserManagementAuthority,
        command: UserStateCommand,
    ) -> Result<UserManagementRecord, AppError> {
        let result = self.state_user_inner(authority, command, false).await;
        self.emit_mutation("user.management.disable", &result);
        result
    }

    #[tracing::instrument(skip_all, name = "user.management.unlock")]
    pub async fn unlock_user(
        &self,
        authority: &UserManagementAuthority,
        command: UserStateCommand,
    ) -> Result<UserManagementRecord, AppError> {
        let result = self.unlock_user_inner(authority, command).await;
        self.emit_mutation("user.management.unlock", &result);
        result
    }

    async fn prepare_query(
        &self,
        request: UserPageRequest,
    ) -> Result<(NormalizedFilter, UserManagementQuery), AppError> {
        if request.first.is_some() && request.last.is_some() {
            return Err(page_conflict());
        }
        if request.after.is_some() && request.before.is_some() {
            return Err(page_conflict());
        }
        if request.first.is_some() && request.before.is_some() {
            return Err(page_conflict());
        }
        if request.last.is_some() && request.after.is_some() {
            return Err(page_conflict());
        }

        let filter = normalize_filter(request.filter)?;
        let backward =
            request.last.is_some() || (request.first.is_none() && request.before.is_some());
        let limit = match (request.first, request.last) {
            (Some(first), None) => validate_page_size(first, "first")?,
            (None, Some(last)) => validate_page_size(last, "last")?,
            (None, None) => DEFAULT_PAGE_SIZE as usize,
            (Some(_), Some(_)) => return Err(page_conflict()),
        };
        let direction = if backward {
            UserPageDirection::Backward
        } else {
            UserPageDirection::Forward
        };

        let after = match (direction, request.after.as_deref()) {
            (UserPageDirection::Forward, Some(token)) => Some(
                decode_cursor(self.data_protector.as_ref(), &filter, request.order, token).await?,
            ),
            _ => None,
        };
        let before = match (direction, request.before.as_deref()) {
            (UserPageDirection::Backward, Some(token)) => Some(
                decode_cursor(self.data_protector.as_ref(), &filter, request.order, token).await?,
            ),
            _ => None,
        };

        Ok((
            filter.clone(),
            UserManagementQuery {
                filter: UserFilter::from(&filter),
                order: request.order,
                direction,
                after,
                before,
                limit,
            },
        ))
    }

    async fn create_user_inner(
        &self,
        authority: &UserManagementAuthority,
        command: CreateUserCommand,
    ) -> Result<UserManagementRecord, AppError> {
        let reason = validate_reason(&command.reason)?;
        validate_client_mutation_id(command.client_mutation_id.as_deref())?;
        let (username, username_normalized) = validate_username_field(&command.username)?;
        let (email, email_normalized) = validate_email_field(&command.email)?;
        let profile = domain_profile_patch(&command.profile)?;

        validate_password(command.password.as_str(), &[&username, &email], "password")?;
        validate_breached_password(
            self.breach_checker.as_ref(),
            &self.settings.snapshot(),
            command.password.as_str(),
            "password",
        )
        .await?;

        let hash_options = self.settings.snapshot().get::<PasswordHashSetting>();
        let hasher = Arc::clone(&self.password_hasher);
        let password = command.password.into_inner();
        let password = run_password_hashing(move || hasher.hash(&password, &hash_options)).await?;

        let outcome = self
            .repository
            .create_user(CreateUserTransaction {
                username,
                username_normalized,
                email,
                email_normalized,
                password,
                profile,
                reason,
                authority: (*authority).clone(),
            })
            .await
            .map_err(map_repository_error)?;
        map_mutation_outcome(outcome)
    }

    async fn update_user_inner(
        &self,
        authority: &UserManagementAuthority,
        command: UpdateUserCommand,
    ) -> Result<UserManagementRecord, AppError> {
        let reason = validate_reason(&command.reason)?;
        validate_client_mutation_id(command.client_mutation_id.as_deref())?;

        let username = command
            .username
            .as_deref()
            .map(validate_username_field)
            .transpose()?
            .map(|(value, normalized)| UserIdentifierValue { value, normalized });
        let email = command
            .email
            .as_deref()
            .map(validate_email_field)
            .transpose()?
            .map(|(value, normalized)| UserIdentifierValue { value, normalized });
        let profile = domain_profile_patch(&command.profile)?;

        let outcome = self
            .repository
            .update_user(UpdateUserTransaction {
                user_oid: command.user_oid,
                username,
                email,
                profile,
                expected_version: command.expected_version,
                reason,
                authority: (*authority).clone(),
            })
            .await
            .map_err(map_repository_error)?;
        map_mutation_outcome(outcome)
    }

    async fn state_user_inner(
        &self,
        authority: &UserManagementAuthority,
        command: UserStateCommand,
        enabled: bool,
    ) -> Result<UserManagementRecord, AppError> {
        let reason = validate_reason(&command.reason)?;
        validate_client_mutation_id(command.client_mutation_id.as_deref())?;

        let outcome = self
            .repository
            .set_user_enabled(
                UserStateTransaction {
                    user_oid: command.user_oid,
                    expected_version: command.expected_version,
                    reason,
                    authority: (*authority).clone(),
                },
                enabled,
            )
            .await
            .map_err(map_repository_error)?;
        map_mutation_outcome(outcome)
    }

    async fn unlock_user_inner(
        &self,
        authority: &UserManagementAuthority,
        command: UserStateCommand,
    ) -> Result<UserManagementRecord, AppError> {
        let reason = validate_reason(&command.reason)?;
        validate_client_mutation_id(command.client_mutation_id.as_deref())?;

        let outcome = self
            .repository
            .unlock_user(UserStateTransaction {
                user_oid: command.user_oid,
                expected_version: command.expected_version,
                reason,
                authority: (*authority).clone(),
            })
            .await
            .map_err(map_repository_error)?;
        map_mutation_outcome(outcome)
    }

    fn emit_mutation(&self, name: &'static str, result: &Result<UserManagementRecord, AppError>) {
        let mut event = BusinessEvent::business(name);
        match result {
            Ok(record) => {
                event = event.outcome("success").attribute(
                    "user_oid",
                    EventValue::Pseudonymized {
                        purpose: "user_oid",
                        value: Uuid::from(record.oid()).to_string(),
                    },
                );
            }
            Err(error) => {
                let (outcome, reason) = error_outcome(error);
                event = event
                    .outcome(outcome)
                    .reason(reason)
                    .attribute("error_code", EventValue::Integer(i64::from(error.code())));
            }
        }
        self.events.emit(event);
    }
}

fn page_conflict() -> AppError {
    AppError::from_code(UserManagementErrorCode::PageArgumentsConflict)
}

fn validate_page_size(value: u32, field: &'static str) -> Result<usize, AppError> {
    if !(1..=MAX_PAGE_SIZE).contains(&value) {
        return Err(
            AppError::from_code(UserManagementErrorCode::PageSizeInvalid)
                .with_param("max", MAX_PAGE_SIZE.to_string())
                .with_field(field),
        );
    }
    Ok(value as usize)
}

/// Normalize an optional audit annotation shared by every user management
/// mutation. Blank input becomes an empty reason; over-long supplied text is
/// rejected.
fn validate_reason(reason: &str) -> Result<String, AppError> {
    let reason = reason.trim();
    if reason.chars().count() > MAX_REASON_LENGTH {
        return Err(
            AppError::from_code(UserManagementErrorCode::ValidationFailed).with_field_error(
                "reason",
                AppError::from_code(UserManagementErrorCode::ReasonTooLong)
                    .with_param("max", MAX_REASON_LENGTH.to_string()),
            ),
        );
    }
    Ok(reason.to_owned())
}

fn validate_client_mutation_id(value: Option<&str>) -> Result<(), AppError> {
    let Some(value) = value else {
        return Ok(());
    };
    if value.chars().count() > MAX_CLIENT_MUTATION_ID_LENGTH {
        return Err(
            AppError::from_code(UserManagementErrorCode::ValidationFailed).with_field_error(
                "clientMutationId",
                AppError::from_code(UserManagementErrorCode::InvalidClientMutationId)
                    .with_param("max", MAX_CLIENT_MUTATION_ID_LENGTH.to_string()),
            ),
        );
    }
    Ok(())
}

fn validate_username_field(value: &str) -> Result<(String, String), AppError> {
    match validate_username(value) {
        Ok(normalized) => Ok((value.trim().to_owned(), normalized)),
        Err(UsernameValidationError::Empty) => Err(AppError::from_code(
            UserManagementErrorCode::ValidationFailed,
        )
        .with_field_error(
            "username",
            AppError::from_code(AccountErrorCode::UsernameRequired),
        )),
        Err(UsernameValidationError::InvalidLength | UsernameValidationError::InvalidCharacter) => {
            Err(
                AppError::from_code(UserManagementErrorCode::ValidationFailed).with_field_error(
                    "username",
                    AppError::from_code(AccountErrorCode::UsernameInvalid),
                ),
            )
        }
    }
}

fn validate_email_field(value: &str) -> Result<(String, String), AppError> {
    match normalize_email(value) {
        Ok(normalized) => Ok((value.trim().to_owned(), normalized)),
        Err(EmailNormalizationError::Empty) => Err(AppError::from_code(
            UserManagementErrorCode::ValidationFailed,
        )
        .with_field_error(
            "email",
            AppError::from_code(AccountErrorCode::EmailRequired),
        )),
        Err(EmailNormalizationError::InvalidFormat | EmailNormalizationError::InvalidDomain) => {
            Err(
                AppError::from_code(UserManagementErrorCode::ValidationFailed)
                    .with_field_error("email", AppError::from_code(AccountErrorCode::EmailInvalid)),
            )
        }
    }
}

fn normalize_filter(filter: UserFilter) -> Result<NormalizedFilter, AppError> {
    let query = normalize_filter_text(filter.query, "query", MAX_QUERY_FILTER_LENGTH)?;
    let username = normalize_filter_text(filter.username, "username", MAX_USERNAME_FILTER_LENGTH)?;
    let email = normalize_filter_text(filter.email, "email", MAX_EMAIL_FILTER_LENGTH)?;
    if let (Some(from), Some(before)) = (filter.created_from, filter.created_before)
        && from >= before
    {
        return Err(
            AppError::from_code(UserManagementErrorCode::InvalidDateRange)
                .with_param("field", "createdFrom")
                .with_field("createdFrom"),
        );
    }
    Ok(NormalizedFilter {
        query,
        username,
        email,
        enabled: filter.enabled,
        locked: filter.locked,
        created_from: filter.created_from,
        created_before: filter.created_before,
    })
}

fn normalize_filter_text(
    value: Option<String>,
    field: &'static str,
    max: usize,
) -> Result<Option<String>, AppError> {
    let Some(value) = value else {
        return Ok(None);
    };
    let value = value.trim();
    if value.is_empty() {
        return Ok(None);
    }
    if value.chars().count() > max {
        return Err(AppError::from_code(UserManagementErrorCode::InvalidFilter)
            .with_param("field", field)
            .with_param("max", max.to_string())
            .with_field(field));
    }
    Ok(Some(value.to_lowercase()))
}

fn map_mutation_outcome(
    outcome: UserManagementMutationOutcome,
) -> Result<UserManagementRecord, AppError> {
    match outcome {
        UserManagementMutationOutcome::Success(record) => Ok(*record),
        UserManagementMutationOutcome::UserNotFound => {
            Err(AppError::from_code(UserManagementErrorCode::UserNotFound))
        }
        UserManagementMutationOutcome::VersionConflict { current_version } => Err(
            AppError::from_code(UserManagementErrorCode::VersionConflict)
                .with_param("current_version", current_version.to_string())
                .with_field("expectedVersion"),
        ),
        UserManagementMutationOutcome::LastOwnerProtected => {
            Err(AppError::from(OwnerProtectionError::LastOwnerProtected))
        }
        UserManagementMutationOutcome::UsernameExists => {
            Err(AppError::from_code(AccountErrorCode::UsernameExists).with_field("username"))
        }
        UserManagementMutationOutcome::EmailExists => {
            Err(AppError::from_code(AccountErrorCode::EmailExists).with_field("email"))
        }
    }
}

fn map_repository_error(error: UserManagementRepositoryError) -> AppError {
    match error {
        UserManagementRepositoryError::Storage(source) => {
            AppError::from_code(UserManagementErrorCode::StorageFailed)
                .with_source(UserManagementRepositoryError::Storage(source))
        }
        UserManagementRepositoryError::Authorization(source) => AppError::from(source),
        UserManagementRepositoryError::AuditFailed(source) => {
            AppError::from_code(AuthorizationErrorCode::AuditWriteFailed)
                .with_source(UserManagementRepositoryError::AuditFailed(source))
        }
        UserManagementRepositoryError::CorruptRecord => {
            AppError::from_code(UserManagementErrorCode::StorageFailed)
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{collections::BTreeSet, sync::Arc};

    use async_trait::async_trait;
    use chrono::{Duration, Utc};
    use identity_domain::{
        authorization::{ActorContext, HumanAuthenticationContext, PolicyVersion, RequestId},
        user::{UserManagementRecord, UserOid, UserTheme},
    };
    use uuid::Uuid;

    use super::{
        super::model, UserManagementService, normalize_filter, validate_reason,
        validate_username_field,
    };
    use crate::{
        auth::{
            password::{HashOptions, PasswordHashError, PasswordHasher, VerifyResult},
            password_policy::BreachedPasswordChecker,
        },
        data_protection::DataProtector,
        domain::data_protection::DataProtectionError,
        error::{AppError, kind::ErrorKind},
        setting::{SettingsSnapshot, SettingsSource},
        user::{
            Password,
            management::{
                model::{
                    UserFilter, UserManagementAuthority, UserPageRequest, UserProfilePatch,
                    UserStateCommand,
                },
                repository::{
                    CreateUserTransaction, UpdateUserTransaction, UserManagementMutationOutcome,
                    UserManagementPageData, UserManagementQuery, UserManagementRepository,
                    UserManagementRepositoryError, UserStateTransaction,
                },
            },
        },
    };

    struct StubRepository {
        outcome: Option<UserManagementMutationOutcome>,
    }

    #[async_trait]
    impl UserManagementRepository for StubRepository {
        async fn count_users(
            &self,
            _filter: UserFilter,
        ) -> Result<u64, UserManagementRepositoryError> {
            Ok(0)
        }

        async fn list_users(
            &self,
            _query: UserManagementQuery,
        ) -> Result<UserManagementPageData, UserManagementRepositoryError> {
            Ok(UserManagementPageData {
                items: Vec::new(),
                has_previous_page: false,
                has_next_page: false,
            })
        }

        async fn find_user(
            &self,
            _user_oid: UserOid,
        ) -> Result<Option<UserManagementRecord>, UserManagementRepositoryError> {
            Ok(None)
        }

        async fn find_users(
            &self,
            _user_oids: Vec<UserOid>,
        ) -> Result<Vec<UserManagementRecord>, UserManagementRepositoryError> {
            Ok(Vec::new())
        }

        async fn create_user(
            &self,
            _command: CreateUserTransaction,
        ) -> Result<UserManagementMutationOutcome, UserManagementRepositoryError> {
            Ok(self
                .outcome
                .clone()
                .unwrap_or(UserManagementMutationOutcome::UserNotFound))
        }

        async fn update_user(
            &self,
            _command: UpdateUserTransaction,
        ) -> Result<UserManagementMutationOutcome, UserManagementRepositoryError> {
            Ok(self
                .outcome
                .clone()
                .unwrap_or(UserManagementMutationOutcome::UserNotFound))
        }

        async fn set_user_enabled(
            &self,
            _command: UserStateTransaction,
            _enabled: bool,
        ) -> Result<UserManagementMutationOutcome, UserManagementRepositoryError> {
            Ok(self
                .outcome
                .clone()
                .unwrap_or(UserManagementMutationOutcome::UserNotFound))
        }

        async fn unlock_user(
            &self,
            _command: UserStateTransaction,
        ) -> Result<UserManagementMutationOutcome, UserManagementRepositoryError> {
            Ok(self
                .outcome
                .clone()
                .unwrap_or(UserManagementMutationOutcome::UserNotFound))
        }
    }

    struct TestProtector;

    #[async_trait]
    impl DataProtector for TestProtector {
        async fn protect(
            &self,
            _purpose: &str,
            plaintext: &[u8],
        ) -> Result<String, DataProtectionError> {
            Ok(String::from_utf8_lossy(plaintext).into_owned())
        }

        async fn unprotect(
            &self,
            _purpose: &str,
            token: &str,
        ) -> Result<Vec<u8>, DataProtectionError> {
            Ok(token.as_bytes().to_vec())
        }
    }

    struct TestSettings;

    impl SettingsSource for TestSettings {
        fn snapshot(&self) -> Arc<SettingsSnapshot> {
            Arc::new(SettingsSnapshot::default())
        }
    }

    struct NeverHasher;

    impl PasswordHasher for NeverHasher {
        fn hash(&self, _: &str, _: &HashOptions) -> Result<Password, PasswordHashError> {
            Err(PasswordHashError::HashFailed("not used".to_owned()))
        }
        fn verify(
            &self,
            _: &str,
            _: &Password,
            _: &HashOptions,
        ) -> Result<VerifyResult, PasswordHashError> {
            Err(PasswordHashError::HashFailed("not used".to_owned()))
        }
    }

    struct NeverBreached;

    #[async_trait]
    impl BreachedPasswordChecker for NeverBreached {
        async fn is_breached(&self, _: &str) -> Result<bool, AppError> {
            Ok(false)
        }
    }

    fn service(outcome: UserManagementMutationOutcome) -> UserManagementService {
        UserManagementService::new(
            Arc::new(StubRepository {
                outcome: Some(outcome),
            }),
            Arc::new(NeverHasher),
            Arc::new(NeverBreached),
            Arc::new(TestSettings),
            Arc::new(TestProtector),
        )
    }

    fn authority() -> UserManagementAuthority {
        UserManagementAuthority::new(
            ActorContext::for_user(
                UserOid(Uuid::new_v4()),
                HumanAuthenticationContext::aal2(None),
                RequestId::new("request-1").unwrap(),
                None,
            ),
            BTreeSet::new(),
            None,
            Uuid::new_v4(),
            PolicyVersion::from_uuid(Uuid::new_v4()),
        )
    }

    #[test]
    fn reason_is_trimmed_and_bounded() {
        assert_eq!(validate_reason("  reviewed  ").unwrap(), "reviewed");
        assert_eq!(validate_reason("   ").unwrap(), "");
        assert_eq!(
            validate_reason(&"x".repeat(1_001))
                .unwrap_err()
                .children_code(),
            Some(16011)
        );
    }

    #[test]
    fn username_validation_preserves_input_and_normalizes_for_uniqueness() {
        assert_eq!(
            validate_username_field(" Alice-01 ").unwrap(),
            ("Alice-01".to_owned(), "alice-01".to_owned())
        );
        assert_eq!(validate_username_field("a").unwrap_err().code(), 16000);
    }

    #[test]
    fn filter_normalization_lowercases_and_rejects_reversed_dates() {
        let filter = UserFilter {
            query: Some("  ADA  ".to_owned()),
            username: Some(" ALICE ".to_owned()),
            ..Default::default()
        };
        let normalized = normalize_filter(filter).unwrap();
        assert_eq!(normalized.query.as_deref(), Some("ada"));
        assert_eq!(normalized.username.as_deref(), Some("alice"));

        let reversed = UserFilter {
            created_from: Some(Utc::now()),
            created_before: Some(Utc::now() - Duration::seconds(1)),
            ..Default::default()
        };
        assert_eq!(normalize_filter(reversed).unwrap_err().code(), 16015);
    }

    #[tokio::test]
    async fn a_stale_version_becomes_a_localized_conflict() {
        let service = service(UserManagementMutationOutcome::VersionConflict {
            current_version: Uuid::new_v4(),
        });
        let error = service
            .unlock_user(
                &authority(),
                UserStateCommand {
                    user_oid: UserOid(Uuid::new_v4()),
                    expected_version: Uuid::new_v4(),
                    reason: "unlock".to_owned(),
                    client_mutation_id: None,
                },
            )
            .await
            .unwrap_err();
        assert_eq!(error.code(), 16008);
        assert_eq!(error.kind(), ErrorKind::Conflict);
        assert!(error.params().get("current_version").is_some());
    }

    #[tokio::test]
    async fn conflicting_pagination_is_rejected_before_storage() {
        let service = service(UserManagementMutationOutcome::UserNotFound);
        let error = service
            .list_users(UserPageRequest {
                first: Some(10),
                last: Some(5),
                ..Default::default()
            })
            .await
            .unwrap_err();
        assert_eq!(error.code(), 16013);
    }

    #[test]
    fn profile_theme_validation_accepts_supported_values_and_rejects_unknown_values() {
        let parsed = model::parse_theme(Some(Some("dark".to_owned()))).unwrap();
        assert_eq!(parsed.flatten().map(UserTheme::as_str), Some("dark"));
        assert!(model::parse_theme(Some(Some("sepia".to_owned()))).is_err());
        assert!(model::domain_profile_patch(&UserProfilePatch::default()).is_ok());
    }

    trait ChildCode {
        fn children_code(&self) -> Option<u32>;
    }

    impl ChildCode for AppError {
        fn children_code(&self) -> Option<u32> {
            self.validation()
                .and_then(|details| details.fields().first())
                .map(|field| field.code())
        }
    }
}
