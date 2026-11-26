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
    authorization::{ActorPrincipal, OwnerProtectionError},
    user::{
        UserManagementRecord, UserOid,
        normalization::{
            EmailNormalizationError, UsernameValidationError, normalize_email, validate_username,
        },
    },
};
use uuid::Uuid;

use crate::{
    authentication::{
        hash::PasswordHasher,
        password::run_password_hashing,
        password_policy::{BreachedPasswordChecker, validate_breached_password, validate_password},
    },
    data_protection::DataProtector,
    error::{
        AppError,
        codes::{account, authorization, user_management},
    },
    observability::{BusinessEvent, EventSink, EventValue, NoopEventSink, error_outcome},
    setting::{PasswordHashSetting, PasswordHistoryCountSetting, SettingsSource},
    user::invitation::{
        InvitationDelivery, Invitee, USER_INVITATION_DELIVERY, UserInvitationRepository,
        UserInvitationStatus,
    },
    user::management::{
        cursor::{NormalizedFilter, decode_cursor, encode_cursor},
        model::{
            CreateUserCommand, RevokeUserSessionsCommand, SendUserInvitationCommand,
            UpdateUserCommand, UserFilter, UserManagementAuthority, UserManagementPage,
            UserManagementPageItem, UserPageRequest, UserPasswordResetResult, UserStateCommand,
            domain_profile_patch,
        },
        repository::{
            CreateUserTransaction, RevokeUserSessionsTransaction, SendUserInvitationTransaction,
            UpdateUserTransaction, UserIdentifierValue, UserInvitationOutcome,
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
    invitations: Option<UserInvitations>,
    events: Arc<dyn EventSink>,
}

/// What sending invitations needs.
#[derive(Clone)]
pub struct UserInvitations {
    pub delivery: InvitationDelivery,
    pub repository: Arc<dyn UserInvitationRepository>,
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
            invitations: None,
            events: Arc::new(NoopEventSink),
        }
    }

    /// Let administrators invite users by email.
    #[must_use]
    pub fn with_invitations(mut self, invitations: UserInvitations) -> Self {
        self.invitations = Some(invitations);
        self
    }

    /// Whether an invitation can be sent now.
    #[must_use]
    pub fn invitations_available(&self) -> bool {
        self.invitations
            .as_ref()
            .is_some_and(|invitations| invitations.delivery.available())
    }

    /// The user's outstanding invitation, for a field already admitted with
    /// `management.user.read`.
    pub async fn invitation_status(
        &self,
        user_oid: UserOid,
    ) -> Result<Option<UserInvitationStatus>, AppError> {
        match &self.invitations {
            Some(invitations) => invitations.repository.find_for_user(user_oid).await,
            None => Ok(None),
        }
    }

    fn available_invitations(&self) -> Result<&UserInvitations, AppError> {
        self.invitations
            .as_ref()
            .filter(|invitations| invitations.delivery.available())
            .ok_or_else(|| user_management::error::InvitationUnavailable::new().into())
    }

    /// Email a new invitation link to a user who has no password yet,
    /// replacing any earlier link.
    #[tracing::instrument(skip_all, name = "user.management.send_invitation")]
    pub async fn send_user_invitation(
        &self,
        authority: &UserManagementAuthority,
        command: SendUserInvitationCommand,
    ) -> Result<(UserManagementRecord, UserInvitationStatus), AppError> {
        let result = self.send_user_invitation_inner(authority, command).await;
        self.emit_mutation_ref(
            "user.management.send_invitation",
            result.as_ref().map(|(record, _)| record),
        );
        result
    }

    async fn send_user_invitation_inner(
        &self,
        authority: &UserManagementAuthority,
        command: SendUserInvitationCommand,
    ) -> Result<(UserManagementRecord, UserInvitationStatus), AppError> {
        let reason = validate_reason(&command.reason)?;
        validate_client_mutation_id(command.client_mutation_id.as_deref())?;
        let invitations = self.available_invitations()?;
        let now = chrono::Utc::now();
        let Some(current) = self
            .repository
            .find_user(command.user_oid)
            .await
            .map_err(map_repository_error)?
        else {
            return Err(user_management::error::UserNotFound::new().into());
        };
        let user = &current.user;
        let issue = invitations.delivery.issue(
            &Invitee {
                name: &user.name,
                email: &user.email,
                email_normalized: &user.email_normalized,
                locale: user.locale.as_deref(),
            },
            now,
        )?;
        let outcome = self
            .repository
            .send_user_invitation(SendUserInvitationTransaction {
                user_oid: command.user_oid,
                invitation: issue,
                delivery: USER_INVITATION_DELIVERY,
                reason,
                authority: (*authority).clone(),
            })
            .await
            .map_err(map_repository_error)?;
        let (record, status) = match outcome {
            UserInvitationOutcome::Sent { record, invitation } => (*record, invitation),
            UserInvitationOutcome::UserNotFound => {
                return Err(user_management::error::UserNotFound.into());
            }
            UserInvitationOutcome::UserDisabled => {
                return Err(user_management::error::InvitationUserDisabled.into());
            }
            UserInvitationOutcome::HasPassword => {
                return Err(user_management::error::InvitationNotPending.into());
            }
            UserInvitationOutcome::TooSoon { available_at } => {
                let seconds = (available_at - now).num_seconds().max(1);
                return Err(user_management::error::InvitationResendTooSoon::new(seconds).into());
            }
            // The address changed after the email was written for it.
            UserInvitationOutcome::AddressChanged { current_version } => {
                return Err(user_management::error::VersionConflict::new(current_version).into());
            }
        };
        Ok((record, status))
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
            return Err(user_management::error::ValidationFailed::new().into());
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
        self.emit_mutation_ref("user.management.create", result.as_ref());
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

    /// Replace the user's password with a generated temporary one that must
    /// be changed at the next sign-in, and sign the user out everywhere.
    #[tracing::instrument(skip_all, name = "user.management.reset_password")]
    pub async fn reset_user_password(
        &self,
        authority: &UserManagementAuthority,
        command: UserStateCommand,
    ) -> Result<UserPasswordResetResult, AppError> {
        let result = async {
            reject_self_credential_action(authority, command.user_oid)?;
            let transaction = self.state_transaction(authority, &command)?;
            let temporary_password = temporary_password();
            let snapshot = self.settings.snapshot();
            let hash_options = snapshot.get::<PasswordHashSetting>();
            let keep_history = snapshot
                .get::<PasswordHistoryCountSetting>()
                .saturating_sub(1);
            let hasher = Arc::clone(&self.password_hasher);
            let plain = temporary_password.clone();
            let password = run_password_hashing(move || hasher.hash(&plain, &hash_options)).await?;
            let outcome = self
                .repository
                .reset_user_password(transaction, password, keep_history)
                .await
                .map_err(map_repository_error)?;
            Ok(UserPasswordResetResult {
                record: map_mutation_outcome(outcome)?,
                temporary_password,
            })
        }
        .await;
        self.emit_mutation_ref(
            "user.management.reset_password",
            result.as_ref().map(|result| &result.record),
        );
        result
    }

    /// Remove the user's authenticator app, recovery codes and passkeys, and
    /// sign the user out everywhere.
    #[tracing::instrument(skip_all, name = "user.management.reset_mfa")]
    pub async fn reset_user_mfa(
        &self,
        authority: &UserManagementAuthority,
        command: UserStateCommand,
    ) -> Result<UserManagementRecord, AppError> {
        let result = async {
            reject_self_credential_action(authority, command.user_oid)?;
            let transaction = self.state_transaction(authority, &command)?;
            let outcome = self
                .repository
                .reset_user_mfa(transaction)
                .await
                .map_err(map_repository_error)?;
            map_mutation_outcome(outcome)
        }
        .await;
        self.emit_mutation("user.management.reset_mfa", &result);
        result
    }

    /// Revoke the listed sessions of the user, or all of them.
    #[tracing::instrument(skip_all, name = "user.management.revoke_sessions")]
    pub async fn revoke_user_sessions(
        &self,
        authority: &UserManagementAuthority,
        command: RevokeUserSessionsCommand,
    ) -> Result<UserManagementRecord, AppError> {
        let result = async {
            let reason = validate_reason(&command.reason)?;
            validate_client_mutation_id(command.client_mutation_id.as_deref())?;
            let outcome = self
                .repository
                .revoke_user_sessions(RevokeUserSessionsTransaction {
                    user_oid: command.user_oid,
                    sessions: command.sessions,
                    reason,
                    authority: (*authority).clone(),
                })
                .await
                .map_err(map_repository_error)?;
            map_mutation_outcome(outcome)
        }
        .await;
        self.emit_mutation("user.management.revoke_sessions", &result);
        result
    }

    /// Delete a disabled user.
    #[tracing::instrument(skip_all, name = "user.management.delete")]
    pub async fn delete_user(
        &self,
        authority: &UserManagementAuthority,
        command: UserStateCommand,
    ) -> Result<UserManagementRecord, AppError> {
        let result = async {
            let transaction = self.state_transaction(authority, &command)?;
            let outcome = self
                .repository
                .delete_user(transaction)
                .await
                .map_err(map_repository_error)?;
            map_mutation_outcome(outcome)
        }
        .await;
        self.emit_mutation("user.management.delete", &result);
        result
    }

    fn state_transaction(
        &self,
        authority: &UserManagementAuthority,
        command: &UserStateCommand,
    ) -> Result<UserStateTransaction, AppError> {
        let reason = validate_reason(&command.reason)?;
        validate_client_mutation_id(command.client_mutation_id.as_deref())?;
        Ok(UserStateTransaction {
            user_oid: command.user_oid,
            expected_version: command.expected_version,
            reason,
            authority: (*authority).clone(),
        })
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

        let (password, invitation) = match (command.password, command.send_invitation) {
            (Some(password), false) => {
                validate_password(password.as_str(), &[&username, &email], "password")?;
                validate_breached_password(
                    self.breach_checker.as_ref(),
                    &self.settings.snapshot(),
                    password.as_str(),
                    "password",
                )
                .await?;
                let hash_options = self.settings.snapshot().get::<PasswordHashSetting>();
                let hasher = Arc::clone(&self.password_hasher);
                let password = password.into_inner();
                let password =
                    run_password_hashing(move || hasher.hash(&password, &hash_options)).await?;
                (Some(password), None)
            }
            (None, true) => {
                let issue = self.available_invitations()?.delivery.issue(
                    &Invitee {
                        name: &username,
                        email: &email,
                        email_normalized: &email_normalized,
                        locale: profile.locale.as_ref().and_then(|locale| locale.as_deref()),
                    },
                    chrono::Utc::now(),
                )?;
                (None, Some(issue))
            }
            _ => {
                return Err(
                    user_management::error::ValidationFailed::new().with_field_error(
                        "password",
                        user_management::error::CredentialChoiceRequired,
                    ),
                );
            }
        };

        let outcome = self
            .repository
            .create_user(CreateUserTransaction {
                username,
                username_normalized,
                email,
                email_normalized,
                password,
                invitation,
                profile,
                reason,
                authority: (*authority).clone(),
            })
            .await
            .map_err(map_repository_error)?;
        // An invitation's email is queued with the account.
        map_mutation_outcome(outcome)
    }

    async fn update_user_inner(
        &self,
        authority: &UserManagementAuthority,
        command: UpdateUserCommand,
    ) -> Result<UserManagementRecord, AppError> {
        // Clearing is harmless; requiring anything of one's own next sign-in
        // belongs in the account center.
        if command
            .required_actions
            .as_ref()
            .is_some_and(|actions| !actions.is_empty())
        {
            reject_self_credential_action(authority, command.user_oid)?;
        }
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
                email_verified: command.email_verified,
                required_actions: command.required_actions,
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
        self.emit_mutation_ref(name, result.as_ref());
    }

    fn emit_mutation_ref(
        &self,
        name: &'static str,
        result: Result<&UserManagementRecord, &AppError>,
    ) {
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

fn reject_self_credential_action(
    authority: &UserManagementAuthority,
    target: UserOid,
) -> Result<(), AppError> {
    if matches!(
        authority.actor.principal,
        ActorPrincipal::User { user_oid, .. } if user_oid == target
    ) {
        return Err(user_management::error::SelfCredentialActionNotAllowed.into());
    }
    Ok(())
}

fn page_conflict() -> AppError {
    user_management::error::PageArgumentsConflict.into()
}

fn validate_page_size(value: u32, field: &'static str) -> Result<usize, AppError> {
    if !(1..=MAX_PAGE_SIZE).contains(&value) {
        return Err(user_management::error::PageSizeInvalid::new(MAX_PAGE_SIZE).with_field(field));
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
            user_management::error::ValidationFailed::new().with_field_error(
                "reason",
                user_management::error::ReasonTooLong::new(MAX_REASON_LENGTH),
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
            user_management::error::ValidationFailed::new().with_field_error(
                "clientMutationId",
                user_management::error::InvalidClientMutationId::new(MAX_CLIENT_MUTATION_ID_LENGTH),
            ),
        );
    }
    Ok(())
}

fn validate_username_field(value: &str) -> Result<(String, String), AppError> {
    match validate_username(value) {
        Ok(normalized) => Ok((value.trim().to_owned(), normalized)),
        Err(UsernameValidationError::Empty) => Err(user_management::error::ValidationFailed::new()
            .with_field_error("username", account::error::UsernameRequired)),
        Err(UsernameValidationError::InvalidLength | UsernameValidationError::InvalidCharacter) => {
            Err(user_management::error::ValidationFailed::new()
                .with_field_error("username", account::error::UsernameInvalid))
        }
    }
}

fn validate_email_field(value: &str) -> Result<(String, String), AppError> {
    match normalize_email(value) {
        Ok(normalized) => Ok((value.trim().to_owned(), normalized)),
        Err(EmailNormalizationError::Empty) => Err(user_management::error::ValidationFailed::new()
            .with_field_error("email", account::error::EmailRequired)),
        Err(EmailNormalizationError::InvalidFormat | EmailNormalizationError::InvalidDomain) => {
            Err(user_management::error::ValidationFailed::new()
                .with_field_error("email", account::error::EmailInvalid))
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
            user_management::error::InvalidDateRange::new("createdFrom").with_field("createdFrom")
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
        return Err(user_management::error::InvalidFilter::new(field)
            .max(max)
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
            Err(user_management::error::UserNotFound.into())
        }
        UserManagementMutationOutcome::VersionConflict { current_version } => Err(
            user_management::error::VersionConflict::new(current_version)
                .with_field("expectedVersion"),
        ),
        UserManagementMutationOutcome::LastOwnerProtected => {
            Err(AppError::from(OwnerProtectionError::LastOwnerProtected))
        }
        UserManagementMutationOutcome::UsernameExists => {
            Err(account::error::UsernameExists.with_field("username"))
        }
        UserManagementMutationOutcome::EmailExists => {
            Err(account::error::EmailExists.with_field("email"))
        }
        UserManagementMutationOutcome::NotDisabled => {
            Err(user_management::error::UserNotDisabled.into())
        }
        UserManagementMutationOutcome::NoPassword => {
            Err(user_management::error::UserHasNoPassword.into())
        }
        UserManagementMutationOutcome::SessionNotFound => {
            Err(user_management::error::SessionNotFound.into())
        }
    }
}

/// Characters of a generated temporary password: four unambiguous character
/// classes without look-alikes (`0`/`O` or `1`/`l`/`I`).
const TEMPORARY_PASSWORD_LOWER: &[u8] = b"abcdefghjkmnpqrstuvwxyz";
const TEMPORARY_PASSWORD_UPPER: &[u8] = b"ABCDEFGHJKLMNPQRSTUVWXYZ";
const TEMPORARY_PASSWORD_DIGITS: &[u8] = b"23456789";
const TEMPORARY_PASSWORD_SYMBOLS: &[u8] = b"!@#$%^&*";
const TEMPORARY_PASSWORD_ALL: &[u8] =
    b"abcdefghjkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789!@#$%^&*";
const TEMPORARY_PASSWORD_LENGTH: usize = 16;

/// Sixteen random characters covering lowercase, uppercase, digits, and symbols.
fn temporary_password() -> String {
    use rand::RngExt;
    let mut rng = rand::rng();
    let mut pick = |alphabet: &[u8]| alphabet[rng.random_range(0..alphabet.len())];
    let mut chars = Vec::with_capacity(TEMPORARY_PASSWORD_LENGTH);
    chars.push(pick(TEMPORARY_PASSWORD_LOWER));
    chars.push(pick(TEMPORARY_PASSWORD_UPPER));
    chars.push(pick(TEMPORARY_PASSWORD_DIGITS));
    chars.push(pick(TEMPORARY_PASSWORD_SYMBOLS));
    while chars.len() < TEMPORARY_PASSWORD_LENGTH {
        chars.push(pick(TEMPORARY_PASSWORD_ALL));
    }
    for i in (1..chars.len()).rev() {
        let j = rng.random_range(0..=i);
        chars.swap(i, j);
    }
    chars.into_iter().map(char::from).collect()
}

fn map_repository_error(error: UserManagementRepositoryError) -> AppError {
    match error {
        UserManagementRepositoryError::Storage(source) => user_management::error::StorageFailed
            .with_source(UserManagementRepositoryError::Storage(source)),
        UserManagementRepositoryError::Authorization(source) => AppError::from(source),
        UserManagementRepositoryError::AuditFailed(source) => {
            authorization::error::AuditWriteFailed
                .with_source(UserManagementRepositoryError::AuditFailed(source))
        }
        UserManagementRepositoryError::CorruptRecord => {
            user_management::error::StorageFailed.into()
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{collections::BTreeSet, sync::Arc};

    use async_trait::async_trait;
    use chrono::{Duration, Utc};
    use identity_domain::{
        authorization::{
            ActorContext, ActorPrincipal, HumanAuthenticationContext, PolicyVersion, RequestId,
        },
        user::{RequiredAction, RequiredActions, UserManagementRecord, UserOid, UserTheme},
    };
    use uuid::Uuid;

    fn change_password() -> RequiredActions {
        [RequiredAction::ChangePassword].into()
    }

    use super::{
        super::model, UserManagementService, normalize_filter, validate_reason,
        validate_username_field,
    };
    use crate::{
        authentication::{
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

        async fn reset_user_password(
            &self,
            _command: UserStateTransaction,
            _password: crate::user::Password,
            _keep_history: u32,
        ) -> Result<UserManagementMutationOutcome, UserManagementRepositoryError> {
            Ok(self
                .outcome
                .clone()
                .unwrap_or(UserManagementMutationOutcome::UserNotFound))
        }

        async fn reset_user_mfa(
            &self,
            _command: UserStateTransaction,
        ) -> Result<UserManagementMutationOutcome, UserManagementRepositoryError> {
            Ok(self
                .outcome
                .clone()
                .unwrap_or(UserManagementMutationOutcome::UserNotFound))
        }

        async fn revoke_user_sessions(
            &self,
            _command: crate::user::management::RevokeUserSessionsTransaction,
        ) -> Result<UserManagementMutationOutcome, UserManagementRepositoryError> {
            Ok(self
                .outcome
                .clone()
                .unwrap_or(UserManagementMutationOutcome::UserNotFound))
        }

        async fn delete_user(
            &self,
            _command: UserStateTransaction,
        ) -> Result<UserManagementMutationOutcome, UserManagementRepositoryError> {
            Ok(self
                .outcome
                .clone()
                .unwrap_or(UserManagementMutationOutcome::UserNotFound))
        }

        async fn send_user_invitation(
            &self,
            _command: crate::user::management::SendUserInvitationTransaction,
        ) -> Result<crate::user::management::UserInvitationOutcome, UserManagementRepositoryError>
        {
            Ok(crate::user::management::UserInvitationOutcome::UserNotFound)
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

    fn create_command(password: Option<&str>, send_invitation: bool) -> model::CreateUserCommand {
        model::CreateUserCommand {
            username: "new-user".to_owned(),
            email: "new-user@example.test".to_owned(),
            password: password.map(model::UserPassword::new),
            send_invitation,
            profile: UserProfilePatch::default(),
            reason: String::new(),
            client_mutation_id: None,
        }
    }

    #[tokio::test]
    async fn a_new_user_needs_exactly_one_first_sign_in_method() {
        let service = service(UserManagementMutationOutcome::UserNotFound);
        for command in [
            create_command(None, false),
            create_command(Some("correct horse battery staple"), true),
        ] {
            let error = service
                .create_user(&authority(), command)
                .await
                .unwrap_err();
            assert_eq!(error.code(), 16000);
            assert_eq!(error.children_code(), Some(16029));
        }
    }

    #[tokio::test]
    async fn invitations_need_email_delivery() {
        let service = service(UserManagementMutationOutcome::UserNotFound);
        assert!(!service.invitations_available());
        let error = service
            .create_user(&authority(), create_command(None, true))
            .await
            .unwrap_err();
        assert_eq!(error.code(), 16025);
        let error = service
            .send_user_invitation(
                &authority(),
                model::SendUserInvitationCommand {
                    user_oid: UserOid(Uuid::new_v4()),
                    reason: String::new(),
                    client_mutation_id: None,
                },
            )
            .await
            .unwrap_err();
        assert_eq!(error.code(), 16025);
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

    #[test]
    fn temporary_passwords_are_long_unambiguous_and_distinct() {
        let first = super::temporary_password();
        let second = super::temporary_password();
        assert_ne!(first, second);
        for password in [&first, &second] {
            assert_eq!(password.len(), super::TEMPORARY_PASSWORD_LENGTH);
            assert!(!password.contains('-'));
            assert!(!password.contains(['0', 'O', '1', 'l', 'I']));
            assert!(
                password
                    .bytes()
                    .all(|b| super::TEMPORARY_PASSWORD_ALL.contains(&b))
            );
            assert!(
                password
                    .bytes()
                    .any(|b| super::TEMPORARY_PASSWORD_LOWER.contains(&b))
            );
            assert!(
                password
                    .bytes()
                    .any(|b| super::TEMPORARY_PASSWORD_UPPER.contains(&b))
            );
            assert!(
                password
                    .bytes()
                    .any(|b| super::TEMPORARY_PASSWORD_DIGITS.contains(&b))
            );
            assert!(
                password
                    .bytes()
                    .any(|b| super::TEMPORARY_PASSWORD_SYMBOLS.contains(&b))
            );
            crate::authentication::password_policy::validate_password(password, &[], "password")
                .unwrap();
        }
    }

    #[tokio::test]
    async fn refused_admin_operations_become_their_own_errors() {
        let command = || model::UserStateCommand {
            user_oid: UserOid(Uuid::new_v4()),
            expected_version: Uuid::new_v4(),
            reason: String::new(),
            client_mutation_id: None,
        };
        let error = service(UserManagementMutationOutcome::NotDisabled)
            .delete_user(&authority(), command())
            .await
            .unwrap_err();
        assert_eq!(
            error.code(),
            crate::error::codes::user_management::UserManagementErrorCode::UserNotDisabled as u32
        );
        let error = service(UserManagementMutationOutcome::NoPassword)
            .reset_user_mfa(&authority(), command())
            .await
            .unwrap_err();
        assert_eq!(
            error.code(),
            crate::error::codes::user_management::UserManagementErrorCode::UserHasNoPassword as u32
        );
        let error = service(UserManagementMutationOutcome::SessionNotFound)
            .revoke_user_sessions(
                &authority(),
                model::RevokeUserSessionsCommand {
                    user_oid: UserOid(Uuid::new_v4()),
                    sessions: Some(vec![Uuid::new_v4()]),
                    reason: String::new(),
                    client_mutation_id: None,
                },
            )
            .await
            .unwrap_err();
        assert_eq!(
            error.code(),
            crate::error::codes::user_management::UserManagementErrorCode::SessionNotFound as u32
        );
    }

    #[tokio::test]
    async fn self_credential_actions_are_refused_for_users_only() {
        let auth = authority();
        let ActorPrincipal::User {
            user_oid: self_oid, ..
        } = auth.actor.principal
        else {
            panic!("expected user actor");
        };
        let service = service(UserManagementMutationOutcome::UserNotFound);
        let state = model::UserStateCommand {
            user_oid: self_oid,
            expected_version: Uuid::new_v4(),
            reason: String::new(),
            client_mutation_id: None,
        };
        let self_code =
            crate::error::codes::user_management::UserManagementErrorCode::SelfCredentialActionNotAllowed as u32;
        let not_found_code =
            crate::error::codes::user_management::UserManagementErrorCode::UserNotFound as u32;

        let err = service
            .reset_user_password(&auth, state.clone())
            .await
            .err()
            .unwrap();
        assert_eq!(err.code(), self_code);

        let err = service.reset_user_mfa(&auth, state).await.unwrap_err();
        assert_eq!(err.code(), self_code);

        let update = |required_actions| model::UpdateUserCommand {
            user_oid: self_oid,
            username: None,
            email: None,
            email_verified: None,
            required_actions,
            profile: UserProfilePatch::default(),
            expected_version: Uuid::new_v4(),
            reason: String::new(),
            client_mutation_id: None,
        };
        let err = service
            .update_user(&auth, update(Some(change_password())))
            .await
            .unwrap_err();
        assert_eq!(err.code(), self_code);

        for keep_or_clear in [None, Some(RequiredActions::new())] {
            let err = service
                .update_user(&auth, update(keep_or_clear))
                .await
                .unwrap_err();
            assert_eq!(err.code(), not_found_code);
        }

        let machine_auth = UserManagementAuthority::new(
            ActorContext::for_client(
                Uuid::new_v4(),
                RequestId::new("request-client").unwrap(),
                None,
            ),
            BTreeSet::new(),
            None,
            Uuid::new_v4(),
            PolicyVersion::from_uuid(Uuid::new_v4()),
        );
        let err = service
            .reset_user_mfa(
                &machine_auth,
                model::UserStateCommand {
                    user_oid: self_oid,
                    expected_version: Uuid::new_v4(),
                    reason: String::new(),
                    client_mutation_id: None,
                },
            )
            .await
            .unwrap_err();
        assert_eq!(err.code(), not_found_code);
        let err = service
            .update_user(&machine_auth, update(Some(change_password())))
            .await
            .unwrap_err();
        assert_eq!(err.code(), not_found_code);
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
