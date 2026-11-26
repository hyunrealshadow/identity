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

mod rules;
use rules::*;
#[cfg(test)]
mod tests;
