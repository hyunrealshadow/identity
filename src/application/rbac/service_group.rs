//! User-group management use cases.
//!
//! Every write requires the exact group permission, re-verifies live authority
//! and the delegation ceiling inside the repository transaction, applies CAS,
//! protects the last recoverable administrator and writes the semantic audit
//! fact before commit. Every write accepts an optional reason annotation

use std::{collections::BTreeSet, sync::Arc};

use identity_domain::{
    rbac,
    rbac::{
        GroupMembershipOid, GroupOid, GroupRoleBindingOid, GroupValidationError, LocalizedMetadata,
        LocalizedTextError, RoleOid, group, group::MAX_GROUP_REASON_LENGTH,
        validate_group_descriptions, validate_group_names,
    },
};

use super::group::GroupFilter as GroupGroupFilter;
use crate::{
    data_protection::DataProtector,
    error::{
        AppError,
        codes::{authorization::AuthorizationErrorCode, group::GroupErrorCode},
    },
    observability::{BusinessEvent, EventSink, EventValue, NoopEventSink, error_outcome},
    rbac::{
        cursor::{PageArguments, encode_cursor, prepare_page},
        group::{
            AddGroupMemberCommand, CreateGroupCommand, DeleteGroupCommand, DeleteGroupResult,
            GroupFilter, GroupMembershipMutationResult, GroupMembershipPage,
            GroupMembershipPageItem, GroupMembershipPageRequest, GroupMembershipRecord, GroupPage,
            GroupPageItem, GroupPageRequest, GroupRecord, GroupRoleBindingRecord,
            GroupRoleMutationResult, GroupRolePage, GroupRolePageItem, GroupRolePageRequest,
            GroupStateCommand, MAX_GROUP_ROLES, RemoveGroupMemberCommand, SetGroupRolesCommand,
            UpdateGroupCommand,
        },
        group_repository::{
            AddGroupMemberTransaction, CreateGroupTransaction, DeleteGroupTransaction,
            GroupEntityKind, GroupManagementRepository, GroupManagementRepositoryError,
            GroupMembershipQuery, GroupQuery, GroupRoleQuery, GroupStateTransaction,
            RemoveGroupMemberTransaction, SetGroupRolesTransaction, UpdateGroupTransaction,
        },
        model::{MAX_CLIENT_MUTATION_ID_LENGTH, MAX_QUERY_FILTER_LENGTH, RbacManagementAuthority},
    },
};

const CURSOR_KIND_GROUP: u8 = 9;
const CURSOR_KIND_GROUP_MEMBERSHIP: u8 = 10;
const CURSOR_KIND_GROUP_ROLE: u8 = 11;

pub struct GroupManagementService {
    repository: Arc<dyn GroupManagementRepository>,
    data_protector: Arc<dyn DataProtector>,
    events: Arc<dyn EventSink>,
}

impl GroupManagementService {
    #[must_use]
    pub fn new(
        repository: Arc<dyn GroupManagementRepository>,
        data_protector: Arc<dyn DataProtector>,
    ) -> Self {
        Self {
            repository,
            data_protector,
            events: Arc::new(NoopEventSink),
        }
    }

    #[must_use]
    pub fn with_events(mut self, events: Arc<dyn EventSink>) -> Self {
        self.events = events;
        self
    }

    // ------------------------------------------------------------------
    // Reads
    // ------------------------------------------------------------------

    #[tracing::instrument(skip_all, name = "rbac.group.find")]
    pub async fn find_group(&self, oid: GroupOid) -> Result<Option<GroupRecord>, AppError> {
        self.repository
            .find_group(oid)
            .await
            .map_err(map_repository_error)
    }

    #[tracing::instrument(skip_all, name = "rbac.group.membership.find")]
    pub async fn find_group_membership(
        &self,
        oid: GroupMembershipOid,
    ) -> Result<Option<GroupMembershipRecord>, AppError> {
        self.repository
            .find_group_membership(oid)
            .await
            .map_err(map_repository_error)
    }

    #[tracing::instrument(skip_all, name = "rbac.group.role_binding.find")]
    pub async fn find_group_role_binding(
        &self,
        oid: GroupRoleBindingOid,
    ) -> Result<Option<GroupRoleBindingRecord>, AppError> {
        self.repository
            .find_group_role_binding(oid)
            .await
            .map_err(map_repository_error)
    }

    #[tracing::instrument(skip_all, name = "rbac.group.count")]
    pub async fn count_groups(&self, filter: GroupGroupFilter) -> Result<u64, AppError> {
        self.repository
            .count_groups(normalize_group_filter(filter)?)
            .await
            .map_err(map_repository_error)
    }

    #[tracing::instrument(skip_all, name = "rbac.group.list")]
    pub async fn list_groups(&self, request: GroupPageRequest) -> Result<GroupPage, AppError> {
        let filter = normalize_group_filter(request.filter)?;
        let order = request.order;
        let prepared = prepare_page(
            self.data_protector.as_ref(),
            CURSOR_KIND_GROUP,
            order.as_u8(),
            &filter,
            PageArguments {
                first: request.first,
                after: request.after,
                last: request.last,
                before: request.before,
            },
        )
        .await?;
        let data = self
            .repository
            .list_groups(GroupQuery {
                filter,
                order,
                direction: prepared.direction,
                after: prepared.after,
                before: prepared.before,
                limit: prepared.limit,
            })
            .await
            .map_err(map_repository_error)?;
        let mut items = Vec::with_capacity(data.items.len());
        for entry in data.items {
            let cursor = encode_cursor(
                self.data_protector.as_ref(),
                CURSOR_KIND_GROUP,
                order.as_u8(),
                &prepared.filter_fingerprint,
                &entry.sort_key,
            )
            .await?;
            items.push(GroupPageItem {
                record: entry.record,
                cursor,
            });
        }
        Ok(GroupPage {
            items,
            has_previous_page: data.has_previous_page,
            has_next_page: data.has_next_page,
        })
    }

    #[tracing::instrument(skip_all, name = "rbac.group.memberships.list")]
    pub async fn list_group_memberships(
        &self,
        group_oid: GroupOid,
        request: GroupMembershipPageRequest,
    ) -> Result<GroupMembershipPage, AppError> {
        let order = request.order;
        let fingerprint = (group_oid, &request.filter);
        let prepared = prepare_page(
            self.data_protector.as_ref(),
            CURSOR_KIND_GROUP_MEMBERSHIP,
            order.as_u8(),
            &fingerprint,
            PageArguments {
                first: request.first,
                after: request.after,
                last: request.last,
                before: request.before,
            },
        )
        .await?;
        let data = self
            .repository
            .list_group_memberships(GroupMembershipQuery {
                group_oid,
                filter: request.filter,
                order,
                direction: prepared.direction,
                after: prepared.after,
                before: prepared.before,
                limit: prepared.limit,
            })
            .await
            .map_err(map_repository_error)?;
        let mut items = Vec::with_capacity(data.items.len());
        for entry in data.items {
            let cursor = encode_cursor(
                self.data_protector.as_ref(),
                CURSOR_KIND_GROUP_MEMBERSHIP,
                order.as_u8(),
                &prepared.filter_fingerprint,
                &entry.sort_key,
            )
            .await?;
            items.push(GroupMembershipPageItem {
                record: entry.record,
                cursor,
            });
        }
        Ok(GroupMembershipPage {
            items,
            has_previous_page: data.has_previous_page,
            has_next_page: data.has_next_page,
        })
    }

    #[tracing::instrument(skip_all, name = "rbac.group.roles.list")]
    pub async fn list_group_roles(
        &self,
        group_oid: GroupOid,
        request: GroupRolePageRequest,
    ) -> Result<GroupRolePage, AppError> {
        let order = request.order;
        let fingerprint = (group_oid, &request.filter);
        let prepared = prepare_page(
            self.data_protector.as_ref(),
            CURSOR_KIND_GROUP_ROLE,
            order.as_u8(),
            &fingerprint,
            PageArguments {
                first: request.first,
                after: request.after,
                last: request.last,
                before: request.before,
            },
        )
        .await?;
        let data = self
            .repository
            .list_group_roles(GroupRoleQuery {
                group_oid,
                filter: request.filter,
                order,
                direction: prepared.direction,
                after: prepared.after,
                before: prepared.before,
                limit: prepared.limit,
            })
            .await
            .map_err(map_repository_error)?;
        let mut items = Vec::with_capacity(data.items.len());
        for entry in data.items {
            let cursor = encode_cursor(
                self.data_protector.as_ref(),
                CURSOR_KIND_GROUP_ROLE,
                order.as_u8(),
                &prepared.filter_fingerprint,
                &entry.sort_key,
            )
            .await?;
            items.push(GroupRolePageItem {
                record: entry.record,
                cursor,
            });
        }
        Ok(GroupRolePage {
            items,
            has_previous_page: data.has_previous_page,
            has_next_page: data.has_next_page,
        })
    }

    // ------------------------------------------------------------------
    // Writes
    // ------------------------------------------------------------------

    #[tracing::instrument(skip_all, name = "rbac.group.create")]
    pub async fn create_group(
        &self,
        authority: &RbacManagementAuthority,
        command: CreateGroupCommand,
    ) -> Result<GroupRecord, AppError> {
        let result = async {
            let reason = validate_reason(&command.reason)?;
            validate_client_mutation_id(command.client_mutation_id.as_deref())?;
            let metadata = LocalizedMetadata::canonicalize(command.names, command.descriptions)
                .map_err(map_localized_error)?;
            self.repository
                .create_group(CreateGroupTransaction {
                    group_oid: GroupOid::new(),
                    name: validate_default_text(&command.name, true)?,
                    description: validate_default_text(&command.description, false)?,
                    names: metadata.names,
                    descriptions: metadata.descriptions,
                    reason,
                    authority: authority.clone(),
                })
                .await
                .map_err(map_repository_error)
        }
        .await;
        self.emit_result("rbac.group.create", &result);
        result
    }

    #[tracing::instrument(skip_all, name = "rbac.group.update")]
    pub async fn update_group(
        &self,
        authority: &RbacManagementAuthority,
        command: UpdateGroupCommand,
    ) -> Result<GroupRecord, AppError> {
        let result = async {
            let reason = validate_reason(&command.reason)?;
            validate_client_mutation_id(command.client_mutation_id.as_deref())?;

            if command.name.is_none()
                && command.description.is_none()
                && command.names.is_none()
                && command.descriptions.is_none()
            {
                return Err(AppError::from_code(GroupErrorCode::EmptyUpdate));
            }
            if let Some(names) = &command.names {
                validate_group_names(names).map_err(map_validation)?;
            }
            if let Some(descriptions) = &command.descriptions {
                validate_group_descriptions(descriptions).map_err(map_validation)?;
            }
            self.repository
                .update_group(UpdateGroupTransaction {
                    group_oid: command.group_oid,
                    name: command
                        .name
                        .as_deref()
                        .map(|text| validate_default_text(text, true))
                        .transpose()?,
                    description: command
                        .description
                        .as_deref()
                        .map(|text| validate_default_text(text, false))
                        .transpose()?,
                    names: command.names,
                    descriptions: command.descriptions,
                    expected_version: command.expected_version,
                    reason,
                    authority: authority.clone(),
                })
                .await
                .map_err(map_repository_error)
        }
        .await;
        self.emit_result("rbac.group.update", &result);
        result
    }

    #[tracing::instrument(skip_all, name = "rbac.group.enable")]
    pub async fn enable_group(
        &self,
        authority: &RbacManagementAuthority,
        command: GroupStateCommand,
    ) -> Result<GroupRecord, AppError> {
        self.set_group_enabled(authority, command, true).await
    }

    #[tracing::instrument(skip_all, name = "rbac.group.disable")]
    pub async fn disable_group(
        &self,
        authority: &RbacManagementAuthority,
        command: GroupStateCommand,
    ) -> Result<GroupRecord, AppError> {
        self.set_group_enabled(authority, command, false).await
    }

    async fn set_group_enabled(
        &self,
        authority: &RbacManagementAuthority,
        command: GroupStateCommand,
        enabled: bool,
    ) -> Result<GroupRecord, AppError> {
        let action = if enabled {
            "rbac.group.enable"
        } else {
            "rbac.group.disable"
        };
        let result = async {
            let reason = validate_reason(&command.reason)?;
            validate_client_mutation_id(command.client_mutation_id.as_deref())?;

            self.repository
                .set_group_enabled(
                    GroupStateTransaction {
                        group_oid: command.group_oid,
                        expected_version: command.expected_version,
                        reason,
                        authority: authority.clone(),
                    },
                    enabled,
                )
                .await
                .map_err(map_repository_error)
        }
        .await;
        self.emit_result(action, &result);
        result
    }

    #[tracing::instrument(skip_all, name = "rbac.group.delete")]
    pub async fn delete_group(
        &self,
        authority: &RbacManagementAuthority,
        command: DeleteGroupCommand,
    ) -> Result<DeleteGroupResult, AppError> {
        let result = async {
            let reason = validate_reason(&command.reason)?;
            validate_client_mutation_id(command.client_mutation_id.as_deref())?;

            self.repository
                .delete_group(DeleteGroupTransaction {
                    group_oid: command.group_oid,
                    expected_version: command.expected_version,
                    reason,
                    authority: authority.clone(),
                })
                .await
                .map_err(map_repository_error)
        }
        .await;
        self.emit_result("rbac.group.delete", &result);
        result
    }

    #[tracing::instrument(skip_all, name = "rbac.group.members.add")]
    pub async fn add_group_member(
        &self,
        authority: &RbacManagementAuthority,
        command: AddGroupMemberCommand,
    ) -> Result<GroupMembershipMutationResult, AppError> {
        let result = async {
            let reason = validate_reason(&command.reason)?;
            validate_client_mutation_id(command.client_mutation_id.as_deref())?;

            self.repository
                .add_group_member(AddGroupMemberTransaction {
                    group_oid: command.group_oid,
                    user_oid: command.user_oid,
                    expected_version: command.expected_version,
                    reason,
                    authority: authority.clone(),
                })
                .await
                .map_err(map_repository_error)
        }
        .await;
        self.emit_result("rbac.group.members.add", &result);
        result
    }

    #[tracing::instrument(skip_all, name = "rbac.group.members.remove")]
    pub async fn remove_group_member(
        &self,
        authority: &RbacManagementAuthority,
        command: RemoveGroupMemberCommand,
    ) -> Result<GroupMembershipMutationResult, AppError> {
        let result = async {
            let reason = validate_reason(&command.reason)?;
            validate_client_mutation_id(command.client_mutation_id.as_deref())?;

            self.repository
                .remove_group_member(RemoveGroupMemberTransaction {
                    group_oid: command.group_oid,
                    user_oid: command.user_oid,
                    expected_version: command.expected_version,
                    reason,
                    authority: authority.clone(),
                })
                .await
                .map_err(map_repository_error)
        }
        .await;
        self.emit_result("rbac.group.members.remove", &result);
        result
    }

    #[tracing::instrument(skip_all, name = "rbac.group.roles.set")]
    pub async fn set_group_roles(
        &self,
        authority: &RbacManagementAuthority,
        command: SetGroupRolesCommand,
    ) -> Result<GroupRoleMutationResult, AppError> {
        let result = async {
            let reason = validate_reason(&command.reason)?;
            validate_client_mutation_id(command.client_mutation_id.as_deref())?;

            let role_oids = dedupe_limit_roles(command.role_oids)?;
            self.repository
                .set_group_roles(SetGroupRolesTransaction {
                    group_oid: command.group_oid,
                    role_oids,
                    expected_version: command.expected_version,
                    reason,
                    authority: authority.clone(),
                })
                .await
                .map_err(map_repository_error)
        }
        .await;
        self.emit_result("rbac.group.roles.set", &result);
        result
    }

    fn emit_result<T>(&self, name: &'static str, result: &Result<T, AppError>) {
        let mut event = BusinessEvent::business(name);
        match result {
            Ok(_) => {
                event = event.outcome("success");
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

// ----------------------------------------------------------------------
// Validation and error mapping
// ----------------------------------------------------------------------

/// Normalize an optional audit annotation shared by every group management
/// mutation. Blank input becomes an empty reason; only over-long supplied text
/// is rejected.
fn validate_reason(reason: &str) -> Result<String, AppError> {
    rbac::validate_group_reason(reason).map_err(map_validation)
}

fn validate_client_mutation_id(value: Option<&str>) -> Result<(), AppError> {
    let Some(value) = value else {
        return Ok(());
    };
    if value.chars().count() > MAX_CLIENT_MUTATION_ID_LENGTH {
        return Err(AppError::from_code(GroupErrorCode::InvalidClientMutationId)
            .with_param("max", MAX_CLIENT_MUTATION_ID_LENGTH.to_string())
            .with_field("clientMutationId"));
    }
    Ok(())
}

fn normalize_group_filter(mut filter: GroupFilter) -> Result<GroupFilter, AppError> {
    filter.query = normalize_filter_text(filter.query, "query", MAX_QUERY_FILTER_LENGTH)?;
    Ok(filter)
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
        return Err(AppError::from_code(GroupErrorCode::InvalidFilter)
            .with_param("field", field)
            .with_param("max", max.to_string())
            .with_field(field));
    }
    Ok(Some(value.to_owned()))
}

fn dedupe_limit_roles(role_oids: Vec<RoleOid>) -> Result<Vec<RoleOid>, AppError> {
    if role_oids.len() > MAX_GROUP_ROLES {
        return Err(AppError::from_code(GroupErrorCode::InvalidCollectionSize)
            .with_param("max", MAX_GROUP_ROLES.to_string())
            .with_field("roleIds"));
    }
    Ok(role_oids
        .into_iter()
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect())
}

fn map_validation(error: GroupValidationError) -> AppError {
    use GroupValidationError as Error;
    match error {
        Error::InvalidName => AppError::from_code(GroupErrorCode::InvalidName)
            .with_param("max", "256")
            .with_field("names"),
        Error::InvalidDescription => AppError::from_code(GroupErrorCode::InvalidDescription)
            .with_param("max", "1024")
            .with_field("descriptions"),
        Error::InvalidLocale => AppError::from_code(GroupErrorCode::InvalidLocale)
            .with_param("max", "35")
            .with_field("names.locale"),
        Error::NameRequired => {
            AppError::from_code(GroupErrorCode::NameRequired).with_field("names")
        }
        Error::DuplicateLocale => {
            AppError::from_code(GroupErrorCode::DuplicateLocale).with_field("names")
        }
        Error::TooManyEntries => AppError::from_code(GroupErrorCode::InvalidCollectionSize)
            .with_param("max", "20")
            .with_field("names"),
        Error::InvalidReason => AppError::from_code(GroupErrorCode::InvalidReason)
            .with_param("max", MAX_GROUP_REASON_LENGTH.to_string())
            .with_field("reason"),
        Error::BuiltInDefinition => AppError::from_code(GroupErrorCode::BuiltInProtected),
    }
}

fn map_localized_error(error: LocalizedTextError) -> AppError {
    use LocalizedTextError as Error;
    match error {
        Error::InvalidLocale { .. } => AppError::from_code(GroupErrorCode::InvalidLocale)
            .with_param("max", "35")
            .with_field("names.locale"),
        Error::DuplicateLocale { locale } => AppError::from_code(GroupErrorCode::DuplicateLocale)
            .with_param("locale", locale)
            .with_field("names"),
        Error::EmptyName { .. } => {
            AppError::from_code(GroupErrorCode::InvalidName).with_field("names")
        }
        Error::TextTooLong { max, .. } => AppError::from_code(GroupErrorCode::InvalidName)
            .with_param("max", max.to_string())
            .with_field("names"),
        Error::TooManyEntries { field, max } => {
            AppError::from_code(GroupErrorCode::InvalidCollectionSize)
                .with_param("max", max.to_string())
                .with_field(field)
        }
    }
}

fn map_repository_error(error: GroupManagementRepositoryError) -> AppError {
    use GroupManagementRepositoryError as Error;
    match error {
        error @ Error::Storage(_) => {
            AppError::from_code(GroupErrorCode::StorageFailed).with_source(error)
        }
        Error::Authorization(source) => AppError::from(source),
        error @ Error::AuditFailed(_) => {
            AppError::from_code(AuthorizationErrorCode::AuditWriteFailed).with_source(error)
        }
        Error::LastRecoveryProtected => {
            AppError::from_code(AuthorizationErrorCode::LastOwnerProtected)
        }
        Error::CorruptRecord => AppError::from_code(GroupErrorCode::StorageFailed),
        Error::NotFound(kind) => AppError::from_code(not_found_code(kind)),
        Error::VersionConflict { current_version } => {
            AppError::from_code(GroupErrorCode::VersionConflict)
                .with_param("current_version", current_version.to_string())
                .with_field("expectedVersion")
        }
        Error::BuiltInProtected => AppError::from_code(GroupErrorCode::BuiltInProtected),
        Error::GroupDisabled => AppError::from_code(GroupErrorCode::Disabled),
        Error::RoleDisabled { role_oid } => AppError::from_code(GroupErrorCode::RoleDisabled)
            .with_param("role_id", role_oid.to_string())
            .with_field("roleIds"),
        Error::DelegationCeilingExceeded { scope } => {
            AppError::from_code(GroupErrorCode::DelegationCeilingExceeded)
                .with_param("scope", scope)
                .with_field("roleIds")
        }
        Error::MembershipAlreadyActive => {
            AppError::from_code(GroupErrorCode::MembershipAlreadyActive).with_field("userId")
        }
        Error::MembershipNotActive => {
            AppError::from_code(GroupErrorCode::MembershipNotActive).with_field("userId")
        }
        Error::InvalidMetadata { field } => {
            AppError::from_code(GroupErrorCode::InvalidMetadata).with_param("field", field)
        }
        Error::EmptyUpdate => AppError::from_code(GroupErrorCode::EmptyUpdate),
        Error::LimitExceeded { limit } => {
            AppError::from_code(GroupErrorCode::InvalidCollectionSize)
                .with_param("max", limit.to_string())
        }
    }
}

fn not_found_code(kind: GroupEntityKind) -> GroupErrorCode {
    match kind {
        GroupEntityKind::Group => GroupErrorCode::GroupNotFound,
        GroupEntityKind::Membership => GroupErrorCode::MembershipNotFound,
        GroupEntityKind::RoleBinding => GroupErrorCode::RoleBindingNotFound,
        GroupEntityKind::User => GroupErrorCode::UserNotFound,
        GroupEntityKind::Role => GroupErrorCode::RoleNotFound,
    }
}

fn validate_default_text(value: &str, name: bool) -> Result<String, AppError> {
    group::validate_group_default(value, name).map_err(|error| {
        map_validation(error).with_field(if name { "name" } else { "description" })
    })
}
