//! Unified RBAC management use cases.
//!
//! Entry Guards establish that the caller held a management scope when the
//! request started. Every write passes immutable request authority to the
//! repository, which re-loads authoritative state and re-evaluates policy
//! inside the mutation transaction.

use std::{collections::BTreeSet, sync::Arc};

use super::model::MAX_SCOPE_ASSIGNMENTS;

use identity_domain::{
    rbac,
    rbac::{
        LocalizedMetadata, LocalizedText, LocalizedTextError, PermissionCode, RbacValidationError,
        ResourceOid, RoleOid, boundary::BusinessScopeBoundaryError,
    },
    user::UserOid,
};

use crate::{
    data_protection::DataProtector,
    error::{
        AppError,
        codes::{authorization::AuthorizationErrorCode, rbac::RbacErrorCode},
    },
    observability::{BusinessEvent, EventSink, EventValue, NoopEventSink, error_outcome},
    rbac::{
        client::{ClientScopePageRequest, ClientScopeSetResult, SetClientScopesCommand},
        cursor::{
            CURSOR_KIND_CLIENT_SCOPE, CURSOR_KIND_EFFECTIVE, CURSOR_KIND_RESOURCE,
            CURSOR_KIND_ROLE, CURSOR_KIND_SCOPE, CURSOR_KIND_USER_ROLE, PageArguments,
            encode_cursor, prepare_page,
        },
        model::{
            MAX_BATCH_LOOKUPS, MAX_CLIENT_MUTATION_ID_LENGTH, MAX_DESCRIPTION_LENGTH,
            MAX_DESCRIPTION_LOCALES, MAX_DISPLAY_NAME_LENGTH, MAX_QUERY_FILTER_LENGTH,
            MAX_REASON_LENGTH, MAX_ROLE_PERMISSIONS, MAX_USER_ROLES, RbacManagementAuthority,
            ScopeDescription, ScopeOid,
        },
        repository::{
            AssignUserRolesTransaction, ClientScopeQuery, CreateResourceTransaction,
            CreateRoleTransaction, CreateScopeTransaction, EffectivePermissionQuery,
            RbacDuplicateKind, RbacEntityKind, RbacManagementRepository,
            RbacManagementRepositoryError, RbacProtectedKind, ResourceQuery,
            ResourceStateTransaction, RevokeUserRolesTransaction, RoleQuery, RoleStateTransaction,
            ScopeQuery, ScopeStateTransaction, SetClientScopesTransaction,
            SetRolePermissionsTransaction, UpdateResourceTransaction, UpdateRoleTransaction,
            UpdateScopeTransaction, UserRoleQuery,
        },
        resource::{
            ApiResourceRecord, CreateResourceCommand, ResourceFilter, ResourcePage,
            ResourcePageItem, ResourcePageRequest, ResourceStateCommand, UpdateResourceCommand,
        },
        role::{
            CreateRoleCommand, RoleFilter, RolePage, RolePageItem, RolePageRequest,
            RoleStateCommand, SetRolePermissionsCommand, UpdateRoleCommand,
        },
        scope::{
            CreateScopeCommand, ScopeFilter, ScopePage, ScopePageItem, ScopePageRequest,
            ScopeStateCommand, UpdateScopeCommand,
        },
        user_role::{
            AssignUserRolesCommand, EffectivePermissionPage, EffectivePermissionPageItem,
            EffectivePermissionPageRequest, RevokeUserRolesCommand, RoleUserPageRequest,
            UserRoleMutationResult, UserRoleOrder, UserRolePage, UserRolePageItem,
            UserRolePageRequest,
        },
    },
};

mod clients;
mod resources;
mod roles;
mod scopes;
mod user_roles;

pub struct RbacManagementService {
    repository: Arc<dyn RbacManagementRepository>,
    data_protector: Arc<dyn DataProtector>,
    events: Arc<dyn EventSink>,
}

impl RbacManagementService {
    #[must_use]
    pub fn new(
        repository: Arc<dyn RbacManagementRepository>,
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

    fn emit_result<T>(
        &self,
        name: &'static str,
        result: &Result<T, AppError>,
        target_key: &'static str,
    ) {
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
        let _ = target_key;
        self.events.emit(event);
    }
}

// ----------------------------------------------------------------------
// Validation and mapping
// ----------------------------------------------------------------------

/// Normalize an optional audit annotation shared by every RBAC management
/// mutation. Blank input becomes an empty reason; only over-long supplied text
/// is rejected.
fn validate_reason(reason: &str) -> Result<String, AppError> {
    let reason = reason.trim();
    if reason.chars().count() > MAX_REASON_LENGTH {
        return Err(AppError::from_code(RbacErrorCode::InvalidReason)
            .with_param("min", "0")
            .with_param("max", MAX_REASON_LENGTH.to_string())
            .with_field("reason"));
    }
    Ok(reason.to_owned())
}

fn validate_client_mutation_id(value: Option<&str>) -> Result<(), AppError> {
    let Some(value) = value else {
        return Ok(());
    };
    if value.chars().count() > MAX_CLIENT_MUTATION_ID_LENGTH {
        return Err(AppError::from_code(RbacErrorCode::InvalidClientMutationId)
            .with_param("max", MAX_CLIENT_MUTATION_ID_LENGTH.to_string())
            .with_field("clientMutationId"));
    }
    Ok(())
}

fn validate_resource_name(value: &str) -> Result<String, AppError> {
    let value = value.trim();
    if value.is_empty() || value.chars().count() > MAX_DISPLAY_NAME_LENGTH {
        return Err(AppError::from_code(RbacErrorCode::InvalidResourceName)
            .with_param("max", MAX_DISPLAY_NAME_LENGTH.to_string())
            .with_field("name"));
    }
    Ok(value.to_owned())
}

fn validate_scope_name(value: &str) -> Result<String, AppError> {
    let value = value.trim();
    if value.is_empty() || value.chars().count() > MAX_DISPLAY_NAME_LENGTH {
        return Err(AppError::from_code(RbacErrorCode::InvalidScopeDescription)
            .with_param("max", MAX_DISPLAY_NAME_LENGTH.to_string())
            .with_field("name"));
    }
    Ok(value.to_owned())
}

fn validate_scope_names(names: Vec<ScopeDescription>) -> Result<Vec<ScopeDescription>, AppError> {
    if names.len() > MAX_DESCRIPTION_LOCALES {
        return Err(AppError::from_code(RbacErrorCode::InvalidCollectionSize)
            .with_param("max", MAX_DESCRIPTION_LOCALES.to_string())
            .with_field("names"));
    }
    let mut seen = BTreeSet::new();
    let mut result = Vec::with_capacity(names.len());
    for name in names {
        let locale = rbac::canonicalize_locale(&name.locale).map_err(|_| {
            AppError::from_code(RbacErrorCode::InvalidDescriptionLocale)
                .with_param("max", "35")
                .with_field("names.locale")
        })?;
        if !seen.insert(locale.clone()) {
            return Err(AppError::from_code(RbacErrorCode::InvalidLocalizedMetadata)
                .with_param("locale", locale)
                .with_field("names.locale"));
        }
        let value = name.value.trim();
        if value.is_empty() {
            return Err(AppError::from_code(RbacErrorCode::InvalidLocalizedMetadata)
                .with_param("field", "names")
                .with_field("names.value"));
        }
        if value.chars().count() > MAX_DISPLAY_NAME_LENGTH {
            return Err(AppError::from_code(RbacErrorCode::InvalidScopeDescription)
                .with_param("max", MAX_DISPLAY_NAME_LENGTH.to_string())
                .with_field("names.value"));
        }
        result.push(ScopeDescription {
            locale,
            value: value.to_owned(),
        });
    }
    Ok(result)
}

fn validate_scope_description(value: &str, field: &'static str) -> Result<String, AppError> {
    validate_bounded_description(value, field, RbacErrorCode::InvalidScopeDescription)
}

fn validate_role_description(value: &str) -> Result<String, AppError> {
    let value = value.trim();
    if value.chars().count() > MAX_DESCRIPTION_LENGTH {
        return Err(
            AppError::from_code(RbacErrorCode::ValidationFailed).with_param("field", "description")
        );
    }
    Ok(value.to_owned())
}

/// Canonicalize an optional names replacement; an empty list clears translations.
fn canonicalize_role_names(names: Vec<LocalizedText>) -> Result<Vec<LocalizedText>, AppError> {
    LocalizedMetadata::canonicalize_names(names).map_err(map_localized_metadata_error)
}

/// Canonicalize a supplied descriptions patch independently from names.
fn canonicalize_role_descriptions(
    descriptions: Vec<LocalizedText>,
) -> Result<Vec<LocalizedText>, AppError> {
    LocalizedMetadata::canonicalize_descriptions(descriptions).map_err(map_localized_metadata_error)
}

fn validate_bounded_description(
    value: &str,
    field: &'static str,
    code: RbacErrorCode,
) -> Result<String, AppError> {
    let value = value.trim();
    if value.chars().count() > MAX_DESCRIPTION_LENGTH {
        return Err(AppError::from_code(code)
            .with_param("max", MAX_DESCRIPTION_LENGTH.to_string())
            .with_field(field));
    }
    Ok(value.to_owned())
}

fn validate_descriptions(
    descriptions: Vec<ScopeDescription>,
) -> Result<Vec<ScopeDescription>, AppError> {
    if descriptions.len() > MAX_DESCRIPTION_LOCALES {
        return Err(AppError::from_code(RbacErrorCode::InvalidCollectionSize)
            .with_param("max", MAX_DESCRIPTION_LOCALES.to_string())
            .with_field("descriptions"));
    }
    let mut result = Vec::with_capacity(descriptions.len());
    for description in descriptions {
        let locale = rbac::canonicalize_locale(&description.locale).map_err(|_| {
            AppError::from_code(RbacErrorCode::InvalidDescriptionLocale)
                .with_param("max", "35")
                .with_field("descriptions.locale")
        })?;
        let value = validate_scope_description(&description.value, "descriptions.value")?;
        result.push(ScopeDescription { locale, value });
    }
    Ok(result)
}

fn validate_role_name(value: &str) -> Result<String, AppError> {
    let value = value.trim();
    if value.is_empty() || value.chars().count() > MAX_DISPLAY_NAME_LENGTH {
        return Err(AppError::from_code(RbacErrorCode::InvalidRoleName)
            .with_param("max", MAX_DISPLAY_NAME_LENGTH.to_string())
            .with_field("name"));
    }
    Ok(value.to_owned())
}

fn validate_new_scope_code(value: &str) -> Result<String, AppError> {
    let value = value.trim();
    if let Err(error) = rbac::validate_business_scope_reference(value) {
        return Err(map_business_scope_error(error, "code"));
    }
    // The same row is later projected as a ResourcePermission, whose machine
    // identity is PermissionCode. Reject general OAuth tokens here instead of
    // persisting rows that would make role/permission projection fail later.
    let code = PermissionCode::parse(value).map_err(permission_code_error)?;
    Ok(code.as_str().to_owned())
}

fn dedupe_limit_roles(role_oids: Vec<RoleOid>) -> Result<Vec<RoleOid>, AppError> {
    if role_oids.is_empty() {
        return Err(AppError::from_code(RbacErrorCode::ValidationFailed)
            .with_param("field", "roleIds")
            .with_field("roleIds"));
    }
    if role_oids.len() > MAX_USER_ROLES {
        return Err(AppError::from_code(RbacErrorCode::UserRoleLimitExceeded)
            .with_param("max", MAX_USER_ROLES.to_string())
            .with_field("roleIds"));
    }
    Ok(role_oids
        .into_iter()
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect())
}

fn normalize_resource_filter(mut filter: ResourceFilter) -> Result<ResourceFilter, AppError> {
    filter.query = normalize_filter_text(filter.query, "query", MAX_QUERY_FILTER_LENGTH)?;
    Ok(filter)
}

fn normalize_scope_filter(mut filter: ScopeFilter) -> Result<ScopeFilter, AppError> {
    filter.query = normalize_filter_text(filter.query, "query", MAX_QUERY_FILTER_LENGTH)?;
    Ok(filter)
}

fn normalize_role_filter(mut filter: RoleFilter) -> Result<RoleFilter, AppError> {
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
        return Err(AppError::from_code(RbacErrorCode::InvalidFilter)
            .with_param("field", field)
            .with_param("max", max.to_string())
            .with_field(field));
    }
    Ok(Some(value.to_owned()))
}

fn map_localized_metadata_error(error: LocalizedTextError) -> AppError {
    use identity_domain::rbac::LocalizedTextError as Error;
    match error {
        Error::InvalidLocale { locale } => {
            AppError::from_code(RbacErrorCode::InvalidLocalizedMetadata)
                .with_param("locale", locale)
                .with_param("field", "locale")
        }
        Error::DuplicateLocale { locale } => {
            AppError::from_code(RbacErrorCode::InvalidLocalizedMetadata)
                .with_param("locale", locale)
                .with_param("field", "locale")
        }
        Error::EmptyName { locale } => AppError::from_code(RbacErrorCode::InvalidLocalizedMetadata)
            .with_param("locale", locale)
            .with_param("field", "names"),
        Error::TextTooLong { locale, max } => {
            AppError::from_code(RbacErrorCode::InvalidLocalizedMetadata)
                .with_param("locale", locale)
                .with_param("max", max.to_string())
                .with_param("field", "value")
        }
        Error::TooManyEntries { field, max } => {
            AppError::from_code(RbacErrorCode::InvalidLocalizedMetadata)
                .with_param("field", field)
                .with_param("max", max.to_string())
        }
    }
}

fn map_business_scope_error(error: BusinessScopeBoundaryError, field: &'static str) -> AppError {
    use identity_domain::rbac::boundary::BusinessScopeBoundaryError as Error;
    match error {
        Error::ManagementScopeReserved => {
            AppError::from_code(AuthorizationErrorCode::ReservedManagementScope)
                .with_param("scope", "management")
                .with_field(field)
        }
        Error::StandardOidcScope(scope) => {
            AppError::from_code(AuthorizationErrorCode::BusinessScopeBoundaryViolation)
                .with_param("scope", scope)
                .with_param("reason_code", "standard_oidc")
                .with_field(field)
        }
        Error::SelfServiceScope(scope) => {
            AppError::from_code(AuthorizationErrorCode::BusinessScopeBoundaryViolation)
                .with_param("scope", scope)
                .with_param("reason_code", "self_service")
                .with_field(field)
        }
        Error::InvalidScopeToken => AppError::from_code(RbacErrorCode::InvalidScopeName)
            .with_param("name", "scope")
            .with_field(field),
    }
}

fn permission_code_error(error: RbacValidationError) -> AppError {
    match error {
        RbacValidationError::InvalidPermissionCode => {
            AppError::from_code(RbacErrorCode::InvalidPermissionCode)
                .with_param("max", "128")
                .with_field("code")
        }
        other => AppError::from_code(RbacErrorCode::ValidationFailed)
            .with_field_error("code", AppError::from_code(RbacErrorCode::ValidationFailed))
            .with_source(other),
    }
}

fn map_delegation_error(error: RbacManagementRepositoryError, field: &'static str) -> AppError {
    match error {
        RbacManagementRepositoryError::DelegationCeilingExceeded { permission } => {
            AppError::from_code(RbacErrorCode::DelegationCeilingExceeded)
                .with_param("permission", permission)
                .with_field(field)
        }
        other => map_repository_error(other),
    }
}

fn map_repository_error(error: RbacManagementRepositoryError) -> AppError {
    use RbacManagementRepositoryError as Error;
    match error {
        error @ Error::Storage(_) => {
            AppError::from_code(RbacErrorCode::StorageFailed).with_source(error)
        }
        Error::Authorization(source) => AppError::from(source),
        Error::LastRecoverableAdministrator => {
            AppError::from_code(AuthorizationErrorCode::LastOwnerProtected)
        }
        error @ Error::AuditFailed(_) => {
            AppError::from_code(AuthorizationErrorCode::AuditWriteFailed).with_source(error)
        }
        Error::CorruptRecord => AppError::from_code(RbacErrorCode::StorageFailed),
        Error::NotFound(kind) => AppError::from_code(not_found_code(kind)),
        Error::VersionConflict { current_version } => {
            AppError::from_code(RbacErrorCode::VersionConflict)
                .with_param("current_version", current_version.to_string())
                .with_field("expectedVersion")
        }
        Error::UserVersionStale { current_version } => {
            AppError::from_code(RbacErrorCode::UserVersionStale)
                .with_param("current_version", current_version.to_string())
                .with_field("expectedUserVersion")
        }
        Error::PolicyVersionStale { current_version } => {
            AppError::from_code(RbacErrorCode::PolicyVersionStale)
                .with_param("current_version", current_version.to_string())
                .with_field("expectedVersion")
        }
        Error::Duplicate(kind) => duplicate_error(kind),
        Error::Protected(kind) => protected_error(kind),
        Error::ScopeNotBusiness { scope } => {
            AppError::from_code(AuthorizationErrorCode::BusinessScopeBoundaryViolation)
                .with_param("scope", scope)
                .with_param("reason_code", "not_business")
                .with_field("scopeIds")
        }
        Error::ClientGrantNotAllowed { scope } => {
            // The field path names the rejected scope so the form can mark it.
            let field = format!("scopes.{scope}");
            AppError::from_code(RbacErrorCode::ClientGrantNotAllowed)
                .with_param("scope", scope)
                .with_field(field)
        }
        Error::InvalidPermissionCode { code } => {
            AppError::from_code(RbacErrorCode::InvalidPermissionCode)
                .with_param("code", code)
                .with_field("code")
        }
        Error::LimitExceeded { limit } => AppError::from_code(RbacErrorCode::InvalidCollectionSize)
            .with_param("max", limit.to_string()),
        Error::RoleDisabled { role_oid } => AppError::from_code(RbacErrorCode::RoleDisabled)
            .with_param("role_id", role_oid.to_string())
            .with_field("roleIds"),
        Error::RoleNotAssigned { role_oid } => AppError::from_code(RbacErrorCode::RoleNotAssigned)
            .with_param("role_id", role_oid.to_string())
            .with_field("roleIds"),
        Error::EmptyUpdate => AppError::from_code(RbacErrorCode::EmptyUpdate),
        Error::BuiltInIdentityConflict => {
            AppError::from_code(RbacErrorCode::BuiltInIdentityConflict)
        }
        Error::DelegationCeilingExceeded { permission } => {
            AppError::from_code(RbacErrorCode::DelegationCeilingExceeded)
                .with_param("permission", permission)
                .with_field("permissionIds")
        }
        Error::InvalidBuiltInPermissionReference { permission } => {
            AppError::from_code(RbacErrorCode::InvalidBuiltInPermissionReference)
                .with_param("permission", permission)
                .with_field("permissionIds")
        }
    }
}

fn not_found_code(kind: RbacEntityKind) -> RbacErrorCode {
    match kind {
        RbacEntityKind::Resource => RbacErrorCode::ResourceNotFound,
        RbacEntityKind::Scope => RbacErrorCode::ScopeNotFound,
        RbacEntityKind::Role => RbacErrorCode::RoleNotFound,
        RbacEntityKind::Binding => RbacErrorCode::BindingNotFound,
        RbacEntityKind::User => RbacErrorCode::UserNotFound,
        RbacEntityKind::Client => RbacErrorCode::ClientNotFound,
    }
}

fn duplicate_error(kind: RbacDuplicateKind) -> AppError {
    match kind {
        RbacDuplicateKind::ResourceUri => {
            AppError::from_code(RbacErrorCode::DuplicateResourceUri).with_field("uri")
        }
        RbacDuplicateKind::ScopeCode => {
            AppError::from_code(RbacErrorCode::DuplicateScopeCode).with_field("code")
        }
    }
}

fn protected_error(kind: RbacProtectedKind) -> AppError {
    match kind {
        RbacProtectedKind::ReservedResource => {
            AppError::from_code(RbacErrorCode::ReservedResourceProtected)
        }
        RbacProtectedKind::BuiltInScope => {
            AppError::from_code(RbacErrorCode::BuiltInScopeProtected)
        }
        RbacProtectedKind::BuiltInClient => AppError::from_code(RbacErrorCode::ClientProtected),
        RbacProtectedKind::BuiltInRole => {
            AppError::from_code(RbacErrorCode::BuiltInDefinitionProtected)
                .with_param("kind", "role")
        }
        RbacProtectedKind::BuiltInGroup => {
            AppError::from_code(RbacErrorCode::BuiltInDefinitionProtected)
                .with_param("kind", "group")
        }
    }
}
