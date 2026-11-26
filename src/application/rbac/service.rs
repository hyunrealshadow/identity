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
        codes::{authorization, rbac as rbac_codes},
    },
    observability::{BusinessEvent, EventSink, EventValue, NoopEventSink, error_outcome},
    rbac::{
        client::{ClientScopePageRequest, ClientScopeSetResult, SetClientScopesCommand},
        cursor::{
            CURSOR_KIND_ACCOUNT_PERMISSION, CURSOR_KIND_ACCOUNT_ROLE, CURSOR_KIND_CLIENT_SCOPE,
            CURSOR_KIND_EFFECTIVE, CURSOR_KIND_RESOURCE, CURSOR_KIND_ROLE, CURSOR_KIND_SCOPE,
            CURSOR_KIND_USER_ROLE, CURSOR_KIND_USER_ROLE_GRANT, PageArguments, encode_cursors,
            prepare_page,
        },
        model::{
            MAX_CLIENT_MUTATION_ID_LENGTH, MAX_DESCRIPTION_LENGTH, MAX_DESCRIPTION_LOCALES,
            MAX_DISPLAY_NAME_LENGTH, MAX_QUERY_FILTER_LENGTH, MAX_REASON_LENGTH,
            MAX_ROLE_PERMISSIONS, MAX_USER_ROLES, RbacManagementAuthority, ScopeDescription,
            ScopeOid, dedupe_batch_lookups,
        },
        repository::{
            AccountPermissionQuery, AccountRoleQuery, AssignUserRolesTransaction, ClientScopeQuery,
            CreateResourceTransaction, CreateRoleTransaction, CreateScopeTransaction,
            EffectivePermissionQuery, RbacDuplicateKind, RbacEntityKind, RbacManagementRepository,
            RbacManagementRepositoryError, RbacProtectedKind, ResourceQuery,
            ResourceStateTransaction, RevokeUserRolesTransaction, RoleQuery, RoleStateTransaction,
            ScopeQuery, ScopeStateTransaction, SetClientScopesTransaction,
            SetRolePermissionsTransaction, UpdateResourceTransaction, UpdateRoleTransaction,
            UpdateScopeTransaction, UserRoleGrantQuery, UserRoleQuery,
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
            AccountPermissionPage, AccountPermissionPageItem, AccountPermissionPageRequest,
            AccountRolePage, AccountRolePageItem, AccountRolePageRequest, AssignUserRolesCommand,
            AuthorizationSource, EffectivePermissionPage, EffectivePermissionPageItem,
            EffectivePermissionPageRequest, RevokeUserRolesCommand, RoleUserPageRequest,
            UserRoleGrantPage, UserRoleGrantPageItem, UserRoleMutationResult, UserRoleOrder,
            UserRolePage, UserRolePageItem, UserRolePageRequest,
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
        return Err(rbac_codes::error::InvalidReason::new()
            .min(0)
            .max(MAX_REASON_LENGTH)
            .with_field("reason"));
    }
    Ok(reason.to_owned())
}

fn validate_client_mutation_id(value: Option<&str>) -> Result<(), AppError> {
    let Some(value) = value else {
        return Ok(());
    };
    if value.chars().count() > MAX_CLIENT_MUTATION_ID_LENGTH {
        return Err(
            rbac_codes::error::InvalidClientMutationId::new(MAX_CLIENT_MUTATION_ID_LENGTH)
                .with_field("client_mutation_id"),
        );
    }
    Ok(())
}

fn validate_resource_name(value: &str) -> Result<String, AppError> {
    let value = value.trim();
    if value.is_empty() || value.chars().count() > MAX_DISPLAY_NAME_LENGTH {
        return Err(rbac_codes::error::InvalidResourceName::new()
            .max(MAX_DISPLAY_NAME_LENGTH)
            .with_field("name"));
    }
    Ok(value.to_owned())
}

fn validate_scope_name(value: &str) -> Result<String, AppError> {
    let value = value.trim();
    if value.is_empty() || value.chars().count() > MAX_DISPLAY_NAME_LENGTH {
        return Err(rbac_codes::error::InvalidScopeDescription::new()
            .max(MAX_DISPLAY_NAME_LENGTH)
            .with_field("name"));
    }
    Ok(value.to_owned())
}

fn validate_scope_names(names: Vec<ScopeDescription>) -> Result<Vec<ScopeDescription>, AppError> {
    if names.len() > MAX_DESCRIPTION_LOCALES {
        return Err(
            rbac_codes::error::InvalidCollectionSize::new(MAX_DESCRIPTION_LOCALES)
                .with_field("names"),
        );
    }
    let mut seen = BTreeSet::new();
    let mut result = Vec::with_capacity(names.len());
    for name in names {
        let locale = rbac::canonicalize_locale(&name.locale).map_err(|_| {
            rbac_codes::error::InvalidDescriptionLocale::new()
                .max(35)
                .with_field("names.locale")
        })?;
        if !seen.insert(locale.clone()) {
            return Err(rbac_codes::error::InvalidLocalizedMetadata::new()
                .locale(locale)
                .with_field("names.locale"));
        }
        let value = name.value.trim();
        if value.is_empty() {
            return Err(rbac_codes::error::InvalidLocalizedMetadata::new()
                .field("names")
                .with_field("names.value"));
        }
        if value.chars().count() > MAX_DISPLAY_NAME_LENGTH {
            return Err(rbac_codes::error::InvalidScopeDescription::new()
                .max(MAX_DISPLAY_NAME_LENGTH)
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
    let value = value.trim();
    if value.chars().count() > MAX_DESCRIPTION_LENGTH {
        return Err(rbac_codes::error::InvalidScopeDescription::new()
            .max(MAX_DESCRIPTION_LENGTH)
            .with_field(field));
    }
    Ok(value.to_owned())
}

fn validate_role_description(value: &str) -> Result<String, AppError> {
    let value = value.trim();
    if value.chars().count() > MAX_DESCRIPTION_LENGTH {
        return Err(rbac_codes::error::ValidationFailed::new().with_field("description"));
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

fn validate_descriptions(
    descriptions: Vec<ScopeDescription>,
) -> Result<Vec<ScopeDescription>, AppError> {
    if descriptions.len() > MAX_DESCRIPTION_LOCALES {
        return Err(
            rbac_codes::error::InvalidCollectionSize::new(MAX_DESCRIPTION_LOCALES)
                .with_field("descriptions"),
        );
    }
    let mut result = Vec::with_capacity(descriptions.len());
    for description in descriptions {
        let locale = rbac::canonicalize_locale(&description.locale).map_err(|_| {
            rbac_codes::error::InvalidDescriptionLocale::new()
                .max(35)
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
        return Err(rbac_codes::error::InvalidRoleName::new()
            .max(MAX_DISPLAY_NAME_LENGTH)
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
        return Err(rbac_codes::error::ValidationFailed::new()
            .field("role_ids")
            .with_field("role_ids"));
    }
    if role_oids.len() > MAX_USER_ROLES {
        return Err(
            rbac_codes::error::UserRoleLimitExceeded::new(MAX_USER_ROLES).with_field("role_ids"),
        );
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
        return Err(rbac_codes::error::InvalidFilter::new(field)
            .max(max.to_string())
            .with_field(field));
    }
    Ok(Some(value.to_owned()))
}

fn map_localized_metadata_error(error: LocalizedTextError) -> AppError {
    use identity_domain::rbac::LocalizedTextError as Error;
    match error {
        Error::InvalidLocale { locale } => rbac_codes::error::InvalidLocalizedMetadata::new()
            .locale(locale)
            .field("locale")
            .into(),
        Error::DuplicateLocale { locale } => rbac_codes::error::InvalidLocalizedMetadata::new()
            .locale(locale)
            .field("locale")
            .into(),
        Error::EmptyName { locale } => rbac_codes::error::InvalidLocalizedMetadata::new()
            .locale(locale)
            .field("names")
            .into(),
        Error::TextTooLong { locale, max } => rbac_codes::error::InvalidLocalizedMetadata::new()
            .locale(locale)
            .max(max.to_string())
            .field("value")
            .into(),
        Error::TooManyEntries { field, max } => rbac_codes::error::InvalidLocalizedMetadata::new()
            .field(field)
            .max(max.to_string())
            .into(),
    }
}

fn map_business_scope_error(error: BusinessScopeBoundaryError, field: &'static str) -> AppError {
    use identity_domain::rbac::boundary::BusinessScopeBoundaryError as Error;
    match error {
        Error::ManagementScopeReserved => {
            authorization::error::ReservedManagementScope::new("management").with_field(field)
        }
        Error::StandardOidcScope(scope) => {
            authorization::error::BusinessScopeBoundaryViolation::new(scope)
                .reason_code("standard_oidc")
                .with_field(field)
        }
        Error::SelfServiceScope(scope) => {
            authorization::error::BusinessScopeBoundaryViolation::new(scope)
                .reason_code("self_service")
                .with_field(field)
        }
        Error::InvalidScopeToken => rbac_codes::error::InvalidScopeName::new()
            .name("scope")
            .with_field(field),
    }
}

fn permission_code_error(error: RbacValidationError) -> AppError {
    match error {
        RbacValidationError::InvalidPermissionCode => {
            rbac_codes::error::InvalidPermissionCode::new()
                .max("128")
                .with_field("code")
        }
        other => rbac_codes::error::ValidationFailed::new()
            .with_field_error("code", rbac_codes::error::ValidationFailed::new())
            .with_source(other),
    }
}

fn map_delegation_error(error: RbacManagementRepositoryError, field: &'static str) -> AppError {
    match error {
        RbacManagementRepositoryError::DelegationCeilingExceeded { permission } => {
            rbac_codes::error::DelegationCeilingExceeded::new()
                .permission(permission)
                .with_field(field)
        }
        other => map_repository_error(other),
    }
}

fn map_repository_error(error: RbacManagementRepositoryError) -> AppError {
    use RbacManagementRepositoryError as Error;
    match error {
        error @ Error::Storage(_) => rbac_codes::error::StorageFailed::new().with_source(error),
        Error::Authorization(source) => AppError::from(source),
        Error::LastRecoverableAdministrator => {
            authorization::error::LastOwnerProtected::new().into()
        }
        error @ Error::AuditFailed(_) => {
            authorization::error::AuditWriteFailed::new().with_source(error)
        }
        Error::CorruptRecord => rbac_codes::error::StorageFailed::new().into(),
        Error::NotFound(kind) => not_found_error(kind),
        Error::VersionConflict { current_version } => {
            rbac_codes::error::VersionConflict::new(current_version.to_string())
                .with_field("expected_version")
        }
        Error::UserVersionStale { current_version } => {
            rbac_codes::error::UserVersionStale::new(current_version.to_string())
                .with_field("expected_user_version")
        }
        Error::PolicyVersionStale { current_version } => {
            rbac_codes::error::PolicyVersionStale::new(current_version.to_string())
                .with_field("expected_version")
        }
        Error::Duplicate(kind) => duplicate_error(kind),
        Error::Protected(kind) => protected_error(kind),
        Error::ScopeNotBusiness { scope } => {
            authorization::error::BusinessScopeBoundaryViolation::new(scope)
                .reason_code("not_business")
                .with_field("scope_ids")
        }
        Error::ClientGrantNotAllowed { scope } => {
            // The field path names the rejected scope so the form can mark it.
            let field = format!("scopes.{scope}");
            rbac_codes::error::ClientGrantNotAllowed::new(scope).with_field(field)
        }
        Error::InvalidPermissionCode { .. } => {
            rbac_codes::error::InvalidPermissionCode::new().with_field("code")
        }
        Error::LimitExceeded { limit } => {
            rbac_codes::error::InvalidCollectionSize::new(limit.to_string()).into()
        }
        Error::RoleDisabled { role_oid } => rbac_codes::error::RoleDisabled::new()
            .role_id(role_oid.to_string())
            .with_field("role_ids"),
        Error::RoleNotAssigned { role_oid } => rbac_codes::error::RoleNotAssigned::new()
            .role_id(role_oid.to_string())
            .with_field("role_ids"),
        Error::EmptyUpdate => rbac_codes::error::EmptyUpdate::new().into(),
        Error::BuiltInIdentityConflict => rbac_codes::error::BuiltInIdentityConflict::new().into(),
        Error::DelegationCeilingExceeded { permission } => {
            rbac_codes::error::DelegationCeilingExceeded::new()
                .permission(permission)
                .with_field("permission_ids")
        }
        Error::InvalidBuiltInPermissionReference { permission } => {
            rbac_codes::error::InvalidBuiltInPermissionReference::new()
                .permission(permission)
                .with_field("permission_ids")
        }
    }
}

fn not_found_error(kind: RbacEntityKind) -> AppError {
    match kind {
        RbacEntityKind::Resource => rbac_codes::error::ResourceNotFound::new().into(),
        RbacEntityKind::Scope => rbac_codes::error::ScopeNotFound::new().into(),
        RbacEntityKind::Role => rbac_codes::error::RoleNotFound::new().into(),
        RbacEntityKind::Binding => rbac_codes::error::BindingNotFound::new().into(),
        RbacEntityKind::User => rbac_codes::error::UserNotFound::new().into(),
        RbacEntityKind::Client => rbac_codes::error::ClientNotFound::new().into(),
    }
}

fn duplicate_error(kind: RbacDuplicateKind) -> AppError {
    match kind {
        RbacDuplicateKind::ResourceUri => {
            rbac_codes::error::DuplicateResourceUri::new().with_field("uri")
        }
        RbacDuplicateKind::ScopeCode => {
            rbac_codes::error::DuplicateScopeCode::new().with_field("code")
        }
    }
}

fn protected_error(kind: RbacProtectedKind) -> AppError {
    match kind {
        RbacProtectedKind::ReservedResource => {
            rbac_codes::error::ReservedResourceProtected::new().into()
        }
        RbacProtectedKind::BuiltInScope => rbac_codes::error::BuiltInScopeProtected::new().into(),
        RbacProtectedKind::BuiltInClient => rbac_codes::error::ClientProtected::new().into(),
        RbacProtectedKind::BuiltInRole => rbac_codes::error::BuiltInDefinitionProtected::new()
            .kind("role")
            .into(),
        RbacProtectedKind::BuiltInGroup => rbac_codes::error::BuiltInDefinitionProtected::new()
            .kind("group")
            .into(),
    }
}
