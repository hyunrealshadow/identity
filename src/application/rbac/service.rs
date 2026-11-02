//! Unified RBAC management use cases.
//!
//! Entry Guards establish that the caller held a management scope when the
//! request started. Every write passes immutable request authority to the
//! repository, which re-loads authoritative state and re-evaluates policy
//! inside the mutation transaction.

use std::sync::Arc;

use super::model::MAX_SCOPE_ASSIGNMENTS;

use identity_domain::{
    rbac::{PermissionCode, RbacValidationError, ResourceOid, RoleOid, UserRoleBindingOid},
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
        binding::{
            AssignUserRolesCommand, EffectivePermissionPage, EffectivePermissionPageItem,
            EffectivePermissionPageRequest, RevokeUserRolesCommand, RoleUserPageRequest,
            UserRoleBindingMutationResult, UserRoleBindingOrder, UserRoleBindingPage,
            UserRoleBindingPageItem, UserRoleBindingRecord, UserRolePageRequest,
        },
        client::{
            ClientScopePageRequest, ClientScopeSetResult, ClientScopeTargetFilter,
            ClientScopeTargetPage, ClientScopeTargetPageItem, ClientScopeTargetPageRequest,
            SetClientScopesCommand,
        },
        cursor::{
            CURSOR_KIND_BINDING, CURSOR_KIND_CLIENT_SCOPE, CURSOR_KIND_CLIENT_TARGET,
            CURSOR_KIND_EFFECTIVE, CURSOR_KIND_RESOURCE, CURSOR_KIND_ROLE, CURSOR_KIND_SCOPE,
            encode_cursor, prepare_page,
        },
        model::{
            MAX_BINDING_LOOKUPS, MAX_CLIENT_MUTATION_ID_LENGTH, MAX_DESCRIPTION_LENGTH,
            MAX_DESCRIPTION_LOCALES, MAX_DISPLAY_NAME_LENGTH, MAX_QUERY_FILTER_LENGTH,
            MAX_REASON_LENGTH, MAX_ROLE_PERMISSIONS, MAX_USER_ROLES, RbacManagementAuthority,
            ScopeDescription, ScopeOid,
        },
        repository::{
            AssignUserRolesTransaction, ClientScopeQuery, ClientScopeTargetQuery,
            CreateResourceTransaction, CreateRoleTransaction, CreateScopeTransaction,
            EffectivePermissionQuery, RbacDuplicateKind, RbacEntityKind, RbacManagementRepository,
            RbacManagementRepositoryError, RbacProtectedKind, ResourceQuery,
            ResourceStateTransaction, RevokeUserRolesTransaction, RoleQuery, RoleStateTransaction,
            ScopeQuery, ScopeStateTransaction, SetClientScopesTransaction,
            SetRolePermissionsTransaction, UpdateResourceTransaction, UpdateRoleTransaction,
            UpdateScopeTransaction, UserRoleBindingQuery,
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
    },
};

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

    // ------------------------------------------------------------------
    // Resource reads
    // ------------------------------------------------------------------

    #[tracing::instrument(skip_all, name = "rbac.resource.find")]
    pub async fn find_resource(
        &self,
        oid: ResourceOid,
    ) -> Result<Option<ApiResourceRecord>, AppError> {
        self.repository
            .find_resource(oid)
            .await
            .map_err(map_repository_error)
    }

    #[tracing::instrument(skip_all, name = "rbac.resource.list")]
    pub async fn list_resources(
        &self,
        request: ResourcePageRequest,
    ) -> Result<ResourcePage, AppError> {
        let filter = normalize_resource_filter(request.filter)?;
        let order = request.order;
        let prepared = prepare_page(
            self.data_protector.as_ref(),
            CURSOR_KIND_RESOURCE,
            order.as_u8(),
            &filter,
            request.first,
            request.after,
            request.last,
            request.before,
        )
        .await?;
        let data = self
            .repository
            .list_resources(ResourceQuery {
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
                CURSOR_KIND_RESOURCE,
                order.as_u8(),
                &prepared.filter_fingerprint,
                &entry.sort_key,
            )
            .await?;
            items.push(ResourcePageItem {
                record: entry.record,
                cursor,
            });
        }
        Ok(ResourcePage {
            items,
            has_previous_page: data.has_previous_page,
            has_next_page: data.has_next_page,
        })
    }

    // ------------------------------------------------------------------
    // Resource writes
    // ------------------------------------------------------------------

    #[tracing::instrument(skip_all, name = "rbac.resource.create")]
    pub async fn create_resource(
        &self,
        authority: &RbacManagementAuthority,
        command: CreateResourceCommand,
    ) -> Result<ApiResourceRecord, AppError> {
        let result = async {
            let reason = validate_reason(&command.reason)?;
            validate_client_mutation_id(command.client_mutation_id.as_deref())?;
            let uri = command.uri.trim().to_owned();
            if !identity_domain::openid_connect::resource::valid_resource_uri(&uri) {
                return Err(AppError::from_code(RbacErrorCode::InvalidResourceUri)
                    .with_param("uri", uri)
                    .with_field("uri"));
            }
            if uri == identity_domain::openid_connect::API_RESOURCE {
                return Err(
                    AppError::from_code(RbacErrorCode::ReservedResourceProtected)
                        .with_param("resource", uri)
                        .with_field("uri"),
                );
            }
            let name = validate_resource_name(&command.name)?;
            let resource_oid = ResourceOid::new();
            let record = self
                .repository
                .create_resource(CreateResourceTransaction {
                    resource_oid,
                    uri,
                    name,
                    reason,
                    authority: authority.clone(),
                })
                .await
                .map_err(map_repository_error)?;
            Ok(record)
        }
        .await;
        self.emit_result("rbac.resource.create", &result, "resource_oid");
        result
    }

    #[tracing::instrument(skip_all, name = "rbac.resource.update")]
    pub async fn update_resource(
        &self,
        authority: &RbacManagementAuthority,
        command: UpdateResourceCommand,
    ) -> Result<ApiResourceRecord, AppError> {
        let result = async {
            let reason = validate_reason(&command.reason)?;
            validate_client_mutation_id(command.client_mutation_id.as_deref())?;
            validate_expected_version(command.expected_version)?;
            let name = command
                .name
                .as_deref()
                .map(validate_resource_name)
                .transpose()?;
            if name.is_none() {
                return Err(AppError::from_code(RbacErrorCode::EmptyUpdate));
            }
            let record = self
                .repository
                .update_resource(UpdateResourceTransaction {
                    resource_oid: command.resource_oid,
                    name,
                    expected_version: command.expected_version,
                    reason,
                    authority: authority.clone(),
                })
                .await
                .map_err(map_repository_error)?;
            Ok(record)
        }
        .await;
        self.emit_result("rbac.resource.update", &result, "resource_oid");
        result
    }

    #[tracing::instrument(skip_all, name = "rbac.resource.enable")]
    pub async fn enable_resource(
        &self,
        authority: &RbacManagementAuthority,
        command: ResourceStateCommand,
    ) -> Result<ApiResourceRecord, AppError> {
        self.set_resource_enabled(authority, command, true).await
    }

    #[tracing::instrument(skip_all, name = "rbac.resource.disable")]
    pub async fn disable_resource(
        &self,
        authority: &RbacManagementAuthority,
        command: ResourceStateCommand,
    ) -> Result<ApiResourceRecord, AppError> {
        self.set_resource_enabled(authority, command, false).await
    }

    async fn set_resource_enabled(
        &self,
        authority: &RbacManagementAuthority,
        command: ResourceStateCommand,
        enabled: bool,
    ) -> Result<ApiResourceRecord, AppError> {
        let action = if enabled {
            "rbac.resource.enable"
        } else {
            "rbac.resource.disable"
        };
        let result = async {
            let reason = validate_reason(&command.reason)?;
            validate_client_mutation_id(command.client_mutation_id.as_deref())?;
            validate_expected_version(command.expected_version)?;
            let record = self
                .repository
                .set_resource_enabled(
                    ResourceStateTransaction {
                        resource_oid: command.resource_oid,
                        expected_version: command.expected_version,
                        reason,
                        authority: authority.clone(),
                    },
                    enabled,
                )
                .await
                .map_err(|error| map_delegation_error(error, "id"))?;
            Ok(record)
        }
        .await;
        self.emit_result(action, &result, "resource_oid");
        result
    }

    // ------------------------------------------------------------------
    // Scope reads and writes
    // ------------------------------------------------------------------

    #[tracing::instrument(skip_all, name = "rbac.scope.find")]
    pub async fn find_scope(
        &self,
        oid: ScopeOid,
    ) -> Result<Option<super::scope::ScopeRecord>, AppError> {
        self.repository
            .find_scope(oid)
            .await
            .map_err(map_repository_error)
    }

    #[tracing::instrument(skip_all, name = "rbac.scope.count")]
    pub async fn count_scopes(&self, filter: super::scope::ScopeFilter) -> Result<u64, AppError> {
        self.repository
            .count_scopes(normalize_scope_filter(filter)?)
            .await
            .map_err(map_repository_error)
    }

    #[tracing::instrument(skip_all, name = "rbac.role.count")]
    pub async fn count_roles(&self, filter: super::role::RoleFilter) -> Result<u64, AppError> {
        self.repository
            .count_roles(normalize_role_filter(filter)?)
            .await
            .map_err(map_repository_error)
    }

    #[tracing::instrument(skip_all, name = "rbac.client_scope.count")]
    pub async fn count_client_scopes(
        &self,
        client_oid: identity_domain::client::model::ClientOid,
    ) -> Result<u64, AppError> {
        self.repository
            .count_client_scopes(client_oid)
            .await
            .map_err(map_repository_error)
    }

    #[tracing::instrument(skip_all, name = "rbac.scope.list")]
    pub async fn list_scopes(&self, request: ScopePageRequest) -> Result<ScopePage, AppError> {
        let filter = normalize_scope_filter(request.filter)?;
        let order = request.order;
        let prepared = prepare_page(
            self.data_protector.as_ref(),
            CURSOR_KIND_SCOPE,
            order.as_u8(),
            &filter,
            request.first,
            request.after,
            request.last,
            request.before,
        )
        .await?;
        let data = self
            .repository
            .list_scopes(ScopeQuery {
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
                CURSOR_KIND_SCOPE,
                order.as_u8(),
                &prepared.filter_fingerprint,
                &entry.sort_key,
            )
            .await?;
            items.push(ScopePageItem {
                record: entry.record,
                cursor,
            });
        }
        Ok(ScopePage {
            items,
            has_previous_page: data.has_previous_page,
            has_next_page: data.has_next_page,
        })
    }

    #[tracing::instrument(skip_all, name = "rbac.scope.create")]
    pub async fn create_scope(
        &self,
        authority: &RbacManagementAuthority,
        command: CreateScopeCommand,
    ) -> Result<super::scope::ScopeRecord, AppError> {
        let result = async {
            let reason = validate_reason(&command.reason)?;
            validate_client_mutation_id(command.client_mutation_id.as_deref())?;
            let code = validate_new_scope_code(&command.code)?;
            let name = validate_scope_name(&command.name)?;
            let names = validate_scope_names(command.names)?;
            let description = validate_scope_description(&command.description, "description")?;
            let descriptions = validate_descriptions(command.descriptions)?;
            let record = self
                .repository
                .create_scope(CreateScopeTransaction {
                    scope_oid: ScopeOid::new(),
                    resource_oid: command.resource_oid,
                    code,
                    name,
                    names,
                    description,
                    descriptions,
                    reason,
                    authority: authority.clone(),
                })
                .await
                .map_err(map_repository_error)?;
            Ok(record)
        }
        .await;
        self.emit_result("rbac.scope.create", &result, "scope_oid");
        result
    }

    #[tracing::instrument(skip_all, name = "rbac.scope.update")]
    pub async fn update_scope(
        &self,
        authority: &RbacManagementAuthority,
        command: UpdateScopeCommand,
    ) -> Result<super::scope::ScopeRecord, AppError> {
        let result = async {
            let reason = validate_reason(&command.reason)?;
            validate_client_mutation_id(command.client_mutation_id.as_deref())?;
            validate_expected_version(command.expected_version)?;
            if command.name.is_none()
                && command.names.is_none()
                && command.description.is_none()
                && command.descriptions.is_none()
            {
                return Err(AppError::from_code(RbacErrorCode::EmptyUpdate));
            }
            let name = command
                .name
                .as_deref()
                .map(validate_scope_name)
                .transpose()?;
            let names = command.names.map(validate_scope_names).transpose()?;
            let description = command
                .description
                .as_deref()
                .map(|value| validate_scope_description(value, "description"))
                .transpose()?;
            let descriptions = command
                .descriptions
                .map(validate_descriptions)
                .transpose()?;
            let record = self
                .repository
                .update_scope(UpdateScopeTransaction {
                    scope_oid: command.scope_oid,
                    name,
                    names,
                    description,
                    descriptions,
                    expected_version: command.expected_version,
                    reason,
                    authority: authority.clone(),
                })
                .await
                .map_err(map_repository_error)?;
            Ok(record)
        }
        .await;
        self.emit_result("rbac.scope.update", &result, "scope_oid");
        result
    }

    #[tracing::instrument(skip_all, name = "rbac.scope.enable")]
    pub async fn enable_scope(
        &self,
        authority: &RbacManagementAuthority,
        command: ScopeStateCommand,
    ) -> Result<super::scope::ScopeRecord, AppError> {
        self.set_scope_enabled(authority, command, true).await
    }

    #[tracing::instrument(skip_all, name = "rbac.scope.disable")]
    pub async fn disable_scope(
        &self,
        authority: &RbacManagementAuthority,
        command: ScopeStateCommand,
    ) -> Result<super::scope::ScopeRecord, AppError> {
        self.set_scope_enabled(authority, command, false).await
    }

    async fn set_scope_enabled(
        &self,
        authority: &RbacManagementAuthority,
        command: ScopeStateCommand,
        enabled: bool,
    ) -> Result<super::scope::ScopeRecord, AppError> {
        let action = if enabled {
            "rbac.scope.enable"
        } else {
            "rbac.scope.disable"
        };
        let result = async {
            let reason = validate_reason(&command.reason)?;
            validate_client_mutation_id(command.client_mutation_id.as_deref())?;
            validate_expected_version(command.expected_version)?;
            let record = self
                .repository
                .set_scope_enabled(
                    ScopeStateTransaction {
                        scope_oid: command.scope_oid,
                        expected_version: command.expected_version,
                        reason,
                        authority: authority.clone(),
                    },
                    enabled,
                )
                .await
                .map_err(|error| map_delegation_error(error, "id"))?;
            Ok(record)
        }
        .await;
        self.emit_result(action, &result, "scope_oid");
        result
    }

    // ------------------------------------------------------------------
    // Role reads and writes
    // ------------------------------------------------------------------

    #[tracing::instrument(skip_all, name = "rbac.role.find")]
    pub async fn find_role(
        &self,
        oid: RoleOid,
    ) -> Result<Option<super::role::RoleRecord>, AppError> {
        self.repository
            .find_role(oid)
            .await
            .map_err(map_repository_error)
    }

    #[tracing::instrument(skip_all, name = "rbac.role.list")]
    pub async fn list_roles(&self, request: RolePageRequest) -> Result<RolePage, AppError> {
        let filter = normalize_role_filter(request.filter)?;
        let order = request.order;
        let prepared = prepare_page(
            self.data_protector.as_ref(),
            CURSOR_KIND_ROLE,
            order.as_u8(),
            &filter,
            request.first,
            request.after,
            request.last,
            request.before,
        )
        .await?;
        let data = self
            .repository
            .list_roles(RoleQuery {
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
                CURSOR_KIND_ROLE,
                order.as_u8(),
                &prepared.filter_fingerprint,
                &entry.sort_key,
            )
            .await?;
            items.push(RolePageItem {
                record: entry.record,
                cursor,
            });
        }
        Ok(RolePage {
            items,
            has_previous_page: data.has_previous_page,
            has_next_page: data.has_next_page,
        })
    }

    #[tracing::instrument(skip_all, name = "rbac.role.create")]
    pub async fn create_role(
        &self,
        authority: &RbacManagementAuthority,
        command: CreateRoleCommand,
    ) -> Result<super::role::RoleRecord, AppError> {
        let result = async {
            let reason = validate_reason(&command.reason)?;
            validate_client_mutation_id(command.client_mutation_id.as_deref())?;
            let metadata = match command.metadata {
                Some(metadata) => identity_domain::rbac::LocalizedMetadata::canonicalize(
                    metadata.names,
                    metadata.descriptions,
                )
                .map_err(map_localized_metadata_error)?,
                None => identity_domain::rbac::LocalizedMetadata::default(),
            };
            let name = validate_role_name(&command.name)?;
            let description = validate_role_description(&command.description)?;
            let record = self
                .repository
                .create_role(CreateRoleTransaction {
                    role_oid: RoleOid::new(),
                    name,
                    description,
                    metadata,
                    reason,
                    authority: authority.clone(),
                })
                .await
                .map_err(map_repository_error)?;
            Ok(record)
        }
        .await;
        self.emit_result("rbac.role.create", &result, "role_oid");
        result
    }

    #[tracing::instrument(skip_all, name = "rbac.role.update")]
    pub async fn update_role(
        &self,
        authority: &RbacManagementAuthority,
        command: UpdateRoleCommand,
    ) -> Result<super::role::RoleRecord, AppError> {
        let result = async {
            let reason = validate_reason(&command.reason)?;
            validate_client_mutation_id(command.client_mutation_id.as_deref())?;
            validate_expected_version(command.expected_version)?;
            if command.name.is_none()
                && command.description.is_none()
                && command.names.is_none()
                && command.descriptions.is_none()
            {
                return Err(AppError::from_code(RbacErrorCode::EmptyUpdate));
            }
            let names = command.names.map(canonicalize_role_names).transpose()?;
            let descriptions = command
                .descriptions
                .map(canonicalize_role_descriptions)
                .transpose()?;
            let record = self
                .repository
                .update_role(UpdateRoleTransaction {
                    role_oid: command.role_oid,
                    name: command
                        .name
                        .as_deref()
                        .map(validate_role_name)
                        .transpose()?,
                    description: command
                        .description
                        .as_deref()
                        .map(validate_role_description)
                        .transpose()?,
                    names,
                    descriptions,
                    expected_version: command.expected_version,
                    reason,
                    authority: authority.clone(),
                })
                .await
                .map_err(map_repository_error)?;
            Ok(record)
        }
        .await;
        self.emit_result("rbac.role.update", &result, "role_oid");
        result
    }

    #[tracing::instrument(skip_all, name = "rbac.role.enable")]
    pub async fn enable_role(
        &self,
        authority: &RbacManagementAuthority,
        command: RoleStateCommand,
    ) -> Result<super::role::RoleRecord, AppError> {
        self.set_role_enabled(authority, command, true).await
    }

    #[tracing::instrument(skip_all, name = "rbac.role.disable")]
    pub async fn disable_role(
        &self,
        authority: &RbacManagementAuthority,
        command: RoleStateCommand,
    ) -> Result<super::role::RoleRecord, AppError> {
        self.set_role_enabled(authority, command, false).await
    }

    async fn set_role_enabled(
        &self,
        authority: &RbacManagementAuthority,
        command: RoleStateCommand,
        enabled: bool,
    ) -> Result<super::role::RoleRecord, AppError> {
        let action = if enabled {
            "rbac.role.enable"
        } else {
            "rbac.role.disable"
        };
        let result = async {
            let reason = validate_reason(&command.reason)?;
            validate_client_mutation_id(command.client_mutation_id.as_deref())?;
            validate_expected_version(command.expected_version)?;
            let record = self
                .repository
                .set_role_enabled(
                    RoleStateTransaction {
                        role_oid: command.role_oid,
                        expected_version: command.expected_version,
                        reason,
                        authority: authority.clone(),
                    },
                    enabled,
                )
                .await
                .map_err(map_repository_error)?;
            Ok(record)
        }
        .await;
        self.emit_result(action, &result, "role_oid");
        result
    }

    #[tracing::instrument(skip_all, name = "rbac.role.permissions.set")]
    pub async fn set_role_permissions(
        &self,
        authority: &RbacManagementAuthority,
        command: SetRolePermissionsCommand,
    ) -> Result<super::role::RoleRecord, AppError> {
        let result = async {
            let reason = validate_reason(&command.reason)?;
            validate_client_mutation_id(command.client_mutation_id.as_deref())?;
            validate_expected_version(command.expected_version)?;
            if command.scope_oids.len() > MAX_ROLE_PERMISSIONS {
                return Err(
                    AppError::from_code(RbacErrorCode::RolePermissionLimitExceeded)
                        .with_param("max", MAX_ROLE_PERMISSIONS.to_string())
                        .with_field("permissionIds"),
                );
            }
            let scope_oids = command
                .scope_oids
                .into_iter()
                .collect::<std::collections::BTreeSet<_>>()
                .into_iter()
                .collect::<Vec<_>>();
            let record = self
                .repository
                .set_role_permissions(SetRolePermissionsTransaction {
                    role_oid: command.role_oid,
                    scope_oids,
                    expected_version: command.expected_version,
                    reason,
                    authority: authority.clone(),
                })
                .await
                .map_err(map_repository_error)?;
            Ok(record)
        }
        .await;
        self.emit_result("rbac.role.permissions.set", &result, "role_oid");
        result
    }

    // ------------------------------------------------------------------
    // Binding reads
    // ------------------------------------------------------------------

    #[tracing::instrument(skip_all, name = "rbac.user_roles.list")]
    pub async fn list_user_roles(
        &self,
        request: UserRolePageRequest,
    ) -> Result<UserRoleBindingPage, AppError> {
        let user_oid = request.user_oid;
        // The repository returns the page rows and the live generation from one
        // REPEATABLE READ snapshot. `userRoles` therefore has the generation
        // even when the binding list is empty, without a second query that
        // could observe a newer generation than the cursor page.
        self.list_bindings(
            Some(user_oid),
            None,
            request.enabled,
            request.order,
            request.first,
            request.after,
            request.last,
            request.before,
        )
        .await
    }

    #[tracing::instrument(skip_all, name = "rbac.role_users.list")]
    pub async fn list_role_users(
        &self,
        request: RoleUserPageRequest,
    ) -> Result<UserRoleBindingPage, AppError> {
        let role_oid = request.role_oid;
        self.list_bindings(
            None,
            Some(role_oid),
            request.enabled,
            request.order,
            request.first,
            request.after,
            request.last,
            request.before,
        )
        .await
    }

    /// Expand server-produced binding IDs for a guarded mutation payload.
    ///
    /// This is deliberately not a search endpoint: the caller can only pass
    /// IDs returned by a successful mutation, and the lookup is bounded.
    #[tracing::instrument(skip_all, name = "rbac.user_role_bindings.find_many")]
    pub async fn find_user_role_bindings(
        &self,
        binding_oids: Vec<UserRoleBindingOid>,
    ) -> Result<Vec<UserRoleBindingRecord>, AppError> {
        let binding_oids = binding_oids
            .into_iter()
            .collect::<std::collections::BTreeSet<_>>()
            .into_iter()
            .collect::<Vec<_>>();
        if binding_oids.len() > MAX_BINDING_LOOKUPS {
            return Err(AppError::from_code(RbacErrorCode::InvalidCollectionSize)
                .with_param("max", MAX_BINDING_LOOKUPS.to_string())
                .with_field("bindingIds"));
        }
        self.repository
            .find_user_role_bindings(binding_oids)
            .await
            .map_err(map_repository_error)
    }

    #[allow(clippy::too_many_arguments)]
    async fn list_bindings(
        &self,
        user_oid: Option<UserOid>,
        role_oid: Option<RoleOid>,
        enabled: Option<bool>,
        order: UserRoleBindingOrder,
        first: Option<u32>,
        after: Option<String>,
        last: Option<u32>,
        before: Option<String>,
    ) -> Result<UserRoleBindingPage, AppError> {
        let fingerprint_input = (user_oid, role_oid, enabled);
        let prepared = prepare_page(
            self.data_protector.as_ref(),
            CURSOR_KIND_BINDING,
            order.as_u8(),
            &fingerprint_input,
            first,
            after,
            last,
            before,
        )
        .await?;
        let data = self
            .repository
            .list_user_role_bindings(UserRoleBindingQuery {
                user_oid,
                role_oid,
                enabled,
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
                CURSOR_KIND_BINDING,
                order.as_u8(),
                &prepared.filter_fingerprint,
                &entry.sort_key,
            )
            .await?;
            items.push(UserRoleBindingPageItem {
                record: entry.record,
                cursor,
            });
        }
        Ok(UserRoleBindingPage {
            items,
            has_previous_page: data.has_previous_page,
            has_next_page: data.has_next_page,
            user_version: data.user_version,
        })
    }

    #[tracing::instrument(skip_all, name = "rbac.effective_permissions.count")]
    pub async fn count_user_permissions(
        &self,
        user_oid: UserOid,
        resource_oid: ResourceOid,
    ) -> Result<u64, AppError> {
        self.repository
            .count_effective_permissions(user_oid, resource_oid)
            .await
            .map_err(map_repository_error)
    }

    #[tracing::instrument(skip_all, name = "rbac.effective_permissions.list")]
    pub async fn list_user_permissions(
        &self,
        request: EffectivePermissionPageRequest,
    ) -> Result<EffectivePermissionPage, AppError> {
        let order = request.order;
        let fingerprint_input = (request.user_oid, request.resource_oid);
        let prepared = prepare_page(
            self.data_protector.as_ref(),
            CURSOR_KIND_EFFECTIVE,
            order.as_u8(),
            &fingerprint_input,
            request.first,
            request.after,
            request.last,
            request.before,
        )
        .await?;
        let data = self
            .repository
            .list_effective_permissions(EffectivePermissionQuery {
                user_oid: request.user_oid,
                resource_oid: request.resource_oid,
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
                CURSOR_KIND_EFFECTIVE,
                order.as_u8(),
                &prepared.filter_fingerprint,
                &entry.sort_key,
            )
            .await?;
            items.push(EffectivePermissionPageItem {
                record: entry.record,
                cursor,
            });
        }
        Ok(EffectivePermissionPage {
            items,
            has_previous_page: data.has_previous_page,
            has_next_page: data.has_next_page,
            user_version: data.user_version,
        })
    }

    // ------------------------------------------------------------------
    // Binding writes
    // ------------------------------------------------------------------

    #[tracing::instrument(skip_all, name = "rbac.user_roles.assign")]
    pub async fn assign_user_roles(
        &self,
        authority: &RbacManagementAuthority,
        command: AssignUserRolesCommand,
    ) -> Result<UserRoleBindingMutationResult, AppError> {
        let result = async {
            let reason = validate_reason(&command.reason)?;
            validate_client_mutation_id(command.client_mutation_id.as_deref())?;
            let role_oids = dedupe_limit_roles(command.role_oids)?;
            let result = self
                .repository
                .assign_user_roles(AssignUserRolesTransaction {
                    user_oid: command.user_oid,
                    role_oids,
                    expected_user_version: command.expected_user_version,
                    reason,
                    authority: authority.clone(),
                })
                .await
                .map_err(map_repository_error)?;
            Ok(result)
        }
        .await;
        self.emit_result("rbac.user_roles.assign", &result, "user_oid");
        result
    }

    #[tracing::instrument(skip_all, name = "rbac.user_roles.revoke")]
    pub async fn revoke_user_roles(
        &self,
        authority: &RbacManagementAuthority,
        command: RevokeUserRolesCommand,
    ) -> Result<UserRoleBindingMutationResult, AppError> {
        let result = async {
            let reason = validate_reason(&command.reason)?;
            validate_client_mutation_id(command.client_mutation_id.as_deref())?;
            let role_oids = dedupe_limit_roles(command.role_oids)?;
            let result = self
                .repository
                .revoke_user_roles(RevokeUserRolesTransaction {
                    user_oid: command.user_oid,
                    role_oids,
                    expected_user_version: command.expected_user_version,
                    reason,
                    authority: authority.clone(),
                })
                .await
                .map_err(map_repository_error)?;
            Ok(result)
        }
        .await;
        self.emit_result("rbac.user_roles.revoke", &result, "user_oid");
        result
    }

    // ------------------------------------------------------------------
    // Narrow client delegation
    // ------------------------------------------------------------------

    #[tracing::instrument(skip_all, name = "rbac.client_scope_targets.list")]
    pub async fn list_client_scope_targets(
        &self,
        request: ClientScopeTargetPageRequest,
    ) -> Result<ClientScopeTargetPage, AppError> {
        let filter = normalize_client_target_filter(request.filter)?;
        let order = request.order;
        let prepared = prepare_page(
            self.data_protector.as_ref(),
            CURSOR_KIND_CLIENT_TARGET,
            order.as_u8(),
            &filter,
            request.first,
            request.after,
            request.last,
            request.before,
        )
        .await?;
        let data = self
            .repository
            .list_client_scope_targets(ClientScopeTargetQuery {
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
                CURSOR_KIND_CLIENT_TARGET,
                order.as_u8(),
                &prepared.filter_fingerprint,
                &entry.sort_key,
            )
            .await?;
            items.push(ClientScopeTargetPageItem {
                record: entry.record,
                cursor,
            });
        }
        Ok(ClientScopeTargetPage {
            items,
            has_previous_page: data.has_previous_page,
            has_next_page: data.has_next_page,
        })
    }

    #[tracing::instrument(skip_all, name = "rbac.client_scopes.list")]
    pub async fn list_client_scopes(
        &self,
        request: ClientScopePageRequest,
    ) -> Result<ScopePage, AppError> {
        let order = request.order;
        let fingerprint_input = (request.client_oid,);
        let prepared = prepare_page(
            self.data_protector.as_ref(),
            CURSOR_KIND_CLIENT_SCOPE,
            order.as_u8(),
            &fingerprint_input,
            request.first,
            request.after,
            request.last,
            request.before,
        )
        .await?;
        let data = self
            .repository
            .list_client_scopes(ClientScopeQuery {
                client_oid: request.client_oid,
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
                CURSOR_KIND_CLIENT_SCOPE,
                order.as_u8(),
                &prepared.filter_fingerprint,
                &entry.sort_key,
            )
            .await?;
            items.push(ScopePageItem {
                record: entry.record,
                cursor,
            });
        }
        Ok(ScopePage {
            items,
            has_previous_page: data.has_previous_page,
            has_next_page: data.has_next_page,
        })
    }

    #[tracing::instrument(skip_all, name = "rbac.client_scopes.set")]
    pub async fn set_client_scopes(
        &self,
        authority: &RbacManagementAuthority,
        command: SetClientScopesCommand,
    ) -> Result<ClientScopeSetResult, AppError> {
        let result = async {
            let reason = validate_reason(&command.reason)?;
            validate_client_mutation_id(command.client_mutation_id.as_deref())?;
            validate_expected_version(command.expected_version)?;
            if command.scope_oids.len() > MAX_SCOPE_ASSIGNMENTS {
                return Err(AppError::from_code(RbacErrorCode::InvalidCollectionSize)
                    .with_param("max", MAX_SCOPE_ASSIGNMENTS.to_string())
                    .with_field("scopeIds"));
            }
            let scope_oids = command
                .scope_oids
                .into_iter()
                .collect::<std::collections::BTreeSet<_>>()
                .into_iter()
                .collect::<Vec<_>>();
            let result = self
                .repository
                .set_client_scopes(SetClientScopesTransaction {
                    client_oid: command.client_oid,
                    scope_oids,
                    expected_version: command.expected_version,
                    reason,
                    authority: authority.clone(),
                })
                .await
                .map_err(|error| map_delegation_error(error, "scopeIds"))?;
            Ok(result)
        }
        .await;
        self.emit_result("rbac.client_scopes.set", &result, "client_oid");
        result
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

fn validate_expected_version(_value: uuid::Uuid) -> Result<(), AppError> {
    // UUID scalar parsing already rejects malformed values at the API boundary.
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
    let mut seen = std::collections::BTreeSet::new();
    let mut result = Vec::with_capacity(names.len());
    for name in names {
        let locale = identity_domain::rbac::canonicalize_locale(&name.locale).map_err(|_| {
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
fn canonicalize_role_names(
    names: Vec<identity_domain::rbac::LocalizedText>,
) -> Result<Vec<identity_domain::rbac::LocalizedText>, AppError> {
    identity_domain::rbac::LocalizedMetadata::canonicalize_names(names)
        .map_err(map_localized_metadata_error)
}

/// Canonicalize a supplied descriptions patch independently from names.
fn canonicalize_role_descriptions(
    descriptions: Vec<identity_domain::rbac::LocalizedText>,
) -> Result<Vec<identity_domain::rbac::LocalizedText>, AppError> {
    identity_domain::rbac::LocalizedMetadata::canonicalize_descriptions(descriptions)
        .map_err(map_localized_metadata_error)
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
        let locale =
            identity_domain::rbac::canonicalize_locale(&description.locale).map_err(|_| {
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
    if let Err(error) = identity_domain::rbac::validate_business_scope_reference(value) {
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
        .collect::<std::collections::BTreeSet<_>>()
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

fn normalize_client_target_filter(
    mut filter: ClientScopeTargetFilter,
) -> Result<ClientScopeTargetFilter, AppError> {
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

fn map_localized_metadata_error(error: identity_domain::rbac::LocalizedTextError) -> AppError {
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

fn map_business_scope_error(
    error: identity_domain::rbac::boundary::BusinessScopeBoundaryError,
    field: &'static str,
) -> AppError {
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
