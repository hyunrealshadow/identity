use super::*;

impl RbacManagementService {
    #[tracing::instrument(skip_all, name = "rbac.role.count")]
    pub async fn count_roles(
        &self,
        filter: crate::rbac::role::RoleFilter,
    ) -> Result<u64, AppError> {
        self.repository
            .count_roles(normalize_role_filter(filter)?)
            .await
            .map_err(map_repository_error)
    }

    #[tracing::instrument(skip_all, name = "rbac.role.find")]
    pub async fn find_role(
        &self,
        oid: RoleOid,
    ) -> Result<Option<crate::rbac::role::RoleRecord>, AppError> {
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
    ) -> Result<crate::rbac::role::RoleRecord, AppError> {
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
    ) -> Result<crate::rbac::role::RoleRecord, AppError> {
        let result = async {
            let reason = validate_reason(&command.reason)?;
            validate_client_mutation_id(command.client_mutation_id.as_deref())?;

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
    ) -> Result<crate::rbac::role::RoleRecord, AppError> {
        self.set_role_enabled(authority, command, true).await
    }

    #[tracing::instrument(skip_all, name = "rbac.role.disable")]
    pub async fn disable_role(
        &self,
        authority: &RbacManagementAuthority,
        command: RoleStateCommand,
    ) -> Result<crate::rbac::role::RoleRecord, AppError> {
        self.set_role_enabled(authority, command, false).await
    }

    async fn set_role_enabled(
        &self,
        authority: &RbacManagementAuthority,
        command: RoleStateCommand,
        enabled: bool,
    ) -> Result<crate::rbac::role::RoleRecord, AppError> {
        let action = if enabled {
            "rbac.role.enable"
        } else {
            "rbac.role.disable"
        };
        let result = async {
            let reason = validate_reason(&command.reason)?;
            validate_client_mutation_id(command.client_mutation_id.as_deref())?;

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
    ) -> Result<crate::rbac::role::RoleRecord, AppError> {
        let result = async {
            let reason = validate_reason(&command.reason)?;
            validate_client_mutation_id(command.client_mutation_id.as_deref())?;

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
}
