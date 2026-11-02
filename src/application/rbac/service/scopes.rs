use super::*;

impl RbacManagementService {
    #[tracing::instrument(skip_all, name = "rbac.scope.find")]
    pub async fn find_scope(
        &self,
        oid: ScopeOid,
    ) -> Result<Option<crate::rbac::scope::ScopeRecord>, AppError> {
        self.repository
            .find_scope(oid)
            .await
            .map_err(map_repository_error)
    }

    #[tracing::instrument(skip_all, name = "rbac.scope.count")]
    pub async fn count_scopes(
        &self,
        filter: crate::rbac::scope::ScopeFilter,
    ) -> Result<u64, AppError> {
        self.repository
            .count_scopes(normalize_scope_filter(filter)?)
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
    ) -> Result<crate::rbac::scope::ScopeRecord, AppError> {
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
    ) -> Result<crate::rbac::scope::ScopeRecord, AppError> {
        let result = async {
            let reason = validate_reason(&command.reason)?;
            validate_client_mutation_id(command.client_mutation_id.as_deref())?;

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
    ) -> Result<crate::rbac::scope::ScopeRecord, AppError> {
        self.set_scope_enabled(authority, command, true).await
    }

    #[tracing::instrument(skip_all, name = "rbac.scope.disable")]
    pub async fn disable_scope(
        &self,
        authority: &RbacManagementAuthority,
        command: ScopeStateCommand,
    ) -> Result<crate::rbac::scope::ScopeRecord, AppError> {
        self.set_scope_enabled(authority, command, false).await
    }

    async fn set_scope_enabled(
        &self,
        authority: &RbacManagementAuthority,
        command: ScopeStateCommand,
        enabled: bool,
    ) -> Result<crate::rbac::scope::ScopeRecord, AppError> {
        let action = if enabled {
            "rbac.scope.enable"
        } else {
            "rbac.scope.disable"
        };
        let result = async {
            let reason = validate_reason(&command.reason)?;
            validate_client_mutation_id(command.client_mutation_id.as_deref())?;

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
}
