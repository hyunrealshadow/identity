use super::*;

impl RbacManagementService {
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
}
