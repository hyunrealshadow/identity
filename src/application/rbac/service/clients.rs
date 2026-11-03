use std::collections::BTreeSet;

use super::*;

use identity_domain::client::model::ClientOid;

impl RbacManagementService {
    #[tracing::instrument(skip_all, name = "rbac.client_scope.count")]
    pub async fn count_client_scopes(&self, client_oid: ClientOid) -> Result<u64, AppError> {
        self.repository
            .count_client_scopes(client_oid)
            .await
            .map_err(map_repository_error)
    }

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

            if command.scope_oids.len() > MAX_SCOPE_ASSIGNMENTS {
                return Err(AppError::from_code(RbacErrorCode::InvalidCollectionSize)
                    .with_param("max", MAX_SCOPE_ASSIGNMENTS.to_string())
                    .with_field("scopeIds"));
            }
            let scope_oids = command
                .scope_oids
                .into_iter()
                .collect::<BTreeSet<_>>()
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
}
