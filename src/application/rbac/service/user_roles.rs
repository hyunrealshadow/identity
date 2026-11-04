use std::collections::BTreeSet;

use super::*;

use crate::rbac::role::RoleRecord;

impl RbacManagementService {
    #[tracing::instrument(skip_all, name = "rbac.user_roles.list")]
    pub async fn list_user_roles(
        &self,
        request: UserRolePageRequest,
    ) -> Result<UserRolePage, AppError> {
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
    ) -> Result<UserRolePage, AppError> {
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

    /// Roles referenced by one page of relation edges.
    #[tracing::instrument(skip_all, name = "rbac.role.find_many")]
    pub async fn find_roles(&self, oids: Vec<RoleOid>) -> Result<Vec<RoleRecord>, AppError> {
        let oids = dedupe_batch(oids)?;
        self.repository
            .find_roles(oids)
            .await
            .map_err(map_repository_error)
    }

    #[allow(clippy::too_many_arguments)]
    async fn list_bindings(
        &self,
        user_oid: Option<UserOid>,
        role_oid: Option<RoleOid>,
        enabled: Option<bool>,
        order: UserRoleOrder,
        first: Option<u32>,
        after: Option<String>,
        last: Option<u32>,
        before: Option<String>,
    ) -> Result<UserRolePage, AppError> {
        let fingerprint_input = (user_oid, role_oid, enabled);
        let prepared = prepare_page(
            self.data_protector.as_ref(),
            CURSOR_KIND_USER_ROLE,
            order.as_u8(),
            &fingerprint_input,
            PageArguments {
                first,
                after,
                last,
                before,
            },
        )
        .await?;
        let data = self
            .repository
            .list_user_roles(UserRoleQuery {
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
                CURSOR_KIND_USER_ROLE,
                order.as_u8(),
                &prepared.filter_fingerprint,
                &entry.sort_key,
            )
            .await?;
            items.push(UserRolePageItem {
                record: entry.record,
                cursor,
            });
        }
        Ok(UserRolePage {
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

    #[tracing::instrument(skip_all, name = "rbac.user_roles.assign")]
    pub async fn assign_user_roles(
        &self,
        authority: &RbacManagementAuthority,
        command: AssignUserRolesCommand,
    ) -> Result<UserRoleMutationResult, AppError> {
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
    ) -> Result<UserRoleMutationResult, AppError> {
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
}

/// Deduplicate a page-bounded batch lookup and reject oversized input.
fn dedupe_batch<T: Ord>(oids: Vec<T>) -> Result<Vec<T>, AppError> {
    let oids = oids.into_iter().collect::<BTreeSet<_>>();
    if oids.len() > MAX_BATCH_LOOKUPS {
        return Err(AppError::from_code(RbacErrorCode::InvalidCollectionSize)
            .with_param("max", MAX_BATCH_LOOKUPS.to_string()));
    }
    Ok(oids.into_iter().collect())
}
