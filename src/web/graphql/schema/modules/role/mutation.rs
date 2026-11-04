use crate::graphql::schema::access::access;
use async_graphql::{Context, Object, Result};
use identity_application::{
    authorization::ManagementTarget,
    rbac::{
        AssignUserRolesCommand, CreateRoleCommand, RevokeUserRolesCommand, RoleStateCommand,
        SetRolePermissionsCommand, UpdateRoleCommand,
    },
};
use identity_domain::{authorization::ManagementScope, rbac::RoleOid};

use super::{
    integration,
    types::{
        CreateRoleInput, RolePayload, RoleStateInput, SetRolePermissionsInput, UpdateRoleInput,
        decode_role_oid, decode_scope_ids,
    },
    user_role::{AssignUserRolesInput, RevokeUserRolesInput, UserRolesPayload, decode_user_oid},
};
use crate::graphql::schema::{
    authorization::request_context,
    error::app_error,
    management_guard::ManagementGuard,
    modules::{
        localized::LocalizedMetadataInput,
        resource::support::{decode_oids, normalize_reason},
        role::types::RoleGlobalId,
    },
};

#[derive(Default)]
pub(crate) struct RoleMutation;

#[Object]
impl RoleMutation {
    #[graphql(
        guard = "ManagementGuard::new(ManagementScope::RolesWrite, ManagementTarget::instance())",
        directive = access::apply(ManagementGuard::policy(ManagementScope::RolesWrite))
    )]
    async fn create_role(&self, ctx: &Context<'_>, input: CreateRoleInput) -> Result<RolePayload> {
        let CreateRoleInput {
            name,
            description,
            names,
            descriptions,
            reason,
            client_mutation_id,
        } = input;
        let metadata = LocalizedMetadataInput {
            names,
            descriptions,
        }
        .into_domain(ctx)?;
        let reason = normalize_reason(ctx, &reason)?;
        let request = request_context(ctx)?;
        let record = integration::create_role(
            request,
            CreateRoleCommand {
                name,
                description,
                metadata: Some(metadata),
                reason,
                client_mutation_id: client_mutation_id.clone(),
            },
        )
        .await
        .map_err(|error| app_error(ctx, error))?;
        Ok(RolePayload::new(record, client_mutation_id))
    }

    #[graphql(
        guard = "ManagementGuard::new(ManagementScope::RolesWrite, ManagementTarget::instance())",
        directive = access::apply(ManagementGuard::policy(ManagementScope::RolesWrite))
    )]
    async fn update_role(&self, ctx: &Context<'_>, input: UpdateRoleInput) -> Result<RolePayload> {
        let UpdateRoleInput {
            name,
            description,
            id,
            names,
            descriptions,
            expected_version,
            reason,
            client_mutation_id,
        } = input;
        let role_oid = decode_role_oid(ctx, &id)?;
        let names = names.map(|names| names.into_iter().map(Into::into).collect());
        let descriptions =
            descriptions.map(|descriptions| descriptions.into_iter().map(Into::into).collect());
        let reason = reason.trim().to_owned();
        let request = request_context(ctx)?;
        let record = integration::update_role(
            request,
            UpdateRoleCommand {
                name,
                description,
                role_oid,
                names,
                descriptions,
                expected_version,
                reason,
                client_mutation_id: client_mutation_id.clone(),
            },
        )
        .await
        .map_err(|error| app_error(ctx, error))?;
        Ok(RolePayload::new(record, client_mutation_id))
    }

    #[graphql(
        guard = "ManagementGuard::new(ManagementScope::RolesWrite, ManagementTarget::instance())",
        directive = access::apply(ManagementGuard::policy(ManagementScope::RolesWrite))
    )]
    async fn enable_role(&self, ctx: &Context<'_>, input: RoleStateInput) -> Result<RolePayload> {
        state(ctx, input, true).await
    }

    #[graphql(
        guard = "ManagementGuard::new(ManagementScope::RolesWrite, ManagementTarget::instance())",
        directive = access::apply(ManagementGuard::policy(ManagementScope::RolesWrite))
    )]
    async fn disable_role(&self, ctx: &Context<'_>, input: RoleStateInput) -> Result<RolePayload> {
        state(ctx, input, false).await
    }

    #[graphql(
        guard = "ManagementGuard::new(ManagementScope::RolesWrite, ManagementTarget::instance())",
        directive = access::apply(ManagementGuard::policy(ManagementScope::RolesWrite))
    )]
    async fn set_role_permissions(
        &self,
        ctx: &Context<'_>,
        input: SetRolePermissionsInput,
    ) -> Result<RolePayload> {
        let SetRolePermissionsInput {
            role_id,
            permission_ids,
            expected_version,
            reason,
            client_mutation_id,
        } = input;
        let role_oid = decode_role_oid(ctx, &role_id)?;
        let scope_oids = decode_scope_ids(ctx, &permission_ids)?;
        let reason = normalize_reason(ctx, &reason)?;
        let request = request_context(ctx)?;
        let record = integration::set_role_permissions(
            request,
            SetRolePermissionsCommand {
                role_oid,
                scope_oids,
                expected_version,
                reason,
                client_mutation_id: client_mutation_id.clone(),
            },
        )
        .await
        .map_err(|error| app_error(ctx, error))?;
        Ok(RolePayload::new(record, client_mutation_id))
    }

    #[graphql(
        guard = "ManagementGuard::new(ManagementScope::RoleAssignmentsWrite, ManagementTarget::instance())",
        directive = access::apply(ManagementGuard::policy(ManagementScope::RoleAssignmentsWrite))
    )]
    async fn assign_user_roles(
        &self,
        ctx: &Context<'_>,
        input: AssignUserRolesInput,
    ) -> Result<UserRolesPayload> {
        let AssignUserRolesInput {
            user_id,
            role_ids,
            expected_user_version,
            reason,
            client_mutation_id,
        } = input;
        let user_oid = decode_user_oid(ctx, &user_id)?;
        let role_oids = decode_role_oids(ctx, &role_ids)?;
        let reason = normalize_reason(ctx, &reason)?;
        let request = request_context(ctx)?;
        let result = integration::assign_user_roles(
            request,
            AssignUserRolesCommand {
                user_oid,
                role_oids,
                expected_user_version,
                reason,
                client_mutation_id: client_mutation_id.clone(),
            },
        )
        .await
        .map_err(|error| app_error(ctx, error))?;
        Ok(UserRolesPayload::new(result, client_mutation_id))
    }

    #[graphql(
        guard = "ManagementGuard::new(ManagementScope::RoleAssignmentsWrite, ManagementTarget::instance())",
        directive = access::apply(ManagementGuard::policy(ManagementScope::RoleAssignmentsWrite))
    )]
    async fn revoke_user_roles(
        &self,
        ctx: &Context<'_>,
        input: RevokeUserRolesInput,
    ) -> Result<UserRolesPayload> {
        let RevokeUserRolesInput {
            user_id,
            role_ids,
            expected_user_version,
            reason,
            client_mutation_id,
        } = input;
        let user_oid = decode_user_oid(ctx, &user_id)?;
        let role_oids = decode_role_oids(ctx, &role_ids)?;
        let reason = normalize_reason(ctx, &reason)?;
        let request = request_context(ctx)?;
        let result = integration::revoke_user_roles(
            request,
            RevokeUserRolesCommand {
                user_oid,
                role_oids,
                expected_user_version,
                reason,
                client_mutation_id: client_mutation_id.clone(),
            },
        )
        .await
        .map_err(|error| app_error(ctx, error))?;
        Ok(UserRolesPayload::new(result, client_mutation_id))
    }
}

fn decode_role_oids(ctx: &Context<'_>, ids: &[async_graphql::ID]) -> Result<Vec<RoleOid>> {
    decode_oids::<RoleGlobalId>(ctx, ids).map(|ids| ids.into_iter().map(RoleOid).collect())
}

async fn state(ctx: &Context<'_>, input: RoleStateInput, enabled: bool) -> Result<RolePayload> {
    let RoleStateInput {
        id,
        expected_version,
        reason,
        client_mutation_id,
    } = input;
    let role_oid = decode_role_oid(ctx, &id)?;
    let reason = normalize_reason(ctx, &reason)?;
    let request = request_context(ctx)?;
    let command = RoleStateCommand {
        role_oid,
        expected_version,
        reason,
        client_mutation_id: client_mutation_id.clone(),
    };
    let record = if enabled {
        integration::enable_role(request, command).await
    } else {
        integration::disable_role(request, command).await
    }
    .map_err(|error| app_error(ctx, error))?;
    Ok(RolePayload::new(record, client_mutation_id))
}
