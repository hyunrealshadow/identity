use crate::graphql::schema::access::access;
use async_graphql::{Context, GuardExt, Object, Result};
use identity_application::{
    authorization::ManagementTarget,
    rbac::{
        AddGroupMemberCommand, CreateGroupCommand, DeleteGroupCommand, GroupStateCommand,
        RemoveGroupMemberCommand, SetGroupRolesCommand, UpdateGroupCommand,
    },
};
use identity_domain::authorization::ManagementScope;

use super::{
    integration,
    types::{
        AddGroupMemberInput, CreateGroupInput, DeleteGroupPayload, GroupMemberPayload,
        GroupPayload, GroupRolesPayload, GroupStateInput, RemoveGroupMemberInput,
        SetGroupEnabledInput, SetGroupRolesInput, UpdateGroupInput, decode_group_oid,
        decode_role_oids, decode_user_oid,
    },
};
use crate::graphql::schema::{
    authorization::{RecentAuthenticationGuard, request_context},
    error::app_error,
    management_guard::ManagementGuard,
    modules::resource::support::normalize_reason,
};

#[derive(Default)]
pub(crate) struct GroupMutation;

#[Object]
impl GroupMutation {
    #[graphql(
        guard = "ManagementGuard::new(ManagementScope::GroupsWrite, ManagementTarget::instance()).and(RecentAuthenticationGuard::aal2())",
        directive = access::apply(ManagementGuard::policy(ManagementScope::GroupsWrite)),
        directive = access::apply(RecentAuthenticationGuard::aal2().policy())
    )]
    async fn create_group(
        &self,
        ctx: &Context<'_>,
        input: CreateGroupInput,
    ) -> Result<GroupPayload> {
        let CreateGroupInput {
            name,
            description,
            names,
            descriptions,
            reason,
            client_mutation_id,
        } = input;
        let reason = normalize_reason(ctx, &reason)?;
        let request = request_context(ctx)?;
        let record = integration::create_group(
            request,
            CreateGroupCommand {
                name,
                description,
                names: names.into_iter().map(Into::into).collect(),
                descriptions: descriptions.into_iter().map(Into::into).collect(),
                reason,
                client_mutation_id: client_mutation_id.clone(),
            },
        )
        .await
        .map_err(|error| app_error(ctx, error))?;
        Ok(GroupPayload::new(record, client_mutation_id))
    }

    #[graphql(
        guard = "ManagementGuard::new(ManagementScope::GroupsWrite, ManagementTarget::instance()).and(RecentAuthenticationGuard::aal2())",
        directive = access::apply(ManagementGuard::policy(ManagementScope::GroupsWrite)),
        directive = access::apply(RecentAuthenticationGuard::aal2().policy())
    )]
    async fn update_group(
        &self,
        ctx: &Context<'_>,
        input: UpdateGroupInput,
    ) -> Result<GroupPayload> {
        let UpdateGroupInput {
            name,
            description,
            id,
            names,
            descriptions,
            expected_version,
            reason,
            client_mutation_id,
        } = input;
        let group_oid = decode_group_oid(ctx, &id)?;
        let reason = reason.trim().to_owned();
        let request = request_context(ctx)?;
        let record = integration::update_group(
            request,
            UpdateGroupCommand {
                name,
                description,
                group_oid,
                names: names.map(|names| names.into_iter().map(Into::into).collect()),
                descriptions: descriptions
                    .map(|descriptions| descriptions.into_iter().map(Into::into).collect()),
                expected_version,
                reason,
                client_mutation_id: client_mutation_id.clone(),
            },
        )
        .await
        .map_err(|error| app_error(ctx, error))?;
        Ok(GroupPayload::new(record, client_mutation_id))
    }

    #[graphql(
        guard = "ManagementGuard::new(ManagementScope::GroupsWrite, ManagementTarget::instance()).and(RecentAuthenticationGuard::aal2())",
        directive = access::apply(ManagementGuard::policy(ManagementScope::GroupsWrite)),
        directive = access::apply(RecentAuthenticationGuard::aal2().policy())
    )]
    async fn set_group_enabled(
        &self,
        ctx: &Context<'_>,
        input: SetGroupEnabledInput,
    ) -> Result<GroupPayload> {
        let SetGroupEnabledInput {
            id,
            enabled,
            expected_version,
            reason,
            client_mutation_id,
        } = input;
        let group_oid = decode_group_oid(ctx, &id)?;
        let reason = normalize_reason(ctx, &reason)?;
        let request = request_context(ctx)?;
        let command = GroupStateCommand {
            group_oid,
            expected_version,
            reason,
            client_mutation_id: client_mutation_id.clone(),
        };
        let record = if enabled {
            integration::enable_group(request, command).await
        } else {
            integration::disable_group(request, command).await
        }
        .map_err(|error| app_error(ctx, error))?;
        Ok(GroupPayload::new(record, client_mutation_id))
    }

    #[graphql(
        guard = "ManagementGuard::new(ManagementScope::GroupsWrite, ManagementTarget::instance()).and(RecentAuthenticationGuard::aal2())",
        directive = access::apply(ManagementGuard::policy(ManagementScope::GroupsWrite)),
        directive = access::apply(RecentAuthenticationGuard::aal2().policy())
    )]
    async fn delete_group(
        &self,
        ctx: &Context<'_>,
        input: GroupStateInput,
    ) -> Result<DeleteGroupPayload> {
        let GroupStateInput {
            id,
            expected_version,
            reason,
            client_mutation_id,
        } = input;
        let group_oid = decode_group_oid(ctx, &id)?;
        let reason = normalize_reason(ctx, &reason)?;
        let request = request_context(ctx)?;
        let result = integration::delete_group(
            request,
            DeleteGroupCommand {
                group_oid,
                expected_version,
                reason,
                client_mutation_id: client_mutation_id.clone(),
            },
        )
        .await
        .map_err(|error| app_error(ctx, error))?;
        Ok(DeleteGroupPayload::new(
            result.group_oid,
            result.deleted,
            client_mutation_id,
        ))
    }

    #[graphql(
        guard = "ManagementGuard::new(ManagementScope::GroupMembershipsWrite, ManagementTarget::instance()).and(RecentAuthenticationGuard::aal2())",
        directive = access::apply(ManagementGuard::policy(ManagementScope::GroupMembershipsWrite)),
        directive = access::apply(RecentAuthenticationGuard::aal2().policy())
    )]
    async fn add_group_member(
        &self,
        ctx: &Context<'_>,
        input: AddGroupMemberInput,
    ) -> Result<GroupMemberPayload> {
        let AddGroupMemberInput {
            group_id,
            user_id,
            expected_version,
            reason,
            client_mutation_id,
        } = input;
        let group_oid = decode_group_oid(ctx, &group_id)?;
        let user_oid = decode_user_oid(ctx, &user_id)?;
        let reason = normalize_reason(ctx, &reason)?;
        let request = request_context(ctx)?;
        let result = integration::add_group_member(
            request,
            AddGroupMemberCommand {
                group_oid,
                user_oid,
                expected_version,
                reason,
                client_mutation_id: client_mutation_id.clone(),
            },
        )
        .await
        .map_err(|error| app_error(ctx, error))?;
        Ok(GroupMemberPayload::new(result, client_mutation_id))
    }

    #[graphql(
        guard = "ManagementGuard::new(ManagementScope::GroupMembershipsWrite, ManagementTarget::instance()).and(RecentAuthenticationGuard::aal2())",
        directive = access::apply(ManagementGuard::policy(ManagementScope::GroupMembershipsWrite)),
        directive = access::apply(RecentAuthenticationGuard::aal2().policy())
    )]
    async fn remove_group_member(
        &self,
        ctx: &Context<'_>,
        input: RemoveGroupMemberInput,
    ) -> Result<GroupMemberPayload> {
        let RemoveGroupMemberInput {
            group_id,
            user_id,
            expected_version,
            reason,
            client_mutation_id,
        } = input;
        let group_oid = decode_group_oid(ctx, &group_id)?;
        let user_oid = decode_user_oid(ctx, &user_id)?;
        let reason = normalize_reason(ctx, &reason)?;
        let request = request_context(ctx)?;
        let result = integration::remove_group_member(
            request,
            RemoveGroupMemberCommand {
                group_oid,
                user_oid,
                expected_version,
                reason,
                client_mutation_id: client_mutation_id.clone(),
            },
        )
        .await
        .map_err(|error| app_error(ctx, error))?;
        Ok(GroupMemberPayload::new(result, client_mutation_id))
    }

    #[graphql(
        guard = "ManagementGuard::new(ManagementScope::GroupRolesWrite, ManagementTarget::instance()).and(RecentAuthenticationGuard::aal2())",
        directive = access::apply(ManagementGuard::policy(ManagementScope::GroupRolesWrite)),
        directive = access::apply(RecentAuthenticationGuard::aal2().policy())
    )]
    async fn set_group_roles(
        &self,
        ctx: &Context<'_>,
        input: SetGroupRolesInput,
    ) -> Result<GroupRolesPayload> {
        let SetGroupRolesInput {
            group_id,
            role_ids,
            expected_version,
            reason,
            client_mutation_id,
        } = input;
        let group_oid = decode_group_oid(ctx, &group_id)?;
        let role_oids = decode_role_oids(ctx, &role_ids)?;
        let reason = normalize_reason(ctx, &reason)?;
        let request = request_context(ctx)?;
        let result = integration::set_group_roles(
            request,
            SetGroupRolesCommand {
                group_oid,
                role_oids,
                expected_version,
                reason,
                client_mutation_id: client_mutation_id.clone(),
            },
        )
        .await
        .map_err(|error| app_error(ctx, error))?;
        Ok(GroupRolesPayload::new(result, client_mutation_id))
    }
}
