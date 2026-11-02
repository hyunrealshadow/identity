use crate::graphql::schema::access::access;
use async_graphql::{Context, MaybeUndefined, Object, Result};
use identity_application::{
    authorization::ManagementTarget,
    rbac::{CreateResourceCommand, ResourceStateCommand, UpdateResourceCommand},
};
use identity_domain::authorization::ManagementScope;

use super::{
    integration,
    support::normalize_reason,
    types::{
        CreateResourceInput, ResourcePayload, ResourceStateInput, UpdateResourceInput,
        decode_resource_oid,
    },
};
use crate::graphql::schema::{
    authorization::request_context, error::app_error, management_guard::ManagementGuard,
};

#[derive(Default)]
pub(crate) struct ResourceMutation;

#[Object]
impl ResourceMutation {
    #[graphql(
        guard = "ManagementGuard::new(ManagementScope::ResourcesWrite, ManagementTarget::instance())",
        directive = access::apply(ManagementGuard::policy(ManagementScope::ResourcesWrite))
    )]
    async fn create_resource(
        &self,
        ctx: &Context<'_>,
        input: CreateResourceInput,
    ) -> Result<ResourcePayload> {
        let CreateResourceInput {
            uri,
            name,
            reason,
            client_mutation_id,
        } = input;
        let reason = normalize_reason(ctx, &reason)?;
        let request = request_context(ctx)?;
        let record = integration::create_resource(
            request,
            CreateResourceCommand {
                uri,
                name,
                reason,
                client_mutation_id: client_mutation_id.clone(),
            },
        )
        .await
        .map_err(|error| app_error(ctx, error))?;
        Ok(ResourcePayload::new(record, client_mutation_id))
    }

    #[graphql(
        guard = "ManagementGuard::new(ManagementScope::ResourcesWrite, ManagementTarget::instance())",
        directive = access::apply(ManagementGuard::policy(ManagementScope::ResourcesWrite))
    )]
    async fn update_resource(
        &self,
        ctx: &Context<'_>,
        input: UpdateResourceInput,
    ) -> Result<ResourcePayload> {
        let UpdateResourceInput {
            id,
            name,
            expected_version,
            reason,
            client_mutation_id,
        } = input;
        let resource_oid = decode_resource_oid(ctx, &id)?;
        let reason = normalize_reason(ctx, &reason)?;
        let name = match name {
            MaybeUndefined::Undefined | MaybeUndefined::Null => None,
            MaybeUndefined::Value(value) => Some(value),
        };
        let request = request_context(ctx)?;
        let record = integration::update_resource(
            request,
            UpdateResourceCommand {
                resource_oid,
                name,
                expected_version,
                reason,
                client_mutation_id: client_mutation_id.clone(),
            },
        )
        .await
        .map_err(|error| app_error(ctx, error))?;
        Ok(ResourcePayload::new(record, client_mutation_id))
    }

    #[graphql(
        guard = "ManagementGuard::new(ManagementScope::ResourcesWrite, ManagementTarget::instance())",
        directive = access::apply(ManagementGuard::policy(ManagementScope::ResourcesWrite))
    )]
    async fn enable_resource(
        &self,
        ctx: &Context<'_>,
        input: ResourceStateInput,
    ) -> Result<ResourcePayload> {
        state(ctx, input, true).await
    }

    #[graphql(
        guard = "ManagementGuard::new(ManagementScope::ResourcesWrite, ManagementTarget::instance())",
        directive = access::apply(ManagementGuard::policy(ManagementScope::ResourcesWrite))
    )]
    async fn disable_resource(
        &self,
        ctx: &Context<'_>,
        input: ResourceStateInput,
    ) -> Result<ResourcePayload> {
        state(ctx, input, false).await
    }
}

async fn state(
    ctx: &Context<'_>,
    input: ResourceStateInput,
    enabled: bool,
) -> Result<ResourcePayload> {
    let ResourceStateInput {
        id,
        expected_version,
        reason,
        client_mutation_id,
    } = input;
    let resource_oid = decode_resource_oid(ctx, &id)?;
    let reason = normalize_reason(ctx, &reason)?;
    let request = request_context(ctx)?;
    let command = ResourceStateCommand {
        resource_oid,
        expected_version,
        reason,
        client_mutation_id: client_mutation_id.clone(),
    };
    let record = if enabled {
        integration::enable_resource(request, command).await
    } else {
        integration::disable_resource(request, command).await
    }
    .map_err(|error| app_error(ctx, error))?;
    Ok(ResourcePayload::new(record, client_mutation_id))
}
