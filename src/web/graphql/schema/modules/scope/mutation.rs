use crate::graphql::schema::access::access;
use async_graphql::{Context, Object, Result};
use identity_application::{
    authorization::ManagementTarget,
    error::{AppError, codes::rbac::RbacErrorCode},
    rbac::{CreateScopeCommand, ScopeStateCommand, UpdateScopeCommand},
};
use identity_domain::{authorization::ManagementScope, rbac::ResourceOid};

use super::super::resource::support::{decode_oid, normalize_reason};
use super::{
    integration,
    types::{
        CreateScopeInput, ScopeDescriptionInput, ScopePayload, ScopeStateInput, UpdateScopeInput,
        decode_scope_oid,
    },
};
use crate::graphql::schema::{
    authorization::request_context, error::app_error, management_guard::ManagementGuard,
};

#[derive(Default)]
pub(crate) struct ScopeMutation;

#[Object]
impl ScopeMutation {
    #[graphql(
        guard = "ManagementGuard::new(ManagementScope::ScopesWrite, ManagementTarget::instance())",
        directive = access::apply(ManagementGuard::policy(ManagementScope::ScopesWrite))
    )]
    async fn create_scope(
        &self,
        ctx: &Context<'_>,
        input: CreateScopeInput,
    ) -> Result<ScopePayload> {
        let CreateScopeInput {
            resource_id,
            code,
            name,
            names,
            description,
            descriptions,
            reason,
            client_mutation_id,
        } = input;
        let resource_oid =
            decode_oid::<super::super::resource::types::ResourceGlobalId>(ctx, &resource_id)?;
        check_localized(ctx, &names, &descriptions)?;
        let reason = normalize_reason(ctx, &reason)?;
        let request = request_context(ctx)?;
        let record = integration::create_scope(
            request,
            CreateScopeCommand {
                resource_oid: ResourceOid(resource_oid),
                code,
                name,
                names: map_descriptions(names),
                description,
                descriptions: map_descriptions(descriptions.unwrap_or_default()),
                reason,
                client_mutation_id: client_mutation_id.clone(),
            },
        )
        .await
        .map_err(|error| app_error(ctx, error))?;
        Ok(ScopePayload::new(record, client_mutation_id))
    }

    #[graphql(
        guard = "ManagementGuard::new(ManagementScope::ScopesWrite, ManagementTarget::instance())",
        directive = access::apply(ManagementGuard::policy(ManagementScope::ScopesWrite))
    )]
    async fn update_scope(
        &self,
        ctx: &Context<'_>,
        input: UpdateScopeInput,
    ) -> Result<ScopePayload> {
        let UpdateScopeInput {
            id,
            name,
            names,
            description,
            descriptions,
            expected_version,
            reason,
            client_mutation_id,
        } = input;
        check_optional_localized(ctx, &names, &descriptions)?;
        let scope_oid = decode_scope_oid(ctx, &id)?;
        let reason = normalize_reason(ctx, &reason)?;
        let descriptions = descriptions.map(map_descriptions);
        let names = names.map(map_descriptions);
        let request = request_context(ctx)?;
        let record = integration::update_scope(
            request,
            UpdateScopeCommand {
                scope_oid,
                name,
                names,
                description,
                descriptions,
                expected_version,
                reason,
                client_mutation_id: client_mutation_id.clone(),
            },
        )
        .await
        .map_err(|error| app_error(ctx, error))?;
        Ok(ScopePayload::new(record, client_mutation_id))
    }

    #[graphql(
        guard = "ManagementGuard::new(ManagementScope::ScopesWrite, ManagementTarget::instance())",
        directive = access::apply(ManagementGuard::policy(ManagementScope::ScopesWrite))
    )]
    async fn enable_scope(
        &self,
        ctx: &Context<'_>,
        input: ScopeStateInput,
    ) -> Result<ScopePayload> {
        state(ctx, input, true).await
    }

    #[graphql(
        guard = "ManagementGuard::new(ManagementScope::ScopesWrite, ManagementTarget::instance())",
        directive = access::apply(ManagementGuard::policy(ManagementScope::ScopesWrite))
    )]
    async fn disable_scope(
        &self,
        ctx: &Context<'_>,
        input: ScopeStateInput,
    ) -> Result<ScopePayload> {
        state(ctx, input, false).await
    }
}

async fn state(ctx: &Context<'_>, input: ScopeStateInput, enabled: bool) -> Result<ScopePayload> {
    let ScopeStateInput {
        id,
        expected_version,
        reason,
        client_mutation_id,
    } = input;
    let scope_oid = decode_scope_oid(ctx, &id)?;
    let reason = normalize_reason(ctx, &reason)?;
    let request = request_context(ctx)?;
    let command = ScopeStateCommand {
        scope_oid,
        expected_version,
        reason,
        client_mutation_id: client_mutation_id.clone(),
    };
    let record = if enabled {
        integration::enable_scope(request, command).await
    } else {
        integration::disable_scope(request, command).await
    }
    .map_err(|error| app_error(ctx, error))?;
    Ok(ScopePayload::new(record, client_mutation_id))
}

fn check_localized(
    ctx: &Context<'_>,
    names: &[ScopeDescriptionInput],
    descriptions: &Option<Vec<ScopeDescriptionInput>>,
) -> Result<()> {
    check_optional_localized(ctx, &Some(names.to_vec()), descriptions)
}

fn check_optional_localized(
    ctx: &Context<'_>,
    names: &Option<Vec<ScopeDescriptionInput>>,
    descriptions: &Option<Vec<ScopeDescriptionInput>>,
) -> Result<()> {
    for (field, len) in [
        ("names", names.as_ref().map(Vec::len)),
        ("descriptions", descriptions.as_ref().map(Vec::len)),
    ] {
        if len.is_some_and(|len| len > 20) {
            return Err(app_error(
                ctx,
                AppError::from_code(RbacErrorCode::InvalidCollectionSize)
                    .with_param("max", "20")
                    .with_field(field),
            ));
        }
    }
    Ok(())
}

fn map_descriptions(
    descriptions: Vec<ScopeDescriptionInput>,
) -> Vec<identity_application::rbac::ScopeDescription> {
    descriptions.into_iter().map(Into::into).collect()
}
