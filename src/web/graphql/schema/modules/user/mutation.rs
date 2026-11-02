use crate::graphql::schema::access::access;
use async_graphql::{Context, Guard, MaybeUndefined, Object, Result};
use identity_application::{
    authorization::ManagementTarget,
    error::{codes::graphql::GraphqlErrorCode, params::ErrorParams},
};
use identity_domain::{authorization::ManagementScope, user::UserOid};

use super::{
    integration,
    query::decode_user_oid,
    types::{
        CreateUserInput, CreateUserPayload, UnlockUserInput, UpdateUserInput, UpdateUserPayload,
        UserProfilePatchInput, UserStateInput, UserStatePayload, normalize_reason,
        optional_identifier,
    },
};
use crate::graphql::schema::{
    authorization::request_context,
    error::{app_error, coded_error},
    management_guard::ManagementGuard,
};

#[derive(Default)]
pub(crate) struct UserManagementMutation;

#[Object]
impl UserManagementMutation {
    #[graphql(
        guard = "ManagementGuard::new(ManagementScope::UsersCreate, ManagementTarget::instance())",
        directive = access::apply(ManagementGuard::policy(ManagementScope::UsersCreate))
    )]
    async fn create_user(
        &self,
        ctx: &Context<'_>,
        input: CreateUserInput,
    ) -> Result<CreateUserPayload> {
        let CreateUserInput {
            username,
            email,
            password,
            profile,
            reason,
            client_mutation_id,
        } = input;
        let reason = reason_or_error(ctx, &reason)?;
        let profile = profile
            .map(UserProfilePatchInput::into_patch)
            .unwrap_or_default();
        let request = request_context(ctx)?;
        let user = integration::create_user(
            request,
            username,
            email,
            password,
            profile,
            reason,
            client_mutation_id.clone(),
        )
        .await
        .map_err(|error| app_error(ctx, error))?;
        Ok(CreateUserPayload::new(user, client_mutation_id))
    }

    #[graphql(
        guard = "ManagementGuard::new(ManagementScope::UsersUpdate, ManagementTarget::instance())",
        directive = access::apply(ManagementGuard::policy(ManagementScope::UsersUpdate))
    )]
    async fn update_user(
        &self,
        ctx: &Context<'_>,
        input: UpdateUserInput,
    ) -> Result<UpdateUserPayload> {
        let UpdateUserInput {
            id,
            username,
            email,
            profile,
            expected_version,
            reason,
            client_mutation_id,
        } = input;
        let user = decode_user_oid(ctx, &id)?;
        let reason = reason.trim().to_owned();
        let username = identifier(username, ctx)?;
        let email = identifier(email, ctx)?;
        let profile = profile
            .map(UserProfilePatchInput::into_patch)
            .unwrap_or_default();

        let request = request_context(ctx)?;
        ManagementGuard::new(
            ManagementScope::UsersUpdate,
            ManagementTarget::user(user, false),
        )
        .check(ctx)
        .await?;
        let user = integration::update_user(
            request,
            user,
            username,
            email,
            profile,
            expected_version,
            reason,
            client_mutation_id.clone(),
        )
        .await
        .map_err(|error| app_error(ctx, error))?;
        Ok(UpdateUserPayload::new(user, client_mutation_id))
    }

    #[graphql(
        guard = "ManagementGuard::new(ManagementScope::UsersState, ManagementTarget::instance())",
        directive = access::apply(ManagementGuard::policy(ManagementScope::UsersState))
    )]
    async fn enable_user(
        &self,
        ctx: &Context<'_>,
        input: UserStateInput,
    ) -> Result<UserStatePayload> {
        let UserStateInput {
            id,
            expected_version,
            reason,
            client_mutation_id,
        } = input;
        let (user, reason) = state_fields(ctx, &id, &reason)?;
        let request = request_context(ctx)?;
        ManagementGuard::new(
            ManagementScope::UsersState,
            ManagementTarget::user(user, false),
        )
        .check(ctx)
        .await?;
        let user = integration::enable_user(
            request,
            user,
            expected_version,
            reason,
            client_mutation_id.clone(),
        )
        .await
        .map_err(|error| app_error(ctx, error))?;
        Ok(UserStatePayload::new(user, client_mutation_id))
    }

    #[graphql(
        guard = "ManagementGuard::new(ManagementScope::UsersState, ManagementTarget::instance())",
        directive = access::apply(ManagementGuard::policy(ManagementScope::UsersState))
    )]
    async fn disable_user(
        &self,
        ctx: &Context<'_>,
        input: UserStateInput,
    ) -> Result<UserStatePayload> {
        let UserStateInput {
            id,
            expected_version,
            reason,
            client_mutation_id,
        } = input;
        let (user, reason) = state_fields(ctx, &id, &reason)?;
        let request = request_context(ctx)?;
        ManagementGuard::new(
            ManagementScope::UsersState,
            ManagementTarget::user(user, false),
        )
        .check(ctx)
        .await?;
        let user = integration::disable_user(
            request,
            user,
            expected_version,
            reason,
            client_mutation_id.clone(),
        )
        .await
        .map_err(|error| app_error(ctx, error))?;
        Ok(UserStatePayload::new(user, client_mutation_id))
    }

    #[graphql(
        guard = "ManagementGuard::new(ManagementScope::UsersState, ManagementTarget::instance())",
        directive = access::apply(ManagementGuard::policy(ManagementScope::UsersState))
    )]
    async fn unlock_user(
        &self,
        ctx: &Context<'_>,
        input: UnlockUserInput,
    ) -> Result<UserStatePayload> {
        let UnlockUserInput {
            id,
            expected_version,
            reason,
            client_mutation_id,
        } = input;
        let (user, reason) = state_fields(ctx, &id, &reason)?;
        let request = request_context(ctx)?;
        ManagementGuard::new(
            ManagementScope::UsersState,
            ManagementTarget::user(user, false),
        )
        .check(ctx)
        .await?;
        let user = integration::unlock_user(
            request,
            user,
            expected_version,
            reason,
            client_mutation_id.clone(),
        )
        .await
        .map_err(|error| app_error(ctx, error))?;
        Ok(UserStatePayload::new(user, client_mutation_id))
    }
}

fn state_fields(
    ctx: &Context<'_>,
    id: &async_graphql::ID,
    reason: &str,
) -> Result<(UserOid, String)> {
    let user = decode_user_oid(ctx, id)?;
    let reason = reason_or_error(ctx, reason)?;
    Ok((user, reason))
}

fn identifier(value: MaybeUndefined<String>, ctx: &Context<'_>) -> Result<Option<String>> {
    optional_identifier(value)
        .map_err(|_| coded_error(ctx, GraphqlErrorCode::ValidationFailed, ErrorParams::new()))
}

fn reason_or_error(ctx: &Context<'_>, reason: &str) -> Result<String> {
    normalize_reason(reason)
        .ok_or_else(|| coded_error(ctx, GraphqlErrorCode::ValidationFailed, ErrorParams::new()))
}
