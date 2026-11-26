use crate::graphql::schema::access::access;
use async_graphql::{Context, Guard, MaybeUndefined, Object, Result};
use identity_application::{
    authorization::ManagementTarget,
    error::codes::graphql,
    user::management::{CreateUserCommand, UpdateUserCommand, UserPassword},
};
use identity_domain::{
    authorization::ManagementScope,
    global_id::GlobalId,
    user::{RequiredAction, UserOid},
};

use crate::graphql::schema::modules::session::SessionGlobalId;

use super::{
    integration,
    query::decode_user_oid,
    types::{
        CreateUserInput, CreateUserPayload, DeleteUserPayload, ResetUserPasswordPayload,
        RevokeUserSessionsInput, SendUserInvitationInput, SendUserInvitationPayload,
        UnlockUserInput, UpdateUserInput, UpdateUserPayload, UserProfilePatchInput, UserStateInput,
        UserStatePayload, normalize_reason, optional_identifier,
    },
};
use crate::graphql::schema::{
    authorization::request_context, error::app_error, management_guard::ManagementGuard,
};

#[derive(Default)]
pub(crate) struct UserManagementMutation;

#[Object]
impl UserManagementMutation {
    #[graphql(
        guard = "ManagementGuard::new(ManagementScope::UsersWrite, ManagementTarget::instance())",
        directive = access::apply(ManagementGuard::policy(ManagementScope::UsersWrite))
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
            send_invitation,
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
            CreateUserCommand {
                username,
                email,
                password: password.map(UserPassword::new),
                send_invitation,
                profile,
                reason,
                client_mutation_id: client_mutation_id.clone(),
            },
        )
        .await
        .map_err(|error| app_error(ctx, error))?;
        Ok(CreateUserPayload::new(user, client_mutation_id))
    }

    /// Email a new link with which the user sets their first password. Only
    /// for a user without a password; it replaces any earlier link.
    #[graphql(
        guard = "ManagementGuard::new(ManagementScope::UsersWrite, ManagementTarget::instance())",
        directive = access::apply(ManagementGuard::policy(ManagementScope::UsersWrite))
    )]
    async fn send_user_invitation(
        &self,
        ctx: &Context<'_>,
        input: SendUserInvitationInput,
    ) -> Result<SendUserInvitationPayload> {
        let SendUserInvitationInput {
            id,
            reason,
            client_mutation_id,
        } = input;
        let (user, reason) = state_fields(ctx, &id, &reason)?;
        let request = request_context(ctx)?;
        ManagementGuard::new(
            ManagementScope::UsersWrite,
            ManagementTarget::user(user, false),
        )
        .check(ctx)
        .await?;
        let (user, invitation) =
            integration::send_user_invitation(request, user, reason, client_mutation_id.clone())
                .await
                .map_err(|error| app_error(ctx, error))?;
        Ok(SendUserInvitationPayload::new(
            user,
            invitation,
            client_mutation_id,
        ))
    }

    #[graphql(
        guard = "ManagementGuard::new(ManagementScope::UsersWrite, ManagementTarget::instance())",
        directive = access::apply(ManagementGuard::policy(ManagementScope::UsersWrite))
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
            email_verified,
            required_actions,
            profile,
            expected_version,
            reason,
            client_mutation_id,
        } = input;
        let required_actions =
            required_actions.map(|actions| actions.into_iter().map(RequiredAction::from).collect());
        let user = decode_user_oid(ctx, &id)?;
        let reason = reason.trim().to_owned();
        let username = identifier(username, ctx)?;
        let email = identifier(email, ctx)?;
        let profile = profile
            .map(UserProfilePatchInput::into_patch)
            .unwrap_or_default();

        let request = request_context(ctx)?;
        ManagementGuard::new(
            ManagementScope::UsersWrite,
            ManagementTarget::user(user, false),
        )
        .check(ctx)
        .await?;
        let user = integration::update_user(
            request,
            UpdateUserCommand {
                user_oid: user,
                username,
                email,
                email_verified,
                required_actions,
                profile,
                expected_version,
                reason,
                client_mutation_id: client_mutation_id.clone(),
            },
        )
        .await
        .map_err(|error| app_error(ctx, error))?;
        Ok(UpdateUserPayload::new(user, client_mutation_id))
    }

    #[graphql(
        guard = "ManagementGuard::new(ManagementScope::UsersWrite, ManagementTarget::instance())",
        directive = access::apply(ManagementGuard::policy(ManagementScope::UsersWrite))
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
            ManagementScope::UsersWrite,
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
        guard = "ManagementGuard::new(ManagementScope::UsersWrite, ManagementTarget::instance())",
        directive = access::apply(ManagementGuard::policy(ManagementScope::UsersWrite))
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
            ManagementScope::UsersWrite,
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
        guard = "ManagementGuard::new(ManagementScope::UsersWrite, ManagementTarget::instance())",
        directive = access::apply(ManagementGuard::policy(ManagementScope::UsersWrite))
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
            ManagementScope::UsersWrite,
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

    /// Replace the user's password with a generated temporary one, require a
    /// change at the next sign-in, and sign the user out everywhere.
    #[graphql(
        guard = "ManagementGuard::new(ManagementScope::UsersWrite, ManagementTarget::instance())",
        directive = access::apply(ManagementGuard::policy(ManagementScope::UsersWrite))
    )]
    async fn reset_user_password(
        &self,
        ctx: &Context<'_>,
        input: UserStateInput,
    ) -> Result<ResetUserPasswordPayload> {
        let UserStateInput {
            id,
            expected_version,
            reason,
            client_mutation_id,
        } = input;
        let (user, reason) = state_fields(ctx, &id, &reason)?;
        let request = request_context(ctx)?;
        ManagementGuard::new(
            ManagementScope::UsersWrite,
            ManagementTarget::user(user, false),
        )
        .check(ctx)
        .await?;
        let (user, temporary_password) = integration::reset_user_password(
            request,
            user,
            expected_version,
            reason,
            client_mutation_id.clone(),
        )
        .await
        .map_err(|error| app_error(ctx, error))?;
        Ok(ResetUserPasswordPayload::new(
            user,
            temporary_password,
            client_mutation_id,
        ))
    }

    /// Remove the user's authenticator app, recovery codes and passkeys, and
    /// sign the user out everywhere. The user keeps the password.
    #[graphql(
        guard = "ManagementGuard::new(ManagementScope::UsersWrite, ManagementTarget::instance())",
        directive = access::apply(ManagementGuard::policy(ManagementScope::UsersWrite))
    )]
    async fn reset_user_mfa(
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
            ManagementScope::UsersWrite,
            ManagementTarget::user(user, false),
        )
        .check(ctx)
        .await?;
        let user = integration::reset_user_mfa(
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

    /// Revoke sessions of the user with the grants issued from them.
    #[graphql(
        guard = "ManagementGuard::new(ManagementScope::UsersWrite, ManagementTarget::instance())",
        directive = access::apply(ManagementGuard::policy(ManagementScope::UsersWrite))
    )]
    async fn revoke_user_sessions(
        &self,
        ctx: &Context<'_>,
        input: RevokeUserSessionsInput,
    ) -> Result<UserStatePayload> {
        let RevokeUserSessionsInput {
            id,
            session_ids,
            reason,
            client_mutation_id,
        } = input;
        let (user, reason) = state_fields(ctx, &id, &reason)?;
        let sessions = session_ids
            .map(|ids| {
                ids.iter()
                    .map(|id| {
                        GlobalId::<SessionGlobalId>::decode(id.as_str())
                            .map(|id| id.oid())
                            .map_err(|_| app_error(ctx, graphql::error::InvalidSessionId))
                    })
                    .collect::<Result<Vec<_>>>()
            })
            .transpose()?;
        let request = request_context(ctx)?;
        ManagementGuard::new(
            ManagementScope::UsersWrite,
            ManagementTarget::user(user, false),
        )
        .check(ctx)
        .await?;
        let user = integration::revoke_user_sessions(
            request,
            user,
            sessions,
            reason,
            client_mutation_id.clone(),
        )
        .await
        .map_err(|error| app_error(ctx, error))?;
        Ok(UserStatePayload::new(user, client_mutation_id))
    }

    /// Delete a disabled user with its credentials, sessions and memberships.
    /// The audit log keeps its history.
    #[graphql(
        guard = "ManagementGuard::new(ManagementScope::UsersWrite, ManagementTarget::instance())",
        directive = access::apply(ManagementGuard::policy(ManagementScope::UsersWrite))
    )]
    async fn delete_user(
        &self,
        ctx: &Context<'_>,
        input: UserStateInput,
    ) -> Result<DeleteUserPayload> {
        let UserStateInput {
            id,
            expected_version,
            reason,
            client_mutation_id,
        } = input;
        let (user, reason) = state_fields(ctx, &id, &reason)?;
        let request = request_context(ctx)?;
        ManagementGuard::new(
            ManagementScope::UsersWrite,
            ManagementTarget::user(user, false),
        )
        .check(ctx)
        .await?;
        let user = integration::delete_user(
            request,
            user,
            expected_version,
            reason,
            client_mutation_id.clone(),
        )
        .await
        .map_err(|error| app_error(ctx, error))?;
        Ok(DeleteUserPayload::new(&user, client_mutation_id))
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
    optional_identifier(value).map_err(|_| app_error(ctx, graphql::error::ValidationFailed))
}

fn reason_or_error(ctx: &Context<'_>, reason: &str) -> Result<String> {
    normalize_reason(reason).ok_or_else(|| app_error(ctx, graphql::error::ValidationFailed))
}
