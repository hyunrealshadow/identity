use async_graphql::{Context, Error, Object, Result};
use identity_domain::openid_connect::ApiScope;
use identity_infrastructure::database::repository::user::UserRepositoryImpl;

use super::{
    types::{
        UpdateEmailInput, UpdateProfileInput, UpdateProfilePayload, UpdateUsernameInput, UserNode,
    },
    validation::{account_repository_error, validate_email, validate_username},
};
use crate::graphql::schema::{
    authorization::{request_context, require_recent_authentication, require_scope},
    error::{app_error, internal_error},
};

#[derive(Default)]
pub(crate) struct AccountMutation;

#[Object]
impl AccountMutation {
    async fn update_username(
        &self,
        ctx: &Context<'_>,
        input: UpdateUsernameInput,
    ) -> Result<UpdateProfilePayload> {
        require_scope(ctx, ApiScope::AccountUpdate)?;
        require_recent_authentication(ctx, None)?;
        let request = request_context(ctx)?;
        let patch = validate_username(&input).map_err(|error| app_error(ctx, error))?;
        let repo = UserRepositoryImpl::new(request.state.resources().db().clone());
        let user = repo
            .update_identifier(request.claims.user_oid, patch)
            .await
            .map_err(|error| account_repository_error(ctx, error))?
            .ok_or_else(|| Error::new("account not found"))?;
        Ok(UpdateProfilePayload::new(
            UserNode::from(user),
            input.client_mutation_id,
        ))
    }

    async fn update_email(
        &self,
        ctx: &Context<'_>,
        input: UpdateEmailInput,
    ) -> Result<UpdateProfilePayload> {
        require_scope(ctx, ApiScope::AccountUpdate)?;
        require_recent_authentication(ctx, None)?;
        let request = request_context(ctx)?;
        let patch = validate_email(&input).map_err(|error| app_error(ctx, error))?;
        let repo = UserRepositoryImpl::new(request.state.resources().db().clone());
        let user = repo
            .update_identifier(request.claims.user_oid, patch)
            .await
            .map_err(|error| account_repository_error(ctx, error))?
            .ok_or_else(|| Error::new("account not found"))?;
        Ok(UpdateProfilePayload::new(
            UserNode::from(user),
            input.client_mutation_id,
        ))
    }

    async fn update_profile(
        &self,
        ctx: &Context<'_>,
        input: UpdateProfileInput,
    ) -> Result<UpdateProfilePayload> {
        require_scope(ctx, ApiScope::AccountUpdate)?;
        let request = request_context(ctx)?;
        let repo = UserRepositoryImpl::new(request.state.resources().db().clone());
        let user = repo
            .update_profile(request.claims.user_oid, input.clone().into_patch())
            .await
            .map_err(internal_error)?
            .ok_or_else(|| Error::new("account not found"))?;
        Ok(UpdateProfilePayload::new(
            UserNode::from(user),
            input.client_mutation_id,
        ))
    }
}
