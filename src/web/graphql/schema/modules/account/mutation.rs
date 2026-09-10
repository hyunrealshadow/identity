use async_graphql::{Context, Object, Result};
use identity_domain::openid_connect::ApiScope;

use super::types::{
    UpdateEmailInput, UpdateProfileInput, UpdateProfilePayload, UpdateUsernameInput, UserNode,
};
use crate::graphql::schema::{
    authorization::{request_context, require_recent_authentication, require_scope},
    error::app_error,
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
        let user = request
            .state
            .services()
            .account()
            .update_username(request.claims.user_oid, &input.username)
            .await
            .map_err(|error| app_error(ctx, error))?;
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
        let user = request
            .state
            .services()
            .account()
            .update_email(request.claims.user_oid, &input.email)
            .await
            .map_err(|error| app_error(ctx, error))?;
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
        let user = request
            .state
            .services()
            .account()
            .update_profile(request.claims.user_oid, input.clone().into_patch()?)
            .await
            .map_err(|error| app_error(ctx, error))?;
        Ok(UpdateProfilePayload::new(
            UserNode::from(user),
            input.client_mutation_id,
        ))
    }
}
