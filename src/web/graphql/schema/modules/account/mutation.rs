use crate::graphql::schema::access::access;
use async_graphql::{Context, Object, Result};
use identity_application::error::{codes::graphql::GraphqlErrorCode, params::ErrorParams};
use identity_domain::openid_connect::ApiScope;

use super::types::{
    UpdateEmailInput, UpdateProfileInput, UpdateProfilePayload, UpdateUsernameInput, UserNode,
};
use crate::graphql::schema::{
    authorization::{RecentAuthenticationGuard, ScopeGuard, UserPrincipalGuard, request_context},
    error::{app_error, coded_error},
};

#[derive(Default)]
pub(crate) struct AccountMutation;

#[Object]
impl AccountMutation {
    #[graphql(
        guard = "UserPrincipalGuard.and(ScopeGuard::new(ApiScope::AccountUpdate)).and(RecentAuthenticationGuard::new())",
        directive = access::apply(ScopeGuard::policy(ApiScope::AccountUpdate)),
        directive = access::apply(RecentAuthenticationGuard::new().policy())
    )]
    async fn update_username(
        &self,
        ctx: &Context<'_>,
        input: UpdateUsernameInput,
    ) -> Result<UpdateProfilePayload> {
        let request = request_context(ctx)?;
        let user = request
            .state
            .services()
            .account()
            .update_username(request.user_oid()?, &input.username)
            .await
            .map_err(|error| app_error(ctx, error))?;
        Ok(UpdateProfilePayload::new(
            UserNode::from(user),
            input.client_mutation_id,
        ))
    }

    #[graphql(
        guard = "UserPrincipalGuard.and(ScopeGuard::new(ApiScope::AccountUpdate)).and(RecentAuthenticationGuard::new())",
        directive = access::apply(ScopeGuard::policy(ApiScope::AccountUpdate)),
        directive = access::apply(RecentAuthenticationGuard::new().policy())
    )]
    async fn update_email(
        &self,
        ctx: &Context<'_>,
        input: UpdateEmailInput,
    ) -> Result<UpdateProfilePayload> {
        let request = request_context(ctx)?;
        let user = request
            .state
            .services()
            .account()
            .update_email(request.user_oid()?, &input.email)
            .await
            .map_err(|error| app_error(ctx, error))?;
        Ok(UpdateProfilePayload::new(
            UserNode::from(user),
            input.client_mutation_id,
        ))
    }

    #[graphql(guard = "UserPrincipalGuard.and(ScopeGuard::new(ApiScope::AccountUpdate))",
        directive = access::apply(ScopeGuard::policy(ApiScope::AccountUpdate)))]
    async fn update_profile(
        &self,
        ctx: &Context<'_>,
        input: UpdateProfileInput,
    ) -> Result<UpdateProfilePayload> {
        let patch = input
            .clone()
            .into_patch()
            .map_err(|()| coded_error(ctx, GraphqlErrorCode::InvalidTheme, ErrorParams::new()))?;
        let request = request_context(ctx)?;
        let user = request
            .state
            .services()
            .account()
            .update_profile(request.user_oid()?, patch)
            .await
            .map_err(|error| app_error(ctx, error))?;
        Ok(UpdateProfilePayload::new(
            UserNode::from(user),
            input.client_mutation_id,
        ))
    }
}
