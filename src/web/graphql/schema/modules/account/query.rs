use crate::graphql::schema::access::access;
use async_graphql::{Context, Object, Result};
use identity_domain::openid_connect::ApiScope;

use super::types::UserNode;
use crate::graphql::schema::authorization::{ScopeGuard, UserPrincipalGuard, request_context};

#[derive(Default)]
pub(crate) struct AccountQuery;

#[Object]
impl AccountQuery {
    #[graphql(guard = "UserPrincipalGuard.and(ScopeGuard::new(ApiScope::AccountRead))",
        directive = access::apply(ScopeGuard::policy(ApiScope::AccountRead)))]
    async fn account(&self, ctx: &Context<'_>) -> Result<Option<UserNode>> {
        Ok(Some(UserNode::from(request_context(ctx)?.user()?.clone())))
    }
}
