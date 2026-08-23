use async_graphql::{Context, Object, Result};
use identity_domain::openid_connect::ApiScope;

use super::types::UserNode;
use crate::graphql::schema::authorization::{request_context, require_scope};

#[derive(Default)]
pub(crate) struct AccountViewer;

#[Object]
impl AccountViewer {
    async fn account(&self, ctx: &Context<'_>) -> Result<Option<UserNode>> {
        require_scope(ctx, ApiScope::AccountRead)?;
        Ok(Some(UserNode::from(request_context(ctx)?.user.clone())))
    }
}
