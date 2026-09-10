use async_graphql::{Context, Error, ID, Interface, Object, Result};
use identity_domain::{auth::SessionOid, openid_connect::ApiScope};
use identity_infrastructure::graphql::id::DecodedGlobalId;
use uuid::Uuid;

use super::{
    account::{UserGlobalId, UserNode},
    session::{SessionGlobalId, SessionNode},
};
use crate::graphql::schema::{
    authorization::{request_context, require_scope},
    error::app_error,
};

#[derive(Default)]
pub(super) struct NodeQuery;

#[Object]
impl NodeQuery {
    async fn node(&self, ctx: &Context<'_>, id: ID) -> Result<Option<Node>> {
        load_node(ctx, &id).await
    }

    async fn nodes(&self, ctx: &Context<'_>, ids: Vec<ID>) -> Vec<Result<Option<Node>>> {
        let mut nodes = Vec::with_capacity(ids.len());
        for id in ids {
            nodes.push(load_node(ctx, &id).await);
        }
        nodes
    }
}

#[derive(Interface)]
#[graphql(field(name = "id", ty = "&ID"))]
enum Node {
    User(Box<UserNode>),
    Session(Box<SessionNode>),
}

async fn load_node(ctx: &Context<'_>, id: &ID) -> Result<Option<Node>> {
    let request = request_context(ctx)?;
    let decoded = DecodedGlobalId::try_from(id).map_err(|_| Error::new("invalid node id"))?;
    if decoded.is::<UserGlobalId>() {
        let oid = decoded
            .into_typed::<UserGlobalId>()
            .map_err(|_| Error::new("invalid node id"))?
            .oid();
        require_scope(ctx, ApiScope::AccountRead)?;
        if oid != Uuid::from(request.claims.user_oid) {
            return Ok(None);
        }
        let user = request
            .state
            .services()
            .account()
            .find_user(request.claims.user_oid)
            .await
            .map_err(|error| app_error(ctx, error))?;
        Ok(user.map(UserNode::from).map(Box::new).map(Node::from))
    } else if decoded.is::<SessionGlobalId>() {
        let oid = decoded
            .into_typed::<SessionGlobalId>()
            .map_err(|_| Error::new("invalid node id"))?
            .oid();
        require_scope(ctx, ApiScope::SessionRead)?;
        let session = request
            .state
            .services()
            .session()
            .find_owned(SessionOid(oid), Uuid::from(request.claims.user_oid))
            .await
            .map_err(|error| app_error(ctx, error))?;
        Ok(session
            .map(|session| SessionNode::new(session, request.claims.session_oid))
            .map(Box::new)
            .map(Node::from))
    } else {
        Err(Error::new("invalid node id"))
    }
}
