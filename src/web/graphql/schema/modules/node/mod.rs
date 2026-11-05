use crate::graphql::schema::access::{AccessPolicy, access};
use async_graphql::{Context, Guard, ID, Interface, Object, Result};
use identity_application::{
    authorization::ManagementTarget,
    error::{codes::graphql::GraphqlErrorCode, params::ErrorParams},
    rbac::ScopeOid,
};
use identity_domain::{
    auth::SessionOid,
    authorization::ManagementScope,
    openid_connect::ApiScope,
    rbac::{GroupOid, ResourceOid, RoleOid},
    user::UserOid,
};
use identity_infrastructure::graphql::id::DecodedGlobalId;
use uuid::Uuid;

use super::{
    account::{UserGlobalId, UserNode},
    client::{
        integration as client_integration,
        types::{ClientGlobalId, ClientNode},
    },
    group::{
        integration as group_integration,
        types::{GroupGlobalId, GroupNode},
    },
    resource::{
        integration as resource_integration,
        types::{ResourceGlobalId, ResourceNode},
    },
    role::{
        integration as role_integration,
        types::{RoleGlobalId, RoleNode},
    },
    scope::{
        integration as scope_integration,
        types::{ScopeGlobalId, ScopeNode},
    },
    session::{SessionGlobalId, SessionNode},
    user::{
        access::{UserReadAccess, node_user_read_access},
        integration,
    },
};
use crate::graphql::schema::{
    authorization::{ScopeGuard, UserPrincipalGuard, request_context},
    error::{app_error, coded_error},
    management_guard::ManagementGuard,
};

#[derive(Default)]
pub(super) struct NodeQuery;

#[Object]
impl NodeQuery {
    #[graphql(directive = access::apply(AccessPolicy::dynamic()))]
    async fn node(&self, ctx: &Context<'_>, id: ID) -> Result<Option<Node>> {
        load_node(ctx, &id).await
    }

    #[graphql(directive = access::apply(AccessPolicy::dynamic()))]
    async fn nodes(
        &self,
        ctx: &Context<'_>,
        #[graphql(validator(max_items = 100))] ids: Vec<ID>,
    ) -> Vec<Result<Option<Node>>> {
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
    Resource(Box<ResourceNode>),
    Scope(Box<ScopeNode>),
    Role(Box<RoleNode>),
    Group(Box<GroupNode>),
    Client(Box<ClientNode>),
}

async fn load_node(ctx: &Context<'_>, id: &ID) -> Result<Option<Node>> {
    let request = request_context(ctx)?;
    let decoded = DecodedGlobalId::try_from(id)
        .map_err(|_| coded_error(ctx, GraphqlErrorCode::InvalidGlobalId, ErrorParams::new()))?;
    if decoded.is::<UserGlobalId>() {
        let oid = decoded
            .into_typed::<UserGlobalId>()
            .map_err(|_| coded_error(ctx, GraphqlErrorCode::InvalidGlobalId, ErrorParams::new()))?
            .oid();
        let target = UserOid(oid);
        match node_user_read_access(ctx, target).await? {
            UserReadAccess::Management => {
                let record = integration::find_user(request, target)
                    .await
                    .map_err(|error| app_error(ctx, error))?;
                Ok(record.map(UserNode::managed).map(Box::new).map(Node::from))
            }
            UserReadAccess::SelfOnly => {
                let user = request
                    .state
                    .services()
                    .account()
                    .find_user(request.user_oid()?)
                    .await
                    .map_err(|error| app_error(ctx, error))?;
                Ok(user.map(UserNode::from).map(Box::new).map(Node::from))
            }
        }
    } else if decoded.is::<SessionGlobalId>() {
        let oid = decoded
            .into_typed::<SessionGlobalId>()
            .map_err(|_| coded_error(ctx, GraphqlErrorCode::InvalidGlobalId, ErrorParams::new()))?
            .oid();
        UserPrincipalGuard.check(ctx).await?;
        ScopeGuard::new(ApiScope::SessionRead).check(ctx).await?;
        let session = request
            .state
            .services()
            .session()
            .find_owned(SessionOid(oid), Uuid::from(request.user_oid()?))
            .await
            .map_err(|error| app_error(ctx, error))?;
        Ok(session
            .map(|session| SessionNode::new(session, request.claims.session_oid))
            .map(Box::new)
            .map(Node::from))
    } else if decoded.is::<ResourceGlobalId>() {
        let oid = decoded
            .into_typed::<ResourceGlobalId>()
            .map_err(|_| coded_error(ctx, GraphqlErrorCode::InvalidGlobalId, ErrorParams::new()))?
            .oid();
        ManagementGuard::new(ManagementScope::ResourcesRead, ManagementTarget::instance())
            .check(ctx)
            .await?;
        let record = resource_integration::find_resource(request, ResourceOid(oid))
            .await
            .map_err(|error| app_error(ctx, error))?;
        Ok(record.map(ResourceNode::new).map(Box::new).map(Node::from))
    } else if decoded.is::<ScopeGlobalId>() {
        let oid = decoded
            .into_typed::<ScopeGlobalId>()
            .map_err(|_| coded_error(ctx, GraphqlErrorCode::InvalidGlobalId, ErrorParams::new()))?
            .oid();
        ManagementGuard::new(ManagementScope::ScopesRead, ManagementTarget::instance())
            .check(ctx)
            .await?;
        let record = scope_integration::find_scope(request, ScopeOid(oid))
            .await
            .map_err(|error| app_error(ctx, error))?;
        Ok(record.map(ScopeNode::new).map(Box::new).map(Node::from))
    } else if decoded.is::<RoleGlobalId>() {
        let oid = decoded
            .into_typed::<RoleGlobalId>()
            .map_err(|_| coded_error(ctx, GraphqlErrorCode::InvalidGlobalId, ErrorParams::new()))?
            .oid();
        ManagementGuard::new(ManagementScope::RolesRead, ManagementTarget::instance())
            .check(ctx)
            .await?;
        let record = role_integration::find_role(request, RoleOid(oid))
            .await
            .map_err(|error| app_error(ctx, error))?;
        Ok(record.map(RoleNode::new).map(Box::new).map(Node::from))
    } else if decoded.is::<ClientGlobalId>() {
        let oid = decoded
            .into_typed::<ClientGlobalId>()
            .map_err(|_| coded_error(ctx, GraphqlErrorCode::InvalidGlobalId, ErrorParams::new()))?
            .oid();
        ManagementGuard::new(ManagementScope::ClientsRead, ManagementTarget::instance())
            .check(ctx)
            .await?;
        let record = client_integration::find_client(request, oid)
            .await
            .map_err(|error| app_error(ctx, error))?;
        Ok(record.map(ClientNode::new).map(Box::new).map(Node::from))
    } else if decoded.is::<GroupGlobalId>() {
        let oid = decoded
            .into_typed::<GroupGlobalId>()
            .map_err(|_| coded_error(ctx, GraphqlErrorCode::InvalidGlobalId, ErrorParams::new()))?
            .oid();
        ManagementGuard::new(ManagementScope::GroupsRead, ManagementTarget::instance())
            .check(ctx)
            .await?;
        let record = group_integration::find_group(request, GroupOid(oid))
            .await
            .map_err(|error| app_error(ctx, error))?;
        Ok(record.map(GroupNode::new).map(Box::new).map(Node::from))
    } else {
        Err(coded_error(
            ctx,
            GraphqlErrorCode::UnsupportedNodeType,
            ErrorParams::new(),
        ))
    }
}
