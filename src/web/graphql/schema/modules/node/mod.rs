use std::collections::HashMap;

use crate::graphql::schema::access::{AccessPolicy, access};
use async_graphql::{Context, Guard, ID, Interface, Object, Result};
use identity_application::{
    authorization::ManagementTarget, error::codes::graphql, rbac::ScopeOid,
    user::credential::StoredPasskey,
};
use identity_domain::global_id::DecodedGlobalId;
use identity_domain::{
    audit::AuditEventOid,
    auth::SessionOid,
    authorization::ManagementScope,
    openid_connect::ApiScope,
    rbac::{GroupOid, ResourceOid, RoleOid},
    user::{User, UserOid},
};
use uuid::Uuid;

use super::{
    account::{UserGlobalId, UserNode},
    audit::{AuditEventGlobalId, AuditEventNode, integration as audit_integration},
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
    security::types::{PasskeyGlobalId, PasskeyNode},
    session::{SessionGlobalId, SessionNode},
    user::{
        access::{UserReadAccess, node_user_read_access},
        integration,
    },
};
use crate::graphql::schema::{
    RequestContext,
    authorization::{ScopeGuard, UserPrincipalGuard, request_context},
    error::app_error,
    management_guard::ManagementGuard,
};

const MAX_NODE_IDS: usize = 100;

fn nodes_complexity(count: usize, child_complexity: usize) -> usize {
    1 + count.min(MAX_NODE_IDS) * (1 + child_complexity)
}

#[derive(Default)]
pub(super) struct NodeQuery;

#[Object]
impl NodeQuery {
    #[graphql(directive = access::apply(AccessPolicy::dynamic()))]
    async fn node(&self, ctx: &Context<'_>, id: ID) -> Result<Option<Node>> {
        let mut loader = NodeBatchLoader::default();
        load_node(ctx, &id, &mut loader).await
    }

    #[graphql(
        directive = access::apply(AccessPolicy::dynamic()),
        complexity = "nodes_complexity(ids.len(), child_complexity)"
    )]
    async fn nodes(
        &self,
        ctx: &Context<'_>,
        #[graphql(validator(max_items = 100))] ids: Vec<ID>,
    ) -> Vec<Result<Option<Node>>> {
        let mut loader = NodeBatchLoader::default();
        let mut nodes = Vec::with_capacity(ids.len());
        for id in ids {
            nodes.push(load_node(ctx, &id, &mut loader).await);
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
    Passkey(Box<PasskeyNode>),
    AuditEvent(Box<AuditEventNode>),
}

/// Request-scoped cache shared across all IDs in a single `nodes(ids)` batch
/// so repeated guard transactions, self-account reads, and passkey listings are
/// executed at most once per request.
#[derive(Default)]
struct NodeBatchLoader {
    user_principal: Option<Result<()>>,
    api_scopes: Vec<(ApiScope, Result<()>)>,
    instance_management_scopes: HashMap<ManagementScope, Result<()>>,
    user_read_access: HashMap<UserOid, Result<UserReadAccess>>,
    self_user: Option<Result<Option<User>>>,
    passkeys: Option<Result<Vec<StoredPasskey>>>,
}

impl NodeBatchLoader {
    async fn check_user_principal(&mut self, ctx: &Context<'_>) -> Result<()> {
        if let Some(cached) = &self.user_principal {
            return cached.clone();
        }
        let res = UserPrincipalGuard.check(ctx).await;
        self.user_principal = Some(res.clone());
        res
    }

    async fn check_scope(&mut self, ctx: &Context<'_>, scope: ApiScope) -> Result<()> {
        if let Some((_, cached)) = self.api_scopes.iter().find(|(s, _)| *s == scope) {
            return cached.clone();
        }
        let res = ScopeGuard::new(scope).check(ctx).await;
        self.api_scopes.push((scope, res.clone()));
        res
    }

    async fn check_instance_management(
        &mut self,
        ctx: &Context<'_>,
        scope: ManagementScope,
    ) -> Result<()> {
        if let Some(cached) = self.instance_management_scopes.get(&scope) {
            return cached.clone();
        }
        let res = ManagementGuard::new(scope, ManagementTarget::instance())
            .check(ctx)
            .await;
        self.instance_management_scopes.insert(scope, res.clone());
        res
    }

    async fn user_read_access(
        &mut self,
        ctx: &Context<'_>,
        target: UserOid,
    ) -> Result<UserReadAccess> {
        if let Some(cached) = self.user_read_access.get(&target) {
            return cached.clone();
        }
        let res = node_user_read_access(ctx, target).await;
        self.user_read_access.insert(target, res.clone());
        res
    }

    async fn load_self_user(
        &mut self,
        ctx: &Context<'_>,
        request: &RequestContext,
    ) -> Result<Option<User>> {
        if let Some(cached) = &self.self_user {
            return cached.clone();
        }
        let user_oid = request.user_oid()?;
        let res = request
            .state
            .services()
            .account()
            .find_user(user_oid)
            .await
            .map_err(|error| app_error(ctx, error));
        self.self_user = Some(res.clone());
        res
    }

    async fn find_passkey(
        &mut self,
        ctx: &Context<'_>,
        request: &RequestContext,
        oid: Uuid,
    ) -> Result<Option<StoredPasskey>> {
        let passkeys = if let Some(cached) = &self.passkeys {
            cached.clone()?
        } else {
            let user_oid = request.user_oid()?;
            let res = request
                .state
                .services()
                .passkey()
                .list(user_oid)
                .await
                .map_err(|error| app_error(ctx, error));
            self.passkeys = Some(res.clone());
            res?
        };
        Ok(passkeys.into_iter().find(|passkey| passkey.id == oid))
    }
}

async fn load_node(
    ctx: &Context<'_>,
    id: &ID,
    loader: &mut NodeBatchLoader,
) -> Result<Option<Node>> {
    let request = request_context(ctx)?;
    let decoded = DecodedGlobalId::decode(id.as_str())
        .map_err(|_| app_error(ctx, graphql::error::InvalidGlobalId))?;
    if decoded.is::<UserGlobalId>() {
        let oid = decoded
            .into_typed::<UserGlobalId>()
            .map_err(|_| app_error(ctx, graphql::error::InvalidGlobalId))?
            .oid();
        let target = UserOid(oid);
        match loader.user_read_access(ctx, target).await? {
            UserReadAccess::Management => {
                let record = integration::find_user(request, target)
                    .await
                    .map_err(|error| app_error(ctx, error))?;
                Ok(record.map(UserNode::managed).map(Box::new).map(Node::from))
            }
            UserReadAccess::SelfOnly => {
                let user = loader.load_self_user(ctx, request).await?;
                Ok(user.map(UserNode::from).map(Box::new).map(Node::from))
            }
        }
    } else if decoded.is::<SessionGlobalId>() {
        let oid = decoded
            .into_typed::<SessionGlobalId>()
            .map_err(|_| app_error(ctx, graphql::error::InvalidGlobalId))?
            .oid();
        loader.check_user_principal(ctx).await?;
        loader.check_scope(ctx, ApiScope::SessionRead).await?;
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
            .map_err(|_| app_error(ctx, graphql::error::InvalidGlobalId))?
            .oid();
        loader
            .check_instance_management(ctx, ManagementScope::ResourcesRead)
            .await?;
        let record = resource_integration::find_resource(request, ResourceOid(oid))
            .await
            .map_err(|error| app_error(ctx, error))?;
        Ok(record.map(ResourceNode::new).map(Box::new).map(Node::from))
    } else if decoded.is::<ScopeGlobalId>() {
        let oid = decoded
            .into_typed::<ScopeGlobalId>()
            .map_err(|_| app_error(ctx, graphql::error::InvalidGlobalId))?
            .oid();
        loader
            .check_instance_management(ctx, ManagementScope::ScopesRead)
            .await?;
        let record = scope_integration::find_scope(request, ScopeOid(oid))
            .await
            .map_err(|error| app_error(ctx, error))?;
        Ok(record.map(ScopeNode::new).map(Box::new).map(Node::from))
    } else if decoded.is::<RoleGlobalId>() {
        let oid = decoded
            .into_typed::<RoleGlobalId>()
            .map_err(|_| app_error(ctx, graphql::error::InvalidGlobalId))?
            .oid();
        loader
            .check_instance_management(ctx, ManagementScope::RolesRead)
            .await?;
        let record = role_integration::find_role(request, RoleOid(oid))
            .await
            .map_err(|error| app_error(ctx, error))?;
        Ok(record.map(RoleNode::new).map(Box::new).map(Node::from))
    } else if decoded.is::<ClientGlobalId>() {
        let oid = decoded
            .into_typed::<ClientGlobalId>()
            .map_err(|_| app_error(ctx, graphql::error::InvalidGlobalId))?
            .oid();
        loader
            .check_instance_management(ctx, ManagementScope::ClientsRead)
            .await?;
        let record = client_integration::find_client(request, oid)
            .await
            .map_err(|error| app_error(ctx, error))?;
        Ok(record.map(ClientNode::new).map(Box::new).map(Node::from))
    } else if decoded.is::<GroupGlobalId>() {
        let oid = decoded
            .into_typed::<GroupGlobalId>()
            .map_err(|_| app_error(ctx, graphql::error::InvalidGlobalId))?
            .oid();
        loader
            .check_instance_management(ctx, ManagementScope::GroupsRead)
            .await?;
        let record = group_integration::find_group(request, GroupOid(oid))
            .await
            .map_err(|error| app_error(ctx, error))?;
        Ok(record.map(GroupNode::new).map(Box::new).map(Node::from))
    } else if decoded.is::<PasskeyGlobalId>() {
        let oid = decoded
            .into_typed::<PasskeyGlobalId>()
            .map_err(|_| app_error(ctx, graphql::error::InvalidGlobalId))?
            .oid();
        loader.check_user_principal(ctx).await?;
        loader.check_scope(ctx, ApiScope::UserRead).await?;
        let passkey = loader.find_passkey(ctx, request, oid).await?;
        Ok(passkey.map(PasskeyNode::from).map(Box::new).map(Node::from))
    } else if decoded.is::<AuditEventGlobalId>() {
        let oid = decoded
            .into_typed::<AuditEventGlobalId>()
            .map_err(|_| app_error(ctx, graphql::error::InvalidGlobalId))?
            .oid();
        loader
            .check_instance_management(ctx, ManagementScope::AuditRead)
            .await?;
        let event = audit_integration::find_event(request, AuditEventOid::from_uuid(oid))
            .await
            .map_err(|error| app_error(ctx, error))?;
        Ok(event.map(AuditEventNode::new).map(Box::new).map(Node::from))
    } else {
        Err(app_error(ctx, graphql::error::UnsupportedNodeType))
    }
}

#[cfg(test)]
mod tests {
    use async_graphql::Request;

    use super::{MAX_NODE_IDS, nodes_complexity};
    use crate::graphql::schema::build_schema;

    #[test]
    fn nodes_complexity_scales_with_count_and_caps_at_limit() {
        assert_eq!(nodes_complexity(0, 4), 1);
        assert_eq!(nodes_complexity(10, 4), 51);
        assert_eq!(nodes_complexity(MAX_NODE_IDS, 4), 501);
        assert_eq!(nodes_complexity(MAX_NODE_IDS + 50, 4), 501);
    }

    #[tokio::test]
    async fn schema_rejects_large_nodes_batches_exceeding_complexity_budget() {
        use identity_application::error::{
            code::AppErrorCode, codes::graphql_transport::GraphqlTransportErrorCode,
        };

        let too_complex_code = async_graphql::Value::from(i64::from(
            GraphqlTransportErrorCode::QueryTooComplex.code(),
        ));
        let schema = build_schema(16, 20);
        let ids = (0..10)
            .map(|i| format!("\"id-{i}\""))
            .collect::<Vec<_>>()
            .join(", ");
        let query =
            format!("query {{ nodes(ids: [{ids}]) {{ id ... on User {{ username email }} }} }}");
        let response = schema.execute(Request::new(query)).await;
        assert!(
            response.errors.iter().any(|err| {
                err.extensions.as_ref().and_then(|ext| ext.get("code")) == Some(&too_complex_code)
            }),
            "expected QueryTooComplex error, got: {:?}",
            response.errors
        );

        let single = schema
            .execute(Request::new(
                "query { nodes(ids: [\"id-0\"]) { id ... on User { username email } } }",
            ))
            .await;
        assert!(
            !single.errors.iter().any(|err| {
                err.extensions.as_ref().and_then(|ext| ext.get("code")) == Some(&too_complex_code)
            }),
            "single-id nodes query should fit complexity budget: {:?}",
            single.errors
        );
    }
}
