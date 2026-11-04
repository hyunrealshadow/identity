//! Relationship facts carried on connection edges.
//!
//! User roles, group roles and group members are relations, not addressable
//! objects. Their facts sit on the edge whose node is the related entity, so a
//! client reads `user.roles` or `group.members` instead of a separate
//! relationship type. Mutations address a relation by its two endpoints.

use std::collections::HashMap;

use async_graphql::{
    Context, Object, OutputType, Result, SimpleObject,
    connection::{Connection, ConnectionNameType, EdgeNameType},
};
use chrono::{DateTime, Utc};
use identity_application::authorization::ManagementTarget;
use identity_domain::{authorization::ManagementScope, user::UserOid};
use uuid::Uuid;

use super::{
    account::UserNode, resource::support::RbacConnectionCursor,
    user::integration as user_integration,
};
use crate::graphql::schema::{
    access::access, authorization::request_context, error::app_error,
    management_guard::ManagementGuard,
};

/// Facts of one relation, flattened into its edge.
pub(crate) struct RelationFacts {
    pub granted_by_user_oid: Option<UserOid>,
    pub reason: String,
    pub enabled: bool,
    pub revoked_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub updated_at: Option<DateTime<Utc>>,
}

#[Object]
impl RelationFacts {
    /// Whether the relation is active. Revoked relations remain as history.
    #[graphql(complexity = 0)]
    async fn enabled(&self) -> bool {
        self.enabled
    }

    #[graphql(complexity = 0)]
    async fn revoked_at(&self) -> Option<DateTime<Utc>> {
        self.revoked_at
    }

    #[graphql(complexity = 0)]
    async fn reason(&self) -> &str {
        &self.reason
    }

    /// When the relation was granted.
    #[graphql(complexity = 0)]
    async fn created_at(&self) -> DateTime<Utc> {
        self.created_at
    }

    #[graphql(complexity = 0)]
    async fn updated_at(&self) -> Option<DateTime<Utc>> {
        self.updated_at
    }

    /// The user who granted the relation, when one was recorded and still
    /// exists.
    #[graphql(
        guard = "ManagementGuard::new(ManagementScope::UsersRead, ManagementTarget::instance())",
        directive = access::apply(ManagementGuard::policy(ManagementScope::UsersRead))
    )]
    async fn granted_by(&self, ctx: &Context<'_>) -> Result<Option<UserNode>> {
        let Some(user_oid) = self.granted_by_user_oid else {
            return Ok(None);
        };
        let user = user_integration::find_user(request_context(ctx)?, user_oid)
            .await
            .map_err(|error| app_error(ctx, error))?;
        Ok(user.map(UserNode::managed))
    }
}

/// Connection whose edges carry relation facts and point at the related node.
pub(crate) type RelationConnection<Node, Fields, Name, EdgeName> =
    Connection<RbacConnectionCursor, Node, Fields, RelationFacts, Name, EdgeName>;

/// Current version of the single parent whose relations a connection lists.
/// Callers pass it as the expected version when changing those relations.
#[derive(SimpleObject)]
pub(crate) struct UserVersionFields {
    pub user_version: Uuid,
}

macro_rules! relation_names {
    ($($connection:ident, $edge:ident => $name:literal;)*) => {
        $(
            pub(crate) struct $connection;

            impl ConnectionNameType for $connection {
                fn type_name<T: OutputType>() -> String {
                    concat!($name, "Connection").to_owned()
                }
            }

            pub(crate) struct $edge;

            impl EdgeNameType for $edge {
                fn type_name<T: OutputType>() -> String {
                    concat!($name, "Edge").to_owned()
                }
            }
        )*
    };
}

relation_names! {
    UserRoleConnectionName, UserRoleEdgeName => "UserRole";
    RoleUserConnectionName, RoleUserEdgeName => "RoleUser";
    GroupRoleConnectionName, GroupRoleEdgeName => "GroupRole";
    GroupMemberConnectionName, GroupMemberEdgeName => "GroupMember";
}

/// Index one page of related nodes by OID. Edges whose node vanished
/// concurrently are skipped rather than reported as empty nodes.
pub(crate) fn index_by<K, V>(values: Vec<V>, key: impl Fn(&V) -> K) -> HashMap<K, V>
where
    K: std::hash::Hash + Eq,
{
    values
        .into_iter()
        .map(|value| (key(&value), value))
        .collect()
}
