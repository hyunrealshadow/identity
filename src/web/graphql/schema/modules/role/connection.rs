use super::{
    super::resource::support::RbacConnectionCursor,
    binding::{EffectivePermissionNode, EffectivePermissionVersionGuard},
};
use crate::graphql::schema::access::{AccessPolicy, access};
use async_graphql::{
    Object,
    connection::{CursorType, PageInfo},
};
use uuid::Uuid;

/// Charge loaded permission rows once, while nested relationship reads keep their own costs.
pub(crate) struct EffectivePermissionConnection {
    pub edges: Vec<EffectivePermissionEdge>,
    has_previous_page: bool,
    has_next_page: bool,
    user_version: Uuid,
    total_count: u64,
}
impl EffectivePermissionConnection {
    pub(crate) fn new(
        has_previous_page: bool,
        has_next_page: bool,
        user_version: Uuid,
        total_count: u64,
    ) -> Self {
        Self {
            edges: Vec::new(),
            has_previous_page,
            has_next_page,
            user_version,
            total_count,
        }
    }
}
#[Object]
impl EffectivePermissionConnection {
    #[graphql(complexity = 0)]
    async fn page_info(&self) -> PageInfo {
        PageInfo {
            has_previous_page: self.has_previous_page,
            has_next_page: self.has_next_page,
            start_cursor: self.edges.first().map(|edge| edge.cursor.encode_cursor()),
            end_cursor: self.edges.last().map(|edge| edge.cursor.encode_cursor()),
        }
    }
    #[graphql(complexity = "child_complexity")]
    async fn edges(&self) -> &[EffectivePermissionEdge] {
        &self.edges
    }
    #[graphql(complexity = "child_complexity")]
    async fn nodes(&self) -> Vec<&EffectivePermissionNode> {
        self.edges.iter().map(|edge| &edge.node).collect()
    }
    #[graphql(complexity = 0, guard = "EffectivePermissionVersionGuard", directive = access::apply(AccessPolicy::dynamic()))]
    async fn user_version(&self) -> Uuid {
        self.user_version
    }
    #[graphql(complexity = 0, guard = "EffectivePermissionVersionGuard", directive = access::apply(AccessPolicy::dynamic()))]
    async fn total_count(&self) -> u64 {
        self.total_count
    }
}
pub(crate) struct EffectivePermissionEdge {
    cursor: RbacConnectionCursor,
    node: EffectivePermissionNode,
}
impl EffectivePermissionEdge {
    pub(crate) fn new(cursor: RbacConnectionCursor, node: EffectivePermissionNode) -> Self {
        Self { cursor, node }
    }
}
#[Object]
impl EffectivePermissionEdge {
    #[graphql(complexity = 0)]
    async fn cursor(&self) -> String {
        self.cursor.encode_cursor()
    }
    #[graphql(complexity = "child_complexity")]
    async fn node(&self) -> &EffectivePermissionNode {
        &self.node
    }
}
