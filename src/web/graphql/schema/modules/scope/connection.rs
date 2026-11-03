use super::{super::resource::support::RbacConnectionCursor, types::ScopeNode};
use async_graphql::{
    Object,
    connection::{CursorType, PageInfo},
};

/// Scope rows are already loaded by the collection resolver. Charge each row
/// once; in-memory projections and page metadata do not repeat database work.
/// Scope relations retain their own costs, multiplied by the parent page size.
pub(crate) struct ScopeConnection {
    pub edges: Vec<ScopeEdge>,
    has_previous_page: bool,
    has_next_page: bool,
    total_count: u64,
}

impl ScopeConnection {
    pub(crate) fn new(has_previous_page: bool, has_next_page: bool, total_count: u64) -> Self {
        Self {
            edges: Vec::new(),
            has_previous_page,
            has_next_page,
            total_count,
        }
    }
}

#[Object]
impl ScopeConnection {
    /// Information to aid in pagination.
    #[graphql(complexity = 0)]
    async fn page_info(&self) -> PageInfo {
        PageInfo {
            has_previous_page: self.has_previous_page,
            has_next_page: self.has_next_page,
            start_cursor: self.edges.first().map(|edge| edge.cursor.encode_cursor()),
            end_cursor: self.edges.last().map(|edge| edge.cursor.encode_cursor()),
        }
    }

    /// A list of edges.
    #[graphql(complexity = "child_complexity")]
    async fn edges(&self) -> &[ScopeEdge] {
        &self.edges
    }

    /// A list of nodes.
    #[graphql(complexity = "child_complexity")]
    async fn nodes(&self) -> Vec<&ScopeNode> {
        self.edges.iter().map(|edge| &edge.node).collect()
    }

    #[graphql(complexity = 0)]
    async fn total_count(&self) -> u64 {
        self.total_count
    }
}

pub(crate) struct ScopeEdge {
    cursor: RbacConnectionCursor,
    node: ScopeNode,
}

impl ScopeEdge {
    pub(crate) fn new(cursor: RbacConnectionCursor, node: ScopeNode) -> Self {
        Self { cursor, node }
    }
}

#[Object]
impl ScopeEdge {
    /// The item at the end of the edge
    #[graphql(complexity = "child_complexity")]
    async fn node(&self) -> &ScopeNode {
        &self.node
    }

    /// A cursor for use in pagination
    #[graphql(complexity = 0)]
    async fn cursor(&self) -> String {
        self.cursor.encode_cursor()
    }
}

#[cfg(test)]
mod tests;
