use std::error::Error as StdError;

use async_trait::async_trait;

use super::{
    model::{AuditEvent, AuditEventOid, AuditEventOrder, AuditEventSortKey},
    query::AuditQueryExpr,
};
use crate::pagination::PageDirection;

/// Cursor traversal direction for Relay pagination.
pub type AuditEventPageDirection = PageDirection;

/// Repository query parameters for one page of security audit events.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditEventQuery {
    pub expr: AuditQueryExpr,
    pub order: AuditEventOrder,
    pub direction: AuditEventPageDirection,
    pub cursor: Option<AuditEventSortKey>,
    pub limit: usize,
}

/// Internal repository page item bundling a domain audit event with its keyset sort key.
#[derive(Debug, Clone, PartialEq)]
pub struct AuditEventRecord {
    pub event: AuditEvent,
    pub sort_key: AuditEventSortKey,
}

/// Repository page result preserving bidirectional cursor edge flags.
#[derive(Debug, Clone, PartialEq)]
pub struct AuditEventPage {
    pub items: Vec<AuditEventRecord>,
    pub has_previous_page: bool,
    pub has_next_page: bool,
}

/// Infrastructure-agnostic errors for reading security audit events.
#[derive(Debug, thiserror::Error)]
pub enum AuditQueryRepositoryError {
    #[error("audit query storage failure")]
    Storage(#[source] Box<dyn StdError + Send + Sync + 'static>),
    #[error("persisted audit event record is malformed")]
    CorruptRecord,
}

/// Read-only persistence port for querying immutable security audit events.
#[async_trait]
pub trait AuditQueryRepository: Send + Sync {
    async fn list_events(
        &self,
        query: AuditEventQuery,
    ) -> Result<AuditEventPage, AuditQueryRepositoryError>;

    async fn count_events(&self, expr: &AuditQueryExpr) -> Result<u64, AuditQueryRepositoryError>;

    async fn find_event(
        &self,
        oid: AuditEventOid,
    ) -> Result<Option<AuditEvent>, AuditQueryRepositoryError>;
}
