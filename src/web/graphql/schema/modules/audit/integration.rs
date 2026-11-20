use chrono::{DateTime, Utc};
use identity_application::{
    audit::{AuditEventCountRequest, AuditEventPageRequest, AuditEventPageResult},
    error::AppError,
};
use identity_domain::audit::{AuditCategory, AuditEvent, AuditEventOid, AuditEventOrder};

use super::types::AuditEventOrder as GraphqlAuditEventOrder;
use crate::graphql::schema::{RequestContext, modules::resource::support::PageArgs};

pub(super) async fn list_events(
    request: &RequestContext,
    category: Option<AuditCategory>,
    query: Option<String>,
    time_zone: Option<String>,
    order: GraphqlAuditEventOrder,
    page: PageArgs,
) -> Result<AuditEventPageResult, AppError> {
    request
        .state
        .services()
        .audit_query()
        .list_events(AuditEventPageRequest {
            category,
            query,
            time_zone,
            order: AuditEventOrder::from(order),
            first: page.first.map(|v| i32::try_from(v).unwrap_or(i32::MAX)),
            after: page.after,
            last: page.last.map(|v| i32::try_from(v).unwrap_or(i32::MAX)),
            before: page.before,
        })
        .await
}

pub(super) async fn count_events(
    request: &RequestContext,
    category: Option<AuditCategory>,
    query: Option<String>,
    time_zone: Option<String>,
    snapshot_at: DateTime<Utc>,
) -> Result<u64, AppError> {
    request
        .state
        .services()
        .audit_query()
        .count_events(AuditEventCountRequest {
            category,
            query,
            time_zone,
            snapshot_at: Some(snapshot_at),
        })
        .await
}

pub(crate) async fn find_event(
    request: &RequestContext,
    oid: AuditEventOid,
) -> Result<Option<AuditEvent>, AppError> {
    request.state.services().audit_query().find_event(oid).await
}
