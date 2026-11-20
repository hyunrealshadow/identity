use std::sync::Arc;

use chrono::{DateTime, Utc};
use identity_domain::{
    audit::{
        AuditEvent, AuditEventOid, AuditEventOrder, AuditEventPageDirection, AuditEventQuery,
        AuditEventSortKey, AuditQueryError, AuditQueryExpr, AuditQueryRepository,
        AuditQueryRepositoryError, parse_audit_query,
    },
    time_zone::TimeZone,
};

use super::cursor::{audit_filter_hash, decode_cursor, encode_cursors};
use crate::{
    data_protection::DataProtector,
    error::{AppError, codes::audit::AuditErrorCode},
};

pub const DEFAULT_AUDIT_PAGE_SIZE: usize = 20;
pub const MAX_AUDIT_PAGE_SIZE: usize = 100;

#[derive(Debug, Clone)]
pub struct AuditEventPageRequest {
    pub query: Option<String>,
    pub time_zone: Option<String>,
    pub order: AuditEventOrder,
    pub first: Option<i32>,
    pub after: Option<String>,
    pub last: Option<i32>,
    pub before: Option<String>,
}

#[derive(Debug, Clone)]
pub struct AuditEventCountRequest {
    pub query: Option<String>,
    pub time_zone: Option<String>,
    pub snapshot_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditEventPageItem {
    pub event: AuditEvent,
    pub cursor: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditEventPageResult {
    pub items: Vec<AuditEventPageItem>,
    pub has_previous_page: bool,
    pub has_next_page: bool,
    pub snapshot_at: DateTime<Utc>,
}

pub struct AuditQueryService {
    repository: Arc<dyn AuditQueryRepository>,
    data_protector: Arc<dyn DataProtector>,
}

impl AuditQueryService {
    #[must_use]
    pub fn new(
        repository: Arc<dyn AuditQueryRepository>,
        data_protector: Arc<dyn DataProtector>,
    ) -> Self {
        Self {
            repository,
            data_protector,
        }
    }

    #[tracing::instrument(skip_all, name = "audit.list")]
    pub async fn list_events(
        &self,
        request: AuditEventPageRequest,
    ) -> Result<AuditEventPageResult, AppError> {
        let (direction, cursor_token, limit) = validate_pagination(&request)?;
        let normalized_query = normalize_query(request.query.as_deref());
        let time_zone = parse_time_zone(request.time_zone.as_deref())?;
        let filter_hash = audit_filter_hash(&normalized_query, time_zone, request.order);

        let (cursor_key, snapshot_at) = match cursor_token {
            Some(token) => {
                let decoded = decode_cursor(
                    self.data_protector.as_ref(),
                    token,
                    &filter_hash,
                    request.order,
                )
                .await?;
                (Some(decoded.sort_key), decoded.snapshot_at)
            }
            None => (None, Utc::now()),
        };

        let expr = parse_query(&normalized_query, snapshot_at, time_zone)?;
        let page = self
            .repository
            .list_events(AuditEventQuery {
                expr,
                order: request.order,
                direction,
                cursor: cursor_key,
                limit,
            })
            .await
            .map_err(map_repository_error)?;

        let sort_keys = page
            .items
            .iter()
            .map(AuditEventSortKey::from_event)
            .collect::<Vec<_>>();
        let cursors = encode_cursors(
            self.data_protector.as_ref(),
            &filter_hash,
            snapshot_at,
            request.order,
            &sort_keys,
        )
        .await?;

        let items = page
            .items
            .into_iter()
            .zip(cursors)
            .map(|(event, cursor)| AuditEventPageItem { event, cursor })
            .collect();

        Ok(AuditEventPageResult {
            items,
            has_previous_page: page.has_previous_page,
            has_next_page: page.has_next_page,
            snapshot_at,
        })
    }

    #[tracing::instrument(skip_all, name = "audit.count")]
    pub async fn count_events(&self, request: AuditEventCountRequest) -> Result<u64, AppError> {
        let normalized_query = normalize_query(request.query.as_deref());
        let time_zone = parse_time_zone(request.time_zone.as_deref())?;
        let snapshot_at = request.snapshot_at.unwrap_or_else(Utc::now);
        let expr = parse_query(&normalized_query, snapshot_at, time_zone)?;
        self.repository
            .count_events(&expr)
            .await
            .map_err(map_repository_error)
    }

    #[tracing::instrument(skip_all, name = "audit.find")]
    pub async fn find_event(&self, oid: AuditEventOid) -> Result<Option<AuditEvent>, AppError> {
        self.repository
            .find_event(oid)
            .await
            .map_err(map_repository_error)
    }

    #[tracing::instrument(skip_all, name = "audit.actions")]
    pub async fn list_distinct_actions(&self) -> Result<Vec<String>, AppError> {
        self.repository
            .list_distinct_actions()
            .await
            .map_err(map_repository_error)
    }
}

fn validate_pagination(
    request: &AuditEventPageRequest,
) -> Result<(AuditEventPageDirection, Option<&str>, usize), AppError> {
    if request.first.is_some() && request.last.is_some() {
        return Err(AppError::from_code(AuditErrorCode::InvalidPageSize)
            .with_param("max", MAX_AUDIT_PAGE_SIZE.to_string()));
    }
    if request.first.is_some() && request.before.is_some() {
        return Err(AppError::from_code(AuditErrorCode::InvalidCursor));
    }
    if request.last.is_some() && request.after.is_some() {
        return Err(AppError::from_code(AuditErrorCode::InvalidCursor));
    }
    if request.after.is_some() && request.before.is_some() {
        return Err(AppError::from_code(AuditErrorCode::InvalidCursor));
    }

    let direction = if request.last.is_some() || request.before.is_some() {
        AuditEventPageDirection::Backward
    } else {
        AuditEventPageDirection::Forward
    };

    let raw_limit = match direction {
        AuditEventPageDirection::Forward => request.first,
        AuditEventPageDirection::Backward => request.last,
    };

    let limit = match raw_limit {
        None => DEFAULT_AUDIT_PAGE_SIZE,
        Some(value) if value < 1 || value as usize > MAX_AUDIT_PAGE_SIZE => {
            let field = if request.first.is_some() {
                "first"
            } else {
                "last"
            };
            return Err(AppError::from_code(AuditErrorCode::InvalidPageSize)
                .with_param("max", MAX_AUDIT_PAGE_SIZE.to_string())
                .with_field(field));
        }
        Some(value) => value as usize,
    };

    let cursor = match direction {
        AuditEventPageDirection::Forward => request.after.as_deref(),
        AuditEventPageDirection::Backward => request.before.as_deref(),
    };

    Ok((direction, cursor, limit))
}

fn normalize_query(raw: Option<&str>) -> String {
    raw.unwrap_or_default().trim().to_owned()
}

fn parse_time_zone(raw: Option<&str>) -> Result<TimeZone, AppError> {
    let trimmed = raw.map(str::trim).filter(|s| !s.is_empty());
    match trimmed {
        None => Ok(TimeZone::parse("UTC").expect("UTC is always valid")),
        Some(value) => TimeZone::parse(value).map_err(|_| {
            AppError::from_code(AuditErrorCode::InvalidTimeZone)
                .with_param("value", value)
                .with_field("timeZone")
        }),
    }
}

fn parse_query(
    normalized_query: &str,
    snapshot_at: DateTime<Utc>,
    time_zone: TimeZone,
) -> Result<AuditQueryExpr, AppError> {
    parse_audit_query(normalized_query, snapshot_at, time_zone).map_err(map_query_error)
}

fn map_query_error(error: AuditQueryError) -> AppError {
    match error {
        AuditQueryError::QueryTooLong { max, actual } => {
            AppError::from_code(AuditErrorCode::QueryTooLong)
                .with_param("max", max.to_string())
                .with_param("actual", actual.to_string())
                .with_field("query")
        }
        AuditQueryError::TooManyClauses { max } => {
            AppError::from_code(AuditErrorCode::QueryTooManyClauses)
                .with_param("max", max.to_string())
                .with_field("query")
        }
        AuditQueryError::TooDeeplyNested { max } => {
            AppError::from_code(AuditErrorCode::QueryTooDeep)
                .with_param("max", max.to_string())
                .with_field("query")
        }
        AuditQueryError::SyntaxError { .. } => {
            AppError::from_code(AuditErrorCode::QuerySyntaxError).with_field("query")
        }
        AuditQueryError::UnknownField { field } => {
            AppError::from_code(AuditErrorCode::QueryUnknownField)
                .with_param("field", field)
                .with_field("query")
        }
        AuditQueryError::InvalidDateValue { value } => {
            AppError::from_code(AuditErrorCode::QueryInvalidDate)
                .with_param("value", value)
                .with_field("query")
        }
        AuditQueryError::InvalidIdentifier { field, value } => {
            AppError::from_code(AuditErrorCode::QueryInvalidIdentifier)
                .with_param("field", field)
                .with_param("value", value)
                .with_field("query")
        }
        AuditQueryError::UnsupportedOperator { field } => {
            AppError::from_code(AuditErrorCode::QueryUnsupportedOperator)
                .with_param("field", field)
                .with_field("query")
        }
        AuditQueryError::UnsupportedRangeField { field } => {
            AppError::from_code(AuditErrorCode::QueryUnsupportedRangeField)
                .with_param("field", field)
                .with_field("query")
        }
        AuditQueryError::UnsupportedRegex => {
            AppError::from_code(AuditErrorCode::QueryUnsupportedRegex).with_field("query")
        }
        AuditQueryError::UnsupportedFuzzy | AuditQueryError::UnsupportedBoost => {
            AppError::from_code(AuditErrorCode::QueryUnsupportedSyntax).with_field("query")
        }
    }
}

fn map_repository_error(error: AuditQueryRepositoryError) -> AppError {
    AppError::internal(error)
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use async_trait::async_trait;
    use chrono::Duration;
    use identity_domain::audit::{
        AuditEvent, AuditEventOid, AuditEventOrder, AuditEventPage, AuditEventQuery,
        AuditQueryExpr, AuditQueryRepository, AuditQueryRepositoryError,
    };
    use uuid::Uuid;

    use identity_domain::data_protection::DataProtectionError;

    use super::*;
    use crate::data_protection::DataProtector;

    struct PassthroughProtector;

    #[async_trait]
    impl DataProtector for PassthroughProtector {
        async fn protect(
            &self,
            purpose: &str,
            plaintext: &[u8],
        ) -> Result<String, DataProtectionError> {
            let text = String::from_utf8(plaintext.to_vec()).unwrap();
            Ok(format!("{purpose}|{text}"))
        }

        async fn unprotect(
            &self,
            purpose: &str,
            token: &str,
        ) -> Result<Vec<u8>, DataProtectionError> {
            let prefix = format!("{purpose}|");
            let rest = token
                .strip_prefix(&prefix)
                .ok_or_else(|| DataProtectionError::InvalidProtectedPayload)?;
            Ok(rest.as_bytes().to_vec())
        }
    }

    #[derive(Default)]
    struct RecordingRepository {
        events: Vec<AuditEvent>,
        last_expr: Mutex<Option<AuditQueryExpr>>,
        queries: Mutex<Vec<AuditEventQuery>>,
    }

    #[async_trait]
    impl AuditQueryRepository for RecordingRepository {
        async fn list_events(
            &self,
            query: AuditEventQuery,
        ) -> Result<AuditEventPage, AuditQueryRepositoryError> {
            *self.last_expr.lock().unwrap() = Some(query.expr.clone());
            self.queries.lock().unwrap().push(query.clone());
            let take = query.limit.min(self.events.len());
            Ok(AuditEventPage {
                items: self.events[..take].to_vec(),
                has_previous_page: query.cursor.is_some(),
                has_next_page: self.events.len() > take,
            })
        }

        async fn count_events(
            &self,
            expr: &AuditQueryExpr,
        ) -> Result<u64, AuditQueryRepositoryError> {
            *self.last_expr.lock().unwrap() = Some(expr.clone());
            Ok(self.events.len() as u64)
        }

        async fn find_event(
            &self,
            oid: AuditEventOid,
        ) -> Result<Option<AuditEvent>, AuditQueryRepositoryError> {
            Ok(self.events.iter().find(|e| e.oid == oid).cloned())
        }

        async fn list_distinct_actions(&self) -> Result<Vec<String>, AuditQueryRepositoryError> {
            Ok(vec!["user.create".to_owned(), "client.update".to_owned()])
        }
    }

    fn sample_event(id: i64, occurred_at: DateTime<Utc>) -> AuditEvent {
        AuditEvent {
            id,
            oid: AuditEventOid::from_uuid(Uuid::new_v4()),
            occurred_at,
            transaction_id: id,
            resource_type: "user".to_owned(),
            resource_oid: Uuid::new_v4(),
            subject_oid: None,
            operation: "mutation".to_owned(),
            credential_type: None,
            previous_status: None,
            status: Some("success".to_owned()),
            actor_type: Some("user".to_owned()),
            actor_oid: Some(Uuid::new_v4()),
            action: Some("user.create".to_owned()),
            target_type: Some("user".to_owned()),
            target_oid: Some(Uuid::new_v4()),
            reason: None,
            request_id: Some("req-1".to_owned()),
            trace_id: Some("trace-1".to_owned()),
            event_kind: Some("semantic".to_owned()),
        }
    }

    #[tokio::test]
    async fn list_events_freezes_relative_snapshot_at_inside_cursor() {
        let base_time = Utc::now();
        let repo = Arc::new(RecordingRepository {
            events: vec![
                sample_event(10, base_time - Duration::seconds(10)),
                sample_event(9, base_time - Duration::seconds(20)),
            ],
            ..Default::default()
        });
        let service = AuditQueryService::new(repo.clone(), Arc::new(PassthroughProtector));

        let page1 = service
            .list_events(AuditEventPageRequest {
                query: Some("occurredAt:>=now-1h".to_owned()),
                time_zone: Some("Asia/Shanghai".to_owned()),
                order: AuditEventOrder::default(),
                first: Some(1),
                after: None,
                last: None,
                before: None,
            })
            .await
            .unwrap();
        assert_eq!(page1.items.len(), 1);
        assert!(page1.has_next_page);

        tokio::time::sleep(std::time::Duration::from_millis(20)).await;

        let page2 = service
            .list_events(AuditEventPageRequest {
                query: Some("occurredAt:>=now-1h".to_owned()),
                time_zone: Some("Asia/Shanghai".to_owned()),
                order: AuditEventOrder::default(),
                first: Some(1),
                after: Some(page1.items[0].cursor.clone()),
                last: None,
                before: None,
            })
            .await
            .unwrap();

        assert_eq!(
            page1.snapshot_at.timestamp_micros(),
            page2.snapshot_at.timestamp_micros()
        );
        let recorded = repo.queries.lock().unwrap();
        assert_eq!(recorded.len(), 2);
        assert_eq!(recorded[0].expr, recorded[1].expr);
    }

    #[tokio::test]
    async fn cursor_mismatch_when_query_or_time_zone_changes() {
        let repo = Arc::new(RecordingRepository {
            events: vec![sample_event(1, Utc::now())],
            ..Default::default()
        });
        let service = AuditQueryService::new(repo, Arc::new(PassthroughProtector));

        let page1 = service
            .list_events(AuditEventPageRequest {
                query: Some("action:user.*".to_owned()),
                time_zone: Some("UTC".to_owned()),
                order: AuditEventOrder::default(),
                first: Some(10),
                after: None,
                last: None,
                before: None,
            })
            .await
            .unwrap();

        let err = service
            .list_events(AuditEventPageRequest {
                query: Some("action:client.*".to_owned()),
                time_zone: Some("UTC".to_owned()),
                order: AuditEventOrder::default(),
                first: Some(10),
                after: Some(page1.items[0].cursor.clone()),
                last: None,
                before: None,
            })
            .await
            .unwrap_err();
        assert_eq!(err.code(), AuditErrorCode::InvalidCursor as u32);

        let err = service
            .list_events(AuditEventPageRequest {
                query: Some("action:user.*".to_owned()),
                time_zone: Some("Asia/Shanghai".to_owned()),
                order: AuditEventOrder::default(),
                first: Some(10),
                after: Some(page1.items[0].cursor.clone()),
                last: None,
                before: None,
            })
            .await
            .unwrap_err();
        assert_eq!(err.code(), AuditErrorCode::InvalidCursor as u32);
    }

    #[tokio::test]
    async fn invalid_pagination_query_and_time_zone_return_expected_codes() {
        let repo = Arc::new(RecordingRepository::default());
        let service = AuditQueryService::new(repo, Arc::new(PassthroughProtector));

        let too_many = service
            .list_events(AuditEventPageRequest {
                query: None,
                time_zone: None,
                order: AuditEventOrder::default(),
                first: Some(101),
                after: None,
                last: None,
                before: None,
            })
            .await
            .unwrap_err();
        assert_eq!(too_many.code(), AuditErrorCode::InvalidPageSize as u32);

        let bad_tz = service
            .list_events(AuditEventPageRequest {
                query: None,
                time_zone: Some("Mars/Olympus".to_owned()),
                order: AuditEventOrder::default(),
                first: None,
                after: None,
                last: None,
                before: None,
            })
            .await
            .unwrap_err();
        assert_eq!(bad_tz.code(), AuditErrorCode::InvalidTimeZone as u32);

        let unknown_field = service
            .list_events(AuditEventPageRequest {
                query: Some("bogus:1".to_owned()),
                time_zone: None,
                order: AuditEventOrder::default(),
                first: None,
                after: None,
                last: None,
                before: None,
            })
            .await
            .unwrap_err();
        assert_eq!(
            unknown_field.code(),
            AuditErrorCode::QueryUnknownField as u32
        );
    }
}
