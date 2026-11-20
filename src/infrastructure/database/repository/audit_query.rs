//! Read-only PostgreSQL query compiler and keyset pagination for `security_audit`.

use async_trait::async_trait;
use chrono::Utc;
use identity_application::rbac::cursor::RbacPageDirection;
use identity_domain::{
    audit::{
        AuditEvent, AuditEventOid, AuditEventOrderDirection, AuditEventPage,
        AuditEventPageDirection, AuditEventQuery, AuditIdentifierMatch, AuditQueryExpr,
        AuditQueryField, AuditQueryRepository, AuditQueryRepositoryError, AuditTextMatcher,
    },
    global_id::DecodedGlobalId,
};
use sea_orm::{
    ColumnTrait, ConnectionTrait, DatabaseConnection, DbBackend, DbErr, EntityTrait,
    FromQueryResult, QueryFilter, Statement,
};
use uuid::Uuid;

use super::rbac_management::support::{Binds, CursorComparison, escape_like, page_flags};
use crate::database::entity::security_audit::{
    Column as SecurityAuditColumn, Entity as SecurityAuditEntity, Model as SecurityAuditModel,
};

pub struct AuditQueryRepositoryImpl {
    db: DatabaseConnection,
}

impl AuditQueryRepositoryImpl {
    #[must_use]
    pub fn new(db: DatabaseConnection) -> Self {
        Self { db }
    }
}

#[async_trait]
impl AuditQueryRepository for AuditQueryRepositoryImpl {
    #[tracing::instrument(skip_all, name = "db.query", fields(db.system = "postgresql", db.operation = "audit.list"))]
    async fn list_events(
        &self,
        query: AuditEventQuery,
    ) -> Result<AuditEventPage, AuditQueryRepositoryError> {
        list(&self.db, query).await
    }

    #[tracing::instrument(skip_all, name = "db.query", fields(db.system = "postgresql", db.operation = "audit.count"))]
    async fn count_events(&self, expr: &AuditQueryExpr) -> Result<u64, AuditQueryRepositoryError> {
        count(&self.db, expr).await
    }

    #[tracing::instrument(skip_all, name = "db.query", fields(db.system = "postgresql", db.operation = "audit.find"))]
    async fn find_event(
        &self,
        oid: AuditEventOid,
    ) -> Result<Option<AuditEvent>, AuditQueryRepositoryError> {
        let model = SecurityAuditEntity::find()
            .filter(SecurityAuditColumn::Oid.eq(oid.as_uuid()))
            .one(&self.db)
            .await
            .map_err(storage)?;
        Ok(model.map(to_domain))
    }

    #[tracing::instrument(skip_all, name = "db.query", fields(db.system = "postgresql", db.operation = "audit.actions"))]
    async fn list_distinct_actions(&self) -> Result<Vec<String>, AuditQueryRepositoryError> {
        let rows = self
            .db
            .query_all_raw(Statement::from_sql_and_values(
                DbBackend::Postgres,
                "SELECT DISTINCT action FROM security_audit WHERE action IS NOT NULL AND action <> '' ORDER BY action ASC LIMIT 200",
                vec![],
            ))
            .await
            .map_err(storage)?;
        rows.into_iter()
            .map(|row| row.try_get::<String>("", "action").map_err(storage))
            .collect()
    }
}

async fn count<C: ConnectionTrait>(
    db: &C,
    expr: &AuditQueryExpr,
) -> Result<u64, AuditQueryRepositoryError> {
    let mut binds = Binds::new();
    let where_sql = compile_expr(expr, &mut binds);
    let row = db
        .query_one_raw(Statement::from_sql_and_values(
            DbBackend::Postgres,
            format!("SELECT COUNT(*)::bigint AS total FROM security_audit WHERE {where_sql}"),
            binds.into_values(),
        ))
        .await
        .map_err(storage)?
        .ok_or_else(corrupt)?;
    let total = row.try_get::<i64>("", "total").map_err(storage)?;
    u64::try_from(total).map_err(|_| corrupt())
}

async fn list<C: ConnectionTrait>(
    db: &C,
    query: AuditEventQuery,
) -> Result<AuditEventPage, AuditQueryRepositoryError> {
    let ascending = matches!(query.order.direction, AuditEventOrderDirection::Asc);
    let descending = match query.direction {
        AuditEventPageDirection::Forward => !ascending,
        AuditEventPageDirection::Backward => ascending,
    };

    let mut binds = Binds::new();
    let mut conditions = vec![compile_expr(&query.expr, &mut binds)];

    if let Some(key) = query.cursor {
        let comparison = match query.direction {
            AuditEventPageDirection::Forward => CursorComparison::After,
            AuditEventPageDirection::Backward => CursorComparison::Before,
        };
        let after = matches!(comparison, CursorComparison::After);
        let op = if after == ascending { ">" } else { "<" };
        let value = key.occurred_at.fixed_offset();
        let p_ts1 = binds.push(value);
        let p_ts2 = binds.push(value);
        let p_id = binds.push(key.id);
        conditions.push(format!(
            "(occurred_at {op} {p_ts1} OR (occurred_at = {p_ts2} AND id {op} {p_id}))"
        ));
    }

    let dir_sql = if descending { "DESC" } else { "ASC" };
    let limit = i64::try_from(query.limit.saturating_add(1)).map_err(|_| corrupt())?;
    let p_limit = binds.push(limit);

    let sql = format!(
        "SELECT id, oid, occurred_at, transaction_id, resource_type, resource_oid, subject_oid, \
         operation, credential_type, previous_status, status, actor_type, actor_oid, action, \
         target_type, target_oid, reason, request_id, trace_id, event_kind \
         FROM security_audit WHERE {} \
         ORDER BY occurred_at {dir_sql}, id {dir_sql} LIMIT {p_limit}",
        conditions.join(" AND ")
    );

    let mut models = SecurityAuditModel::find_by_statement(Statement::from_sql_and_values(
        DbBackend::Postgres,
        sql,
        binds.into_values(),
    ))
    .all(db)
    .await
    .map_err(storage)?;

    let has_more = models.len() > query.limit;
    models.truncate(query.limit);
    if matches!(query.direction, AuditEventPageDirection::Backward) {
        models.reverse();
    }

    let rbac_dir = match query.direction {
        AuditEventPageDirection::Forward => RbacPageDirection::Forward,
        AuditEventPageDirection::Backward => RbacPageDirection::Backward,
    };
    let cursor_present = query.cursor.is_some();
    let (has_previous_page, has_next_page) = match rbac_dir {
        RbacPageDirection::Forward => page_flags(rbac_dir, has_more, cursor_present, false),
        RbacPageDirection::Backward => page_flags(rbac_dir, has_more, false, cursor_present),
    };

    Ok(AuditEventPage {
        items: models.into_iter().map(to_domain).collect(),
        has_previous_page,
        has_next_page,
    })
}

fn compile_expr(expr: &AuditQueryExpr, binds: &mut Binds) -> String {
    match expr {
        AuditQueryExpr::MatchAll => "TRUE".to_owned(),
        AuditQueryExpr::And(items) => {
            if items.is_empty() {
                return "TRUE".to_owned();
            }
            let compiled = items
                .iter()
                .map(|item| format!("({})", compile_expr(item, binds)))
                .collect::<Vec<_>>();
            format!("({})", compiled.join(" AND "))
        }
        AuditQueryExpr::Or(items) => {
            if items.is_empty() {
                return "FALSE".to_owned();
            }
            let compiled = items
                .iter()
                .map(|item| format!("({})", compile_expr(item, binds)))
                .collect::<Vec<_>>();
            format!("({})", compiled.join(" OR "))
        }
        AuditQueryExpr::Not(inner) => {
            // Nullable audit columns must not evaluate NOT(NULL) to SQL UNKNOWN.
            format!("NOT COALESCE(({}), FALSE)", compile_expr(inner, binds))
        }
        AuditQueryExpr::Text { field, matcher } => {
            let col = text_column(*field);
            compile_text_matcher(col, *field == AuditQueryField::Reason, matcher, binds)
        }
        AuditQueryExpr::Identifier { field, value } => {
            let col = identifier_column(*field);
            match value {
                AuditIdentifierMatch::Exists => format!("({col} IS NOT NULL)"),
                AuditIdentifierMatch::Exact(oid) => {
                    let p = binds.push(*oid);
                    format!("({col} = {p})")
                }
            }
        }
        AuditQueryExpr::OccurredAtRange { min, max } => {
            let mut clauses = Vec::with_capacity(2);
            if let Some(bound) = min {
                let p = binds.push(bound.instant.fixed_offset());
                let op = if bound.inclusive { ">=" } else { ">" };
                clauses.push(format!("occurred_at {op} {p}"));
            }
            if let Some(bound) = max {
                let p = binds.push(bound.instant.fixed_offset());
                let op = if bound.inclusive { "<=" } else { "<" };
                clauses.push(format!("occurred_at {op} {p}"));
            }
            if clauses.is_empty() {
                "(occurred_at IS NOT NULL)".to_owned()
            } else {
                format!("({})", clauses.join(" AND "))
            }
        }
        AuditQueryExpr::FreeText(term) => {
            let p_like = binds.push(format!("%{}%", escape_like(term)));
            let mut parts = vec![
                format!("action ILIKE {p_like} ESCAPE '\\'"),
                format!("actor_type ILIKE {p_like} ESCAPE '\\'"),
                format!("target_type ILIKE {p_like} ESCAPE '\\'"),
                format!("resource_type ILIKE {p_like} ESCAPE '\\'"),
                format!("operation ILIKE {p_like} ESCAPE '\\'"),
                format!("status ILIKE {p_like} ESCAPE '\\'"),
                format!("reason ILIKE {p_like} ESCAPE '\\'"),
                format!("request_id ILIKE {p_like} ESCAPE '\\'"),
                format!("trace_id ILIKE {p_like} ESCAPE '\\'"),
            ];
            if let Some(oid) = parse_uuid_or_global_id(term) {
                let p_oid = binds.push(oid);
                parts.push(format!("oid = {p_oid}"));
                parts.push(format!("actor_oid = {p_oid}"));
                parts.push(format!("target_oid = {p_oid}"));
                parts.push(format!("resource_oid = {p_oid}"));
                parts.push(format!("subject_oid = {p_oid}"));
            }
            format!("({})", parts.join(" OR "))
        }
    }
}

fn compile_text_matcher(
    col: &str,
    case_insensitive_exact: bool,
    matcher: &AuditTextMatcher,
    binds: &mut Binds,
) -> String {
    match matcher {
        AuditTextMatcher::Exists => format!("({col} IS NOT NULL AND {col} <> '')"),
        AuditTextMatcher::Exact(value) => {
            let p = binds.push(value.clone());
            if case_insensitive_exact {
                format!("(LOWER({col}) = LOWER({p}))")
            } else {
                format!("({col} = {p})")
            }
        }
        AuditTextMatcher::Prefix(prefix) => {
            let p = binds.push(format!("{}%", escape_like(prefix)));
            format!("({col} ILIKE {p} ESCAPE '\\')")
        }
        AuditTextMatcher::Contains(substr) => {
            let p = binds.push(format!("%{}%", escape_like(substr)));
            format!("({col} ILIKE {p} ESCAPE '\\')")
        }
        AuditTextMatcher::Wildcard(pattern) => {
            let p = binds.push(wildcard_to_like(pattern));
            format!("({col} ILIKE {p} ESCAPE '\\')")
        }
    }
}

const fn text_column(field: AuditQueryField) -> &'static str {
    match field {
        AuditQueryField::Action => "action",
        AuditQueryField::ActorType => "actor_type",
        AuditQueryField::TargetType => "target_type",
        AuditQueryField::ResourceType => "resource_type",
        AuditQueryField::Operation => "operation",
        AuditQueryField::Status => "status",
        AuditQueryField::PreviousStatus => "previous_status",
        AuditQueryField::CredentialType => "credential_type",
        AuditQueryField::EventKind => "event_kind",
        AuditQueryField::RequestId => "request_id",
        AuditQueryField::TraceId => "trace_id",
        AuditQueryField::Reason => "reason",
        AuditQueryField::Actor
        | AuditQueryField::Target
        | AuditQueryField::Resource
        | AuditQueryField::Subject
        | AuditQueryField::OccurredAt => {
            debug_assert!(false, "non-text field passed to text_column");
            "action"
        }
    }
}

const fn identifier_column(field: AuditQueryField) -> &'static str {
    match field {
        AuditQueryField::Actor => "actor_oid",
        AuditQueryField::Target => "target_oid",
        AuditQueryField::Resource => "resource_oid",
        AuditQueryField::Subject => "subject_oid",
        _ => {
            debug_assert!(false, "non-identifier field passed to identifier_column");
            "resource_oid"
        }
    }
}

fn wildcard_to_like(pattern: &str) -> String {
    let mut out = String::with_capacity(pattern.len() + 4);
    for ch in pattern.chars() {
        match ch {
            '\\' => out.push_str("\\\\"),
            '%' => out.push_str("\\%"),
            '_' => out.push_str("\\_"),
            '*' => out.push('%'),
            '?' => out.push('_'),
            other => out.push(other),
        }
    }
    out
}

fn parse_uuid_or_global_id(raw: &str) -> Option<Uuid> {
    if let Ok(oid) = Uuid::parse_str(raw) {
        return Some(oid);
    }
    DecodedGlobalId::decode(raw)
        .ok()
        .map(|decoded| decoded.oid())
}

fn to_domain(model: SecurityAuditModel) -> AuditEvent {
    AuditEvent {
        id: model.id,
        oid: AuditEventOid::from_uuid(model.oid),
        occurred_at: model.occurred_at.with_timezone(&Utc),
        transaction_id: model.transaction_id,
        resource_type: model.resource_type,
        resource_oid: model.resource_oid,
        subject_oid: model.subject_oid,
        operation: model.operation,
        credential_type: model.credential_type,
        previous_status: model.previous_status,
        status: model.status,
        actor_type: model.actor_type,
        actor_oid: model.actor_oid,
        action: model.action,
        target_type: model.target_type,
        target_oid: model.target_oid,
        reason: model.reason,
        request_id: model.request_id,
        trace_id: model.trace_id,
        event_kind: model.event_kind,
    }
}

fn storage(error: DbErr) -> AuditQueryRepositoryError {
    AuditQueryRepositoryError::Storage(Box::new(error))
}

fn corrupt() -> AuditQueryRepositoryError {
    AuditQueryRepositoryError::CorruptRecord
}
