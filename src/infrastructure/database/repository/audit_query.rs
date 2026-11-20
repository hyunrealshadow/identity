//! Read-only PostgreSQL query compiler and keyset pagination for `audit`.

use std::str::FromStr;

use async_trait::async_trait;
use chrono::Utc;
use identity_domain::{
    audit::{
        AuditAction, AuditActor, AuditActorKind, AuditAuthMethod, AuditCategory, AuditChange,
        AuditEvent, AuditEventOid, AuditEventOrderDirection, AuditEventPage,
        AuditEventPageDirection, AuditEventQuery, AuditFailureReason, AuditIdentifierMatch,
        AuditOutcome, AuditQueryExpr, AuditQueryField, AuditQueryRepository,
        AuditQueryRepositoryError, AuditTarget, AuditTargetKind, AuditTextMatcher,
    },
    global_id::DecodedGlobalId,
};
use sea_orm::{
    ColumnTrait, Condition, DatabaseConnection, DbErr, EntityTrait, Order, PaginatorTrait,
    QueryFilter, QueryOrder, QuerySelect,
    sea_query::{Expr, ExprTrait, Func, LikeExpr, SimpleExpr, extension::postgres::PgExpr},
};
use serde_json::Value;
use uuid::Uuid;

use super::rbac_management::support::{escape_like, page_flags};
use crate::database::entity::audit::{
    Column as AuditColumn, Entity as AuditEntity, Model as AuditModel,
};
use identity_application::rbac::cursor::RbacPageDirection;

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
        AuditEntity::find()
            .filter(compile_expr(expr))
            .count(&self.db)
            .await
            .map_err(storage)
    }

    #[tracing::instrument(skip_all, name = "db.query", fields(db.system = "postgresql", db.operation = "audit.find"))]
    async fn find_event(
        &self,
        oid: AuditEventOid,
    ) -> Result<Option<AuditEvent>, AuditQueryRepositoryError> {
        AuditEntity::find()
            .filter(AuditColumn::Oid.eq(oid.as_uuid()))
            .one(&self.db)
            .await
            .map_err(storage)?
            .map(to_domain)
            .transpose()
    }
}

async fn list(
    db: &DatabaseConnection,
    query: AuditEventQuery,
) -> Result<AuditEventPage, AuditQueryRepositoryError> {
    let ascending = matches!(query.order.direction, AuditEventOrderDirection::Asc);
    let descending = match query.direction {
        AuditEventPageDirection::Forward => !ascending,
        AuditEventPageDirection::Backward => ascending,
    };

    let mut condition = Condition::all().add(compile_expr(&query.expr));
    if let Some(key) = query.cursor {
        let at = key.occurred_at.fixed_offset();
        condition = condition.add(if descending {
            Condition::any().add(AuditColumn::OccurredAt.lt(at)).add(
                AuditColumn::OccurredAt
                    .eq(at)
                    .and(AuditColumn::Id.lt(key.id)),
            )
        } else {
            Condition::any().add(AuditColumn::OccurredAt.gt(at)).add(
                AuditColumn::OccurredAt
                    .eq(at)
                    .and(AuditColumn::Id.gt(key.id)),
            )
        });
    }

    let order = if descending { Order::Desc } else { Order::Asc };
    let limit = u64::try_from(query.limit.saturating_add(1)).map_err(|_| corrupt())?;
    let mut models = AuditEntity::find()
        .filter(condition)
        .order_by(AuditColumn::OccurredAt, order.clone())
        .order_by(AuditColumn::Id, order)
        .limit(limit)
        .all(db)
        .await
        .map_err(storage)?;

    let has_more = models.len() > query.limit;
    models.truncate(query.limit);
    if matches!(query.direction, AuditEventPageDirection::Backward) {
        models.reverse();
    }

    let cursor_present = query.cursor.is_some();
    let (has_previous_page, has_next_page) = match query.direction {
        AuditEventPageDirection::Forward => {
            page_flags(RbacPageDirection::Forward, has_more, cursor_present, false)
        }
        AuditEventPageDirection::Backward => {
            page_flags(RbacPageDirection::Backward, has_more, false, cursor_present)
        }
    };

    Ok(AuditEventPage {
        items: models
            .into_iter()
            .map(to_domain)
            .collect::<Result<_, _>>()?,
        has_previous_page,
        has_next_page,
    })
}

fn compile_expr(expr: &AuditQueryExpr) -> Condition {
    match expr {
        AuditQueryExpr::MatchAll => Condition::all(),
        AuditQueryExpr::And(items) => items
            .iter()
            .fold(Condition::all(), |all, item| all.add(compile_expr(item))),
        AuditQueryExpr::Or(items) if items.is_empty() => Condition::all().add(Expr::val(false)),
        AuditQueryExpr::Or(items) => items
            .iter()
            .fold(Condition::any(), |any, item| any.add(compile_expr(item))),
        AuditQueryExpr::Not(inner) => {
            // Nullable columns must not turn NOT(NULL) into SQL UNKNOWN.
            let inner: SimpleExpr = compile_expr(inner).into();
            Condition::all().add(Expr::expr(Func::coalesce([inner, Expr::val(false)])).not())
        }
        AuditQueryExpr::Text { field, matcher } => {
            Condition::all().add(text_predicate(*field, matcher))
        }
        AuditQueryExpr::Identifier { field, value } => {
            let column = identifier_column(*field);
            Condition::all().add(match value {
                AuditIdentifierMatch::Exists => column.is_not_null(),
                AuditIdentifierMatch::Exact(oid) => column.eq(*oid),
            })
        }
        AuditQueryExpr::OccurredAtRange { min, max } => {
            let mut condition = Condition::all().add(AuditColumn::OccurredAt.is_not_null());
            if let Some(bound) = min {
                let at = bound.instant.fixed_offset();
                condition = condition.add(if bound.inclusive {
                    AuditColumn::OccurredAt.gte(at)
                } else {
                    AuditColumn::OccurredAt.gt(at)
                });
            }
            if let Some(bound) = max {
                let at = bound.instant.fixed_offset();
                condition = condition.add(if bound.inclusive {
                    AuditColumn::OccurredAt.lte(at)
                } else {
                    AuditColumn::OccurredAt.lt(at)
                });
            }
            condition
        }
        AuditQueryExpr::FreeText(term) => {
            let pattern = contains_pattern(term);
            let mut any = Condition::any();
            for column in FREE_TEXT_COLUMNS {
                any = any.add(Expr::col(column).ilike(pattern.clone()));
            }
            if let Some(oid) = parse_uuid_or_global_id(term) {
                for column in [
                    AuditColumn::Oid,
                    AuditColumn::ActorOid,
                    AuditColumn::TargetOid,
                    AuditColumn::ClientOid,
                ] {
                    any = any.add(column.eq(oid));
                }
            }
            any
        }
    }
}

/// Text columns a bare search term matches.
const FREE_TEXT_COLUMNS: [AuditColumn; 7] = [
    AuditColumn::Action,
    AuditColumn::ActorLabel,
    AuditColumn::TargetLabel,
    AuditColumn::IpAddress,
    AuditColumn::UserAgent,
    AuditColumn::RequestId,
    AuditColumn::TraceId,
];

fn text_predicate(field: AuditQueryField, matcher: &AuditTextMatcher) -> SimpleExpr {
    if field == AuditQueryField::AuthMethod {
        return auth_method_predicate(matcher);
    }
    let column = text_column(field);
    // Enumerated columns hold exact stable values; labels and request facts
    // compare without regard to case.
    let enumerated = !matches!(
        field,
        AuditQueryField::ActorLabel
            | AuditQueryField::TargetLabel
            | AuditQueryField::IpAddress
            | AuditQueryField::UserAgent
            | AuditQueryField::RequestId
            | AuditQueryField::TraceId
    );
    match matcher {
        AuditTextMatcher::Exists => column.is_not_null().and(column.ne("")),
        AuditTextMatcher::Exact(value) if enumerated => column.eq(value.clone()),
        AuditTextMatcher::Exact(value) => Expr::col(column).ilike(like(escape_like(value))),
        AuditTextMatcher::Prefix(prefix) => {
            Expr::col(column).ilike(like(format!("{}%", escape_like(prefix))))
        }
        AuditTextMatcher::Contains(substr) => Expr::col(column).ilike(contains_pattern(substr)),
        AuditTextMatcher::Wildcard(pattern) => {
            Expr::col(column).ilike(like(wildcard_to_like(pattern)))
        }
    }
}

/// `auth_methods` is a JSON array of method values.
fn auth_method_predicate(matcher: &AuditTextMatcher) -> SimpleExpr {
    let column = AuditColumn::AuthMethods;
    match matcher {
        AuditTextMatcher::Exists => column.is_not_null(),
        AuditTextMatcher::Exact(value) => {
            Expr::col(column).contains(Expr::val(Value::from(vec![value.clone()])))
        }
        AuditTextMatcher::Prefix(text) | AuditTextMatcher::Contains(text) => Expr::col(column)
            .cast_as("text")
            .ilike(contains_pattern(text)),
        AuditTextMatcher::Wildcard(pattern) => Expr::col(column)
            .cast_as("text")
            .ilike(like(format!("%{}%", wildcard_to_like(pattern)))),
    }
}

const fn text_column(field: AuditQueryField) -> AuditColumn {
    match field {
        AuditQueryField::Category => AuditColumn::Category,
        AuditQueryField::Action => AuditColumn::Action,
        AuditQueryField::Outcome => AuditColumn::Outcome,
        AuditQueryField::FailureReason => AuditColumn::FailureReason,
        AuditQueryField::ActorKind => AuditColumn::ActorKind,
        AuditQueryField::ActorLabel => AuditColumn::ActorLabel,
        AuditQueryField::TargetKind => AuditColumn::TargetKind,
        AuditQueryField::TargetLabel => AuditColumn::TargetLabel,
        AuditQueryField::AuthMethod => AuditColumn::AuthMethods,
        AuditQueryField::IpAddress => AuditColumn::IpAddress,
        AuditQueryField::UserAgent => AuditColumn::UserAgent,
        AuditQueryField::RequestId => AuditColumn::RequestId,
        AuditQueryField::TraceId => AuditColumn::TraceId,
        AuditQueryField::Actor
        | AuditQueryField::Target
        | AuditQueryField::Client
        | AuditQueryField::OccurredAt => {
            debug_assert!(false, "non-text field passed to text_column");
            AuditColumn::Action
        }
    }
}

const fn identifier_column(field: AuditQueryField) -> AuditColumn {
    match field {
        AuditQueryField::Actor => AuditColumn::ActorOid,
        AuditQueryField::Target => AuditColumn::TargetOid,
        AuditQueryField::Client => AuditColumn::ClientOid,
        _ => {
            debug_assert!(false, "non-identifier field passed to identifier_column");
            AuditColumn::Oid
        }
    }
}

/// PostgreSQL's default LIKE escape character is the backslash that
/// `escape_like` and `wildcard_to_like` emit.
fn like(pattern: String) -> LikeExpr {
    LikeExpr::new(pattern)
}

fn contains_pattern(text: &str) -> LikeExpr {
    like(format!("%{}%", escape_like(text)))
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

fn to_domain(model: AuditModel) -> Result<AuditEvent, AuditQueryRepositoryError> {
    let target = match (model.target_kind, model.target_oid) {
        (Some(kind), Some(oid)) => Some(AuditTarget {
            kind: parse::<AuditTargetKind>(&kind)?,
            oid,
            label: model.target_label,
        }),
        (None, None) => None,
        _ => return Err(corrupt()),
    };
    let auth_methods = match model.auth_methods {
        None => Vec::new(),
        Some(value) => serde_json::from_value::<Vec<String>>(value)
            .map_err(|_| corrupt())?
            .iter()
            .map(|method| parse::<AuditAuthMethod>(method))
            .collect::<Result<_, _>>()?,
    };
    let changes = match model.changes {
        None => Vec::new(),
        Some(value) => serde_json::from_value::<Vec<AuditChange>>(value).map_err(|_| corrupt())?,
    };
    Ok(AuditEvent {
        id: model.id,
        oid: AuditEventOid::from_uuid(model.oid),
        occurred_at: model.occurred_at.with_timezone(&Utc),
        category: parse::<AuditCategory>(&model.category)?,
        action: parse::<AuditAction>(&model.action)?,
        outcome: parse::<AuditOutcome>(&model.outcome)?,
        failure_reason: model
            .failure_reason
            .as_deref()
            .map(parse::<AuditFailureReason>)
            .transpose()?,
        actor: AuditActor {
            kind: parse::<AuditActorKind>(&model.actor_kind)?,
            oid: model.actor_oid,
            label: model.actor_label,
        },
        target,
        client_oid: model.client_oid,
        auth_methods,
        ip_address: model.ip_address,
        user_agent: model.user_agent,
        request_id: model.request_id,
        trace_id: model.trace_id,
        changes,
    })
}

fn parse<T: FromStr>(value: &str) -> Result<T, AuditQueryRepositoryError> {
    value.parse().map_err(|_| corrupt())
}

fn storage(error: DbErr) -> AuditQueryRepositoryError {
    AuditQueryRepositoryError::Storage(Box::new(error))
}

fn corrupt() -> AuditQueryRepositoryError {
    AuditQueryRepositoryError::CorruptRecord
}
