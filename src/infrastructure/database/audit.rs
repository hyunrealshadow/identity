//! Append-only writer for the `audit` journal.
//!
//! Callers describe what happened with a typed [`AuditRecord`] and write it on
//! the transaction of the business change it describes, so a failed insert
//! rolls the change back. Request facts (actor, client address, User-Agent,
//! request and trace identifiers) come from task-local context captured once
//! per request; a record only carries what its call site knows. Each record is
//! a single `INSERT` whose missing display labels are snapshotted by
//! subqueries in the same statement, so auditing adds no round trips.
//! Credentials, tokens, and secret values are never recorded.

use identity_application::audit as audit_context;
pub use identity_application::audit::{AuditRequestContext, as_system, with_actor, with_request};
use identity_domain::audit::{AuditActor, AuditActorKind, AuditRecord, AuditTargetKind};
use sea_orm::{
    ColumnTrait, ConnectionTrait, DatabaseConnection, DbErr, EntityName, EntityTrait,
    TransactionTrait,
    sea_query::{Expr, Query, SelectStatement, SimpleExpr},
};
use uuid::Uuid;

use crate::{
    database::entity::{
        audit::{Column as AuditColumn, Entity as AuditEntity},
        client, resource, role, scope, user, user_group,
    },
    observability::context,
};

/// Longest stored User-Agent; longer values are truncated on a char boundary.
const MAX_USER_AGENT_LEN: usize = 512;

/// Append `record` on `conn`, normally the business change's transaction.
#[tracing::instrument(
    skip_all,
    name = "db.audit",
    fields(
        db.system = "postgresql",
        audit.action = %record.action,
        audit.category = %record.action.category(),
        audit.outcome = %record.outcome,
    )
)]
pub async fn record<C: ConnectionTrait>(conn: &C, record: AuditRecord) -> Result<(), DbErr> {
    let actor = resolve_actor(record.actor.clone(), record.default_actor.clone());
    let (request_id, trace_id) = correlation(&record);
    let request = audit_context::current_request();
    let target_kind = record.target_oid.map(|_| record.action.target_kind());
    let changes = (!record.changes.is_empty())
        .then(|| serde_json::to_value(&record.changes))
        .transpose()
        .map_err(|error| DbErr::Custom(format!("audit changes are not serializable: {error}")))?;
    let auth_methods = (!record.auth_methods.is_empty()).then(|| {
        serde_json::Value::from(
            record
                .auth_methods
                .iter()
                .map(|method| <&'static str>::from(*method))
                .collect::<Vec<_>>(),
        )
    });

    let actor_label = label_expr(
        actor.label.clone(),
        match actor.kind {
            AuditActorKind::User => Some(AuditTargetKind::User),
            AuditActorKind::Client => Some(AuditTargetKind::Client),
            AuditActorKind::System | AuditActorKind::Anonymous => None,
        },
        actor.oid,
    );
    let target_label = label_expr(record.target_label.clone(), target_kind, record.target_oid);

    let mut insert = Query::insert();
    insert
        .into_table(AuditEntity.table_ref())
        .columns([
            AuditColumn::Category,
            AuditColumn::Action,
            AuditColumn::Outcome,
            AuditColumn::FailureReason,
            AuditColumn::ActorKind,
            AuditColumn::ActorOid,
            AuditColumn::ActorLabel,
            AuditColumn::TargetKind,
            AuditColumn::TargetOid,
            AuditColumn::TargetLabel,
            AuditColumn::ClientOid,
            AuditColumn::AuthMethods,
            AuditColumn::IpAddress,
            AuditColumn::UserAgent,
            AuditColumn::RequestId,
            AuditColumn::TraceId,
            AuditColumn::Changes,
        ])
        .values([
            Expr::val(<&'static str>::from(record.action.category())),
            Expr::val(<&'static str>::from(record.action)),
            Expr::val(<&'static str>::from(record.outcome)),
            Expr::val(record.failure_reason.map(<&'static str>::from)),
            Expr::val(<&'static str>::from(actor.kind)),
            Expr::val(actor.oid),
            actor_label,
            Expr::val(target_kind.map(<&'static str>::from)),
            Expr::val(record.target_oid),
            target_label,
            Expr::val(record.client_oid),
            Expr::val(auth_methods),
            Expr::val(request.ip_address.map(|address| address.to_string())),
            Expr::val(request.user_agent.map(truncate_user_agent)),
            Expr::val(request_id),
            Expr::val(trace_id),
            Expr::val(changes),
        ])
        .map_err(|error| DbErr::Custom(format!("audit insert is malformed: {error}")))?;
    conn.execute(&insert).await?;
    Ok(())
}

/// Append `record` in its own transaction. Only for facts that have no
/// business write to join, such as a rejected attempt.
pub async fn record_standalone(db: &DatabaseConnection, record: AuditRecord) -> Result<(), DbErr> {
    let transaction = db.begin().await?;
    self::record(&transaction, record).await?;
    transaction.commit().await
}

fn resolve_actor(explicit: Option<AuditActor>, fallback: Option<AuditActor>) -> AuditActor {
    if let Some(actor) = explicit {
        return actor;
    }
    if let Some(actor) = audit_context::current_actor() {
        return AuditActor::from_principal(&actor.principal);
    }
    if let Some(actor) = fallback {
        return actor;
    }
    if audit_context::is_system() {
        return AuditActor::system();
    }
    AuditActor::anonymous()
}

fn correlation(record: &AuditRecord) -> (Option<String>, Option<String>) {
    let explicit = record.correlation.clone().unwrap_or_default();
    let actor = audit_context::current_actor().map(|actor| {
        (
            actor.request_id.as_str().to_owned(),
            actor.trace_id.as_ref().map(|id| id.as_str().to_owned()),
        )
    });
    let request = context::current_request_correlation();
    let request_id = explicit
        .request_id
        .or_else(|| actor.as_ref().map(|(id, _)| id.clone()))
        .or_else(|| request.as_ref().map(|value| value.request_id.clone()));
    let trace_id = explicit
        .trace_id
        .or_else(|| actor.and_then(|(_, trace)| trace))
        .or_else(|| request.and_then(|value| value.trace_id));
    (request_id, trace_id)
}

/// The supplied label, or the object's current name read in the same statement.
fn label_expr(
    label: Option<String>,
    kind: Option<AuditTargetKind>,
    oid: Option<Uuid>,
) -> SimpleExpr {
    if let Some(label) = label {
        return Expr::val(label);
    }
    match (kind, oid) {
        (Some(kind), Some(oid)) => label_query(kind, oid).map_or_else(
            || Expr::val(Option::<String>::None),
            |select| SimpleExpr::SubQuery(None, Box::new(select.into())),
        ),
        _ => Expr::val(Option::<String>::None),
    }
}

/// Reads the display name of an object. Kinds without a name column take
/// their label from the call site.
fn label_query(kind: AuditTargetKind, oid: Uuid) -> Option<SelectStatement> {
    fn name_of<E: EntityTrait>(
        entity: E,
        oid_column: E::Column,
        label: E::Column,
        oid: Uuid,
    ) -> SelectStatement {
        Query::select()
            .column(label)
            .from(entity)
            .and_where(oid_column.eq(oid))
            .limit(1)
            .to_owned()
    }
    Some(match kind {
        AuditTargetKind::User => name_of(user::Entity, user::Column::Oid, user::Column::Name, oid),
        AuditTargetKind::Client => name_of(
            client::Entity,
            client::Column::Oid,
            client::Column::Name,
            oid,
        ),
        AuditTargetKind::Role => name_of(role::Entity, role::Column::Oid, role::Column::Name, oid),
        AuditTargetKind::Group => name_of(
            user_group::Entity,
            user_group::Column::Oid,
            user_group::Column::Name,
            oid,
        ),
        AuditTargetKind::Scope => {
            name_of(scope::Entity, scope::Column::Oid, scope::Column::Code, oid)
        }
        AuditTargetKind::Resource => name_of(
            resource::Entity,
            resource::Column::Oid,
            resource::Column::Name,
            oid,
        ),
        AuditTargetKind::Key
        | AuditTargetKind::Setting
        | AuditTargetKind::Session
        | AuditTargetKind::Passkey
        | AuditTargetKind::DeviceAuthorization => return None,
    })
}

fn truncate_user_agent(mut value: String) -> String {
    if value.len() > MAX_USER_AGENT_LEN {
        let mut end = MAX_USER_AGENT_LEN;
        while !value.is_char_boundary(end) {
            end -= 1;
        }
        value.truncate(end);
    }
    value
}

#[cfg(test)]
mod tests {
    use super::truncate_user_agent;

    #[test]
    fn user_agent_truncation_keeps_whole_characters() {
        let value = "浏".repeat(200);
        let truncated = truncate_user_agent(value);
        assert!(truncated.len() <= 512);
        assert!(truncated.chars().all(|ch| ch == '浏'));
    }
}
