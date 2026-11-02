//! Explicit security facts on the caller's business transaction.
//!
//! Request actor state is task-local, never PostgreSQL session configuration.
//! Anonymous protocol transitions retain an unknown actor rather than treating
//! the target account as the caller. No credential or token data is recorded.
use identity_domain::authorization::{ActorContext, ActorPrincipal};
use sea_orm::{
    ConnectionTrait, DatabaseConnection, DatabaseTransaction, DbBackend, DbErr, Statement,
    TransactionTrait,
};
use uuid::Uuid;

tokio::task_local! {
    static ACTOR: ActorContext;
}

pub async fn with_actor<F: std::future::Future>(actor: ActorContext, future: F) -> F::Output {
    ACTOR.scope(actor, future).await
}

pub async fn begin(
    db: &DatabaseConnection,
    _action: &'static str,
) -> Result<DatabaseTransaction, DbErr> {
    db.begin().await
}

/// Record only after a successful transition, before committing its transaction.
/// The journal has no update/delete API; a failed insert must abort the change.
#[tracing::instrument(skip_all, name = "db.audit", fields(db.system = "postgresql", audit.action = action, audit.target_type = target_type))]
pub async fn record(
    transaction: &DatabaseTransaction,
    action: &'static str,
    target_type: &'static str,
    target_oid: Uuid,
) -> Result<(), DbErr> {
    let actor = ACTOR.try_with(Clone::clone).ok();
    let correlation = crate::observability::context::current_request_correlation();
    let (kind, oid) = match actor.as_ref().map(|actor| &actor.principal) {
        Some(ActorPrincipal::User { user_oid, .. }) => ("user", Some(Uuid::from(*user_oid))),
        Some(ActorPrincipal::Client { client_oid }) => ("client", Some(*client_oid)),
        None => ("unknown", None),
    };
    let request_id = actor
        .as_ref()
        .map(|actor| actor.request_id.as_str().to_owned())
        .or_else(|| correlation.as_ref().map(|value| value.request_id.clone()));
    let trace_id = actor
        .as_ref()
        .and_then(|actor| {
            actor
                .trace_id
                .as_ref()
                .map(|value| value.as_str().to_owned())
        })
        .or_else(|| correlation.and_then(|value| value.trace_id));
    transaction
        .execute_raw(Statement::from_sql_and_values(
            DbBackend::Postgres,
            r#"INSERT INTO security_audit
               (resource_type,resource_oid,subject_oid,operation,status,
                actor_type,actor_oid,action,target_type,target_oid,reason,request_id,trace_id,event_kind)
               VALUES ($1,$2,CASE WHEN $3='user' THEN $4::uuid ELSE NULL END,'mutation','success',
                       $3,$4,$5,$1,$2,$6,$7,$8,'semantic')"#,
            [target_type.into(), target_oid.into(), kind.into(), oid.into(), action.into(),
             if actor.is_some() { "authenticated_action" } else { "protocol_transition" }.into(),
             request_id.into(), trace_id.into()],
        ))
        .await?;
    Ok(())
}
