use super::{query_error, query_failed};
use crate::database::{
    audit,
    entity::{
        client::Entity as ClientEntity,
        client_authorization,
        client_authorization::{
            Column as ClientAuthorizationColumn, Entity as ClientAuthorizationEntity,
        },
    },
    query::{advisory_transaction_lock, json_text},
    repository::client_authorization_query as query,
};
use chrono::{DateTime, Utc};
use identity_domain::audit::{AuditAction, AuditActor, AuditFailureReason, AuditRecord};
use identity_domain::{
    client::model::ClientOid,
    client_authorization::{ClientAuthorizationRepositoryError, ClientAuthorizationType},
};
use sea_orm::{
    ColumnTrait, Condition, ConnectionTrait, DatabaseConnection, DatabaseTransaction, DbErr,
    EntityTrait, QueryFilter, TransactionTrait,
    sea_query::{Expr, ExprTrait, Func, SimpleExpr},
};
use serde_json::Value;
use uuid::Uuid;

/// The user a grant was issued to, from its stored data.
fn grant_user(data: &Value) -> Option<Uuid> {
    data["user_oid"]
        .as_str()
        .and_then(|oid| Uuid::parse_str(oid).ok())
}

/// The user and client of one stored grant, read in a single query.
async fn grant_parties(
    transaction: &DatabaseTransaction,
    oid: Uuid,
) -> Result<(Option<Uuid>, Option<Uuid>), DbErr> {
    let row = ClientAuthorizationEntity::find()
        .filter(ClientAuthorizationColumn::Oid.eq(oid))
        .find_also_related(ClientEntity)
        .one(transaction)
        .await?;
    Ok(row.map_or((None, None), |(grant, client)| {
        (grant_user(&grant.data), client.map(|client| client.oid))
    }))
}

/// A replayed or revoked token: the client presented it, and it belongs to
/// the user it was issued to.
fn token_record(
    record: AuditRecord,
    user_oid: Option<Uuid>,
    client_oid: Option<Uuid>,
) -> AuditRecord {
    let mut record = AuditRecord {
        target_oid: user_oid,
        ..record
    };
    if let Some(client_oid) = client_oid {
        record = record
            .client(client_oid)
            .default_actor(AuditActor::client(client_oid));
    }
    record
}

pub(super) async fn lock_refresh_family(
    transaction: &DatabaseTransaction,
    refresh_oid: Uuid,
    client_oid: ClientOid,
    reject_compromised: bool,
) -> Result<Uuid, ClientAuthorizationRepositoryError> {
    let root = transaction
        .query_one(&query::refresh_root(refresh_oid, client_oid))
        .await
        .map_err(query_error("client_authorization.lock_refresh_family"))?
        .ok_or_else(|| {
            query_failed(
                "client_authorization.lock_refresh_family",
                DbErr::RecordNotFound("refresh token family not found".into()),
            )
        })?;
    let root_oid: Uuid = root
        .try_get("", "root_oid")
        .map_err(query_error("client_authorization.lock_refresh_family"))?;
    transaction
        .query_one(&advisory_transaction_lock(
            Func::cust("hashtextextended")
                .args([Expr::value(root_oid.to_string()), Expr::value(0_i64)]),
        ))
        .await
        .map_err(query_error("client_authorization.lock_refresh_family"))?;
    if reject_compromised {
        let row = transaction
            .query_one(&query::refresh_compromised(root_oid))
            .await
            .map_err(query_error("client_authorization.lock_refresh_family"))?
            .ok_or_else(|| {
                query_failed(
                    "client_authorization.lock_refresh_family",
                    DbErr::RecordNotFound("refresh token family root not found".into()),
                )
            })?;
        let compromised: bool = row
            .try_get("", "compromised")
            .map_err(query_error("client_authorization.lock_refresh_family"))?;
        if compromised {
            return Err(query_failed(
                "client_authorization.lock_refresh_family",
                DbErr::RecordNotFound("refresh token family was revoked".into()),
            ));
        }
    }
    Ok(root_oid)
}

#[tracing::instrument(skip_all, name = "db.query", fields(db.system = "postgresql", db.operation = "revoke_access_tokens_for_authorization_code"))]
pub(super) async fn revoke_access_tokens_for_authorization_code(
    db: &DatabaseConnection,
    authorization_code_oid: Uuid,
) -> Result<(), ClientAuthorizationRepositoryError> {
    let now = Utc::now();
    let transaction = db.begin().await.map_err(query_error(
        "client_authorization.revoke_access_tokens_for_authorization_code",
    ))?;
    let changed = ClientAuthorizationEntity::update_many()
        .col_expr(
            ClientAuthorizationColumn::RevokedAt,
            Expr::cust("COALESCE(revoked_at, CURRENT_TIMESTAMP)"),
        )
        .col_expr(
            ClientAuthorizationColumn::UpdatedAt,
            SimpleExpr::Value(now.into()),
        )
        // A replay withdraws the code and all descendants, including consumed
        // refresh parents that another exchange may already be processing.
        .col_expr(
            ClientAuthorizationColumn::Data,
            Expr::cust("jsonb_set(data, '{_authority_withdrawn}', 'true'::jsonb, true)"),
        )
        .filter(
            Condition::all()
                .add(ClientAuthorizationColumn::Type.is_in([
                    ClientAuthorizationType::AuthorizationCode.to_string(),
                    ClientAuthorizationType::AccessToken.to_string(),
                    ClientAuthorizationType::RefreshToken.to_string(),
                ]))
                .add(
                    Condition::any()
                        .add(ClientAuthorizationColumn::Oid.eq(authorization_code_oid))
                        .add(
                            json_text(
                                (
                                    client_authorization::Entity,
                                    ClientAuthorizationColumn::Data,
                                ),
                                "authorization_code_oid",
                            )
                            .eq(authorization_code_oid.to_string()),
                        ),
                ),
        )
        .exec(&transaction)
        .await
        .map_err(query_error(
            "client_authorization.revoke_access_tokens_for_authorization_code",
        ))?;

    if changed.rows_affected > 0 {
        let (user_oid, client_oid) = grant_parties(&transaction, authorization_code_oid)
            .await
            .map_err(query_error(
                "client_authorization.revoke_access_tokens_for_authorization_code",
            ))?;
        audit::record(
            &transaction,
            token_record(
                AuditRecord::failure(
                    AuditAction::TokenReplay,
                    AuditFailureReason::ReplayDetected,
                    None,
                ),
                user_oid,
                client_oid,
            ),
        )
        .await
        .map_err(query_error(
            "client_authorization.revoke_access_tokens_for_authorization_code",
        ))?;
    }
    transaction.commit().await.map_err(query_error(
        "client_authorization.revoke_access_tokens_for_authorization_code",
    ))?;
    Ok(())
}

#[tracing::instrument(skip_all, name = "db.query", fields(db.system = "postgresql", db.operation = "revoke_if_active"))]
pub(super) async fn revoke_if_active(
    db: &DatabaseConnection,
    oid: Uuid,
    type_: ClientAuthorizationType,
    now: DateTime<Utc>,
) -> Result<bool, ClientAuthorizationRepositoryError> {
    let transaction = db
        .begin()
        .await
        .map_err(query_error("client_authorization.revoke_if_active"))?;
    let result = ClientAuthorizationEntity::update_many()
        .col_expr(
            ClientAuthorizationColumn::RevokedAt,
            SimpleExpr::Value(Some(now).into()),
        )
        .col_expr(
            ClientAuthorizationColumn::UpdatedAt,
            SimpleExpr::Value(Some(now).into()),
        )
        .filter(
            Condition::all()
                .add(ClientAuthorizationColumn::Oid.eq(oid))
                .add(ClientAuthorizationColumn::Type.eq(type_.to_string()))
                .add(ClientAuthorizationColumn::RevokedAt.is_null())
                .add(ClientAuthorizationColumn::ExpiresAt.gt(now)),
        )
        .exec(&transaction)
        .await
        .map_err(query_error("client_authorization.revoke_if_active"))?;

    let changed = result.rows_affected == 1;
    transaction
        .commit()
        .await
        .map_err(query_error("client_authorization.revoke_if_active"))?;
    Ok(changed)
}

#[tracing::instrument(skip_all, name = "db.query", fields(db.system = "postgresql", db.operation = "revoke_refresh_token_family"))]
pub(super) async fn revoke_refresh_token_family(
    db: &DatabaseConnection,
    refresh_oid: Uuid,
    client_oid: ClientOid,
    now: DateTime<Utc>,
) -> Result<(), ClientAuthorizationRepositoryError> {
    let transaction = db.begin().await.map_err(query_error(
        "client_authorization.revoke_refresh_token_family",
    ))?;
    let root_oid = lock_refresh_family(&transaction, refresh_oid, client_oid, false).await?;
    let root = transaction
        .query_one(&query::authorization_data(root_oid))
        .await
        .map_err(query_error(
            "client_authorization.revoke_refresh_token_family",
        ))?
        .ok_or_else(|| {
            query_failed(
                "client_authorization.revoke_refresh_token_family",
                DbErr::RecordNotFound("refresh token family root not found".into()),
            )
        })?;
    let data: Value = root.try_get("", "data").map_err(query_error(
        "client_authorization.revoke_refresh_token_family",
    ))?;
    let authorization_code_oid = data["authorization_code_oid"].as_str().unwrap_or("");
    let device_authorization_oid = data["device_authorization_oid"].as_str().unwrap_or("");

    transaction
        .execute(&query::mark_refresh_flag(root_oid, "replay_detected", now))
        .await
        .map_err(query_error(
            "client_authorization.revoke_refresh_token_family",
        ))?;
    transaction
        .execute(&query::revoke_refresh_family(
            root_oid,
            client_oid,
            authorization_code_oid,
            device_authorization_oid,
            now,
        ))
        .await
        .map_err(query_error(
            "client_authorization.revoke_refresh_token_family",
        ))?;
    if !device_authorization_oid.is_empty() {
        transaction
            .execute(&query::revoke_token_for_client(
                Expr::col(ClientAuthorizationColumn::Oid)
                    .cast_as("text")
                    .eq(device_authorization_oid),
                client_oid,
                "device_authorization",
                now,
            ))
            .await
            .map_err(query_error(
                "client_authorization.revoke_refresh_token_family",
            ))?;
    }
    audit::record(
        &transaction,
        token_record(
            AuditRecord::failure(
                AuditAction::TokenReplay,
                AuditFailureReason::ReplayDetected,
                None,
            ),
            grant_user(&data),
            Some(client_oid),
        ),
    )
    .await
    .map_err(query_error(
        "client_authorization.revoke_refresh_token_family",
    ))?;
    transaction.commit().await.map_err(query_error(
        "client_authorization.revoke_refresh_token_family",
    ))?;
    Ok(())
}

#[tracing::instrument(skip_all, name = "db.query", fields(db.system = "postgresql", db.operation = "revoke_access_token_for_client"))]
pub(super) async fn revoke_access_token_for_client(
    db: &DatabaseConnection,
    access_oid: Uuid,
    client_oid: ClientOid,
    now: DateTime<Utc>,
) -> Result<(), ClientAuthorizationRepositoryError> {
    let transaction = db.begin().await.map_err(query_error(
        "client_authorization.revoke_access_token_for_client",
    ))?;
    let result = transaction
        .execute(&query::revoke_token_for_client(
            Expr::col(ClientAuthorizationColumn::Oid).eq(access_oid),
            client_oid,
            "access_token",
            now,
        ))
        .await
        .map_err(query_error(
            "client_authorization.revoke_access_token_for_client",
        ))?;
    if result.rows_affected() > 0 {
        audit::record(
            &transaction,
            token_record(
                AuditRecord::success(AuditAction::TokenRevoke, None),
                grant_parties(&transaction, access_oid)
                    .await
                    .map_err(query_error(
                        "client_authorization.revoke_access_token_for_client",
                    ))?
                    .0,
                Some(client_oid),
            ),
        )
        .await
        .map_err(query_error(
            "client_authorization.revoke_access_token_for_client",
        ))?;
    }
    transaction.commit().await.map_err(query_error(
        "client_authorization.revoke_access_token_for_client",
    ))?;
    Ok(())
}

#[tracing::instrument(skip_all, name = "db.query", fields(db.system = "postgresql", db.operation = "revoke_refresh_grant_for_client"))]
pub(super) async fn revoke_refresh_grant_for_client(
    db: &DatabaseConnection,
    refresh_oid: Uuid,
    client_oid: ClientOid,
    now: DateTime<Utc>,
) -> Result<(), ClientAuthorizationRepositoryError> {
    let transaction = db.begin().await.map_err(query_error(
        "client_authorization.revoke_refresh_grant_for_client",
    ))?;
    let root_oid = lock_refresh_family(&transaction, refresh_oid, client_oid, false).await?;
    let root = transaction
        .query_one(&query::authorization_data(root_oid))
        .await
        .map_err(query_error(
            "client_authorization.revoke_refresh_grant_for_client",
        ))?
        .ok_or_else(|| {
            query_failed(
                "client_authorization.revoke_refresh_grant_for_client",
                DbErr::RecordNotFound("refresh grant root not found".into()),
            )
        })?;
    let data: Value = root.try_get("", "data").map_err(query_error(
        "client_authorization.revoke_refresh_grant_for_client",
    ))?;
    let authorization_code_oid = data["authorization_code_oid"].as_str().unwrap_or("");
    let device_authorization_oid = data["device_authorization_oid"].as_str().unwrap_or("");

    transaction
        .execute(&query::mark_refresh_flag(root_oid, "grant_revoked", now))
        .await
        .map_err(query_error(
            "client_authorization.revoke_refresh_grant_for_client",
        ))?;
    transaction
        .execute(&query::revoke_refresh_family(
            root_oid,
            client_oid,
            authorization_code_oid,
            device_authorization_oid,
            now,
        ))
        .await
        .map_err(query_error(
            "client_authorization.revoke_refresh_grant_for_client",
        ))?;
    if !device_authorization_oid.is_empty() {
        transaction
            .execute(&query::revoke_token_for_client(
                Expr::col(ClientAuthorizationColumn::Oid)
                    .cast_as("text")
                    .eq(device_authorization_oid),
                client_oid,
                "device_authorization",
                now,
            ))
            .await
            .map_err(query_error(
                "client_authorization.revoke_refresh_grant_for_client",
            ))?;
    }
    audit::record(
        &transaction,
        token_record(
            AuditRecord::success(AuditAction::TokenRevoke, None),
            grant_user(&data),
            Some(client_oid),
        ),
    )
    .await
    .map_err(query_error(
        "client_authorization.revoke_refresh_grant_for_client",
    ))?;
    transaction.commit().await.map_err(query_error(
        "client_authorization.revoke_refresh_grant_for_client",
    ))?;
    Ok(())
}
