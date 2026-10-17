use super::{query_error, query_failed};
use crate::database::entity::{
    client_authorization, client_authorization::Entity as ClientAuthorizationEntity,
};
use crate::database::{
    query::{advisory_transaction_lock, json_text},
    repository::client_authorization_query as query,
};
use chrono::{DateTime, Utc};
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
    ClientAuthorizationEntity::update_many()
        .col_expr(
            client_authorization::Column::RevokedAt,
            SimpleExpr::Value(now.into()),
        )
        .col_expr(
            client_authorization::Column::UpdatedAt,
            SimpleExpr::Value(now.into()),
        )
        .filter(
            Condition::all()
                .add(
                    client_authorization::Column::Type
                        .eq(ClientAuthorizationType::AccessToken.to_string()),
                )
                .add(client_authorization::Column::RevokedAt.is_null())
                .add(
                    json_text(
                        (
                            client_authorization::Entity,
                            client_authorization::Column::Data,
                        ),
                        "authorization_code_oid",
                    )
                    .eq(authorization_code_oid.to_string()),
                ),
        )
        .exec(db)
        .await
        .map_err(query_error(
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
    let result = ClientAuthorizationEntity::update_many()
        .col_expr(
            client_authorization::Column::RevokedAt,
            SimpleExpr::Value(Some(now).into()),
        )
        .col_expr(
            client_authorization::Column::UpdatedAt,
            SimpleExpr::Value(Some(now).into()),
        )
        .filter(
            Condition::all()
                .add(client_authorization::Column::Oid.eq(oid))
                .add(client_authorization::Column::Type.eq(type_.to_string()))
                .add(client_authorization::Column::RevokedAt.is_null())
                .add(client_authorization::Column::ExpiresAt.gt(now)),
        )
        .exec(db)
        .await
        .map_err(query_error("client_authorization.revoke_if_active"))?;

    Ok(result.rows_affected == 1)
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
                Expr::col(client_authorization::Column::Oid)
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
    db.execute(&query::revoke_token_for_client(
        Expr::col(client_authorization::Column::Oid).eq(access_oid),
        client_oid,
        "access_token",
        now,
    ))
    .await
    .map_err(query_error(
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
                Expr::col(client_authorization::Column::Oid)
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
    transaction.commit().await.map_err(query_error(
        "client_authorization.revoke_refresh_grant_for_client",
    ))?;
    Ok(())
}
