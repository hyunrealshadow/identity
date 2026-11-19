//! Protected Login (account center) OAuth client reconciliation.
//!
//! Installation provisions the client with its redirect URIs and secret. Like
//! the Console, it is system-managed: every start brings its scope ceiling and
//! protocol shape back to what Login needs, so an upgrade or a stray edit never
//! leaves sign-in broken. Redirect URIs and credentials stay as installed.

use sea_orm::{
    ActiveModelTrait, ColumnTrait, ConnectionTrait, DatabaseConnection, DatabaseTransaction,
    DbBackend, EntityTrait, QueryFilter, Set, Statement, TransactionTrait,
};
use serde_json::json;

use super::{
    console::{ensure_scope_rows, replace_client_scopes},
    oauth_resource::graphql_resource_oid,
};
use crate::{
    application::{
        error::{AppError, codes::common::CommonErrorCode},
        setting::LoginClientIdSetting,
    },
    database::{
        audit, client_authorization_boundary,
        entity::{
            client::{Column as ClientColumn, Entity as ClientEntity},
            client_openid_connect,
            client_openid_connect::{
                Column as ClientOpenIdConnectColumn, Entity as ClientOpenIdConnectEntity,
            },
        },
        repository::setting::read_setting,
    },
    domain::openid_connect::{ApiScope, GrantType, ResponseType, model::claim::StandardScopes},
};

/// Scopes the Login application requests for sign-in and the account center.
pub const LOGIN_SCOPE_NAMES: [&str; 9] = [
    StandardScopes::OPENID,
    StandardScopes::PROFILE,
    StandardScopes::EMAIL,
    StandardScopes::OFFLINE_ACCESS,
    ApiScope::USER_READ,
    ApiScope::USER_WRITE,
    ApiScope::SESSION_READ,
    ApiScope::SESSION_REVOKE,
    ApiScope::PASSWORD_CHANGE,
];

/// Reconcile the installed Login client. Does nothing before installation.
pub async fn ensure_login_client(db: &DatabaseConnection) -> Result<(), AppError> {
    let txn = db.begin().await.map_err(AppError::internal)?;
    ensure_login_client_in_transaction(&txn).await?;
    txn.commit().await.map_err(AppError::internal)
}

async fn ensure_login_client_in_transaction(db: &DatabaseTransaction) -> Result<(), AppError> {
    let Some(oid) = read_setting::<LoginClientIdSetting, _>(db).await? else {
        return Ok(());
    };
    let client = ClientEntity::find()
        .filter(ClientColumn::Oid.eq(oid))
        .one(db)
        .await
        .map_err(AppError::internal)?
        .ok_or_else(|| AppError::from_code(CommonErrorCode::InternalError))?;
    if !client.built_in {
        return Err(AppError::from_code(CommonErrorCode::Forbidden));
    }

    let scope_ids =
        ensure_scope_rows(db, &LOGIN_SCOPE_NAMES, graphql_resource_oid(db).await?).await?;
    let mut changed = replace_client_scopes(db, client.id, &scope_ids).await?;

    let grant_types = json!([
        GrantType::AuthorizationCode.as_str(),
        GrantType::RefreshToken.as_str()
    ]);
    let response_types = json!([ResponseType::Code]);
    if let Some(row) = ClientOpenIdConnectEntity::find()
        .filter(ClientOpenIdConnectColumn::ClientId.eq(client.id))
        .one(db)
        .await
        .map_err(AppError::internal)?
        && (row.grant_types.as_ref() != Some(&grant_types)
            || row.response_types.as_ref() != Some(&response_types))
    {
        let mut active: client_openid_connect::ActiveModel = row.into();
        active.grant_types = Set(Some(grant_types));
        active.response_types = Set(Some(response_types));
        active.update(db).await.map_err(AppError::internal)?;
        changed = true;
    }

    if changed {
        db.execute_raw(Statement::from_sql_and_values(
            DbBackend::Postgres,
            "UPDATE client SET version = gen_random_uuid(), updated_at = now() WHERE id = $1",
            [client.id.into()],
        ))
        .await
        .map_err(AppError::internal)?;
        client_authorization_boundary::withdraw_client_authorizations(db, client.id)
            .await
            .map_err(AppError::internal)?;
        audit::record(db, "client.update", "client", oid)
            .await
            .map_err(AppError::internal)?;
    }
    Ok(())
}
