//! Protected Login (account center) OAuth client reconciliation.
//!
//! Installation provisions the client with its redirect URIs and secret. Like
//! the Console, it is system-managed: every start brings its scope ceiling and
//! protocol shape back to what Login needs, so an upgrade or a stray edit never
//! leaves sign-in broken. Redirect URIs and credentials stay as installed.

use sea_orm::{
    ActiveModelTrait, ColumnTrait, DatabaseConnection, DatabaseTransaction, EntityTrait,
    QueryFilter, Set, TransactionTrait,
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
        audit,
        entity::{
            client::{Column as ClientColumn, Entity as ClientEntity},
            client_openid_connect,
            client_openid_connect::{
                Column as ClientOpenIdConnectColumn, Entity as ClientOpenIdConnectEntity,
            },
        },
        repository::setting::read_setting,
    },
    domain::openid_connect::{GrantType, ResponseType},
};

/// Scopes the Login application requests for sign-in and the account center.
pub const LOGIN_SCOPE_NAMES: [&str; 9] = [
    "openid",
    "profile",
    "email",
    "offline_access",
    "account.read",
    "account.update",
    "session.read",
    "session.revoke",
    "password.change",
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
        audit::record(db, "client.update", "client", oid)
            .await
            .map_err(AppError::internal)?;
    }
    Ok(())
}
