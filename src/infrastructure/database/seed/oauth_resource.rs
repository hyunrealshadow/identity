//! Baseline resource rows for the management authorization model.
//!
//! The reserved GraphQL API resource is version-controlled by this seed. Scope
//! ownership is seeded separately after this entry, so the resource exists
//! before any resource-owned built-in API scope is inserted.

use async_trait::async_trait;
use identity_domain::openid_connect::API_RESOURCE;
use sea_orm::{
    ColumnTrait, ConnectionTrait, DatabaseConnection, DatabaseTransaction, DbErr, EntityTrait,
    QueryFilter, Set, TransactionTrait, sea_query::OnConflict,
};
use uuid::Uuid;

use super::Seed;
use crate::{
    application::error::{AppError, codes::authorization::AuthorizationErrorCode},
    database::entity::{
        resource,
        resource::{Column as ResourceColumn, Entity as ResourceEntity},
    },
};

pub struct OAuthResourceDefaultsSeed;

#[async_trait]
impl Seed for OAuthResourceDefaultsSeed {
    fn name(&self) -> &'static str {
        "oauth_resource_defaults"
    }

    async fn run(&self, db: &DatabaseConnection) -> Result<(), AppError> {
        let transaction = db.begin().await.map_err(AppError::internal)?;
        ensure_graphql_resource_coverage(&transaction).await?;
        transaction.commit().await.map_err(AppError::internal)?;
        Ok(())
    }
}

/// Idempotently ensure the reserved GraphQL resource. Resource identity, URI,
/// enabled state and creation time are preserved on repeated runs; scope rows
/// point at this resource instead of duplicating a scope list on the resource.
pub async fn ensure_graphql_resource_coverage(
    transaction: &DatabaseTransaction,
) -> Result<(), AppError> {
    ResourceEntity::insert(resource::ActiveModel {
        oid: Set(Uuid::new_v4()),
        uri: Set(API_RESOURCE.to_owned()),
        name: Set("Identity GraphQL API".to_owned()),
        enabled: Set(true),
        ..Default::default()
    })
    .on_conflict(
        OnConflict::column(ResourceColumn::Uri)
            .do_nothing()
            .to_owned(),
    )
    .exec_without_returning(transaction)
    .await
    .map_err(AppError::internal)?;
    Ok(())
}

/// Resolve the reserved GraphQL resource by URI. This is the authoritative
/// owner for built-in API scopes and management RBAC associations.
pub async fn graphql_resource_oid(db: &impl ConnectionTrait) -> Result<Uuid, AppError> {
    ResourceEntity::find()
        .filter(ResourceColumn::Uri.eq(API_RESOURCE))
        .one(db)
        .await
        .map_err(AppError::internal)?
        .map(|row| row.oid)
        .ok_or_else(|| {
            AppError::map_source(AuthorizationErrorCode::RbacPolicyUnavailable)(
                DbErr::RecordNotFound("the reserved GraphQL API resource is missing".to_owned()),
            )
        })
}
