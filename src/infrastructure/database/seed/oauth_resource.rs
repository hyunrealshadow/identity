use super::Seed;
use super::scope::BUILT_IN_OPENID_CONNECT_SCOPES;
use crate::application::error::{AppError, codes::common::CommonErrorCode};
use crate::database::entity::resource;
use async_trait::async_trait;
use chrono::Utc;
use identity_domain::openid_connect::API_RESOURCE;
use sea_orm::{DatabaseConnection, EntityTrait, Set, sea_query::OnConflict};
use uuid::Uuid;

pub struct OAuthResourceDefaultsSeed;
#[async_trait]
impl Seed for OAuthResourceDefaultsSeed {
    fn name(&self) -> &'static str {
        "oauth_resource_defaults"
    }
    async fn run(&self, db: &DatabaseConnection) -> Result<(), AppError> {
        resource::Entity::insert(resource::ActiveModel {
            oid: Set(Uuid::new_v4()),
            uri: Set(API_RESOURCE.to_owned()),
            name: Set("Identity GraphQL API".to_owned()),
            scopes: Set(serde_json::json!(
                BUILT_IN_OPENID_CONNECT_SCOPES
                    .iter()
                    .map(|scope| scope.name)
                    .collect::<Vec<_>>()
            )),
            enabled: Set(true),
            created_at: Set(Utc::now().into()),
            updated_at: Set(None),
        })
        .on_conflict(
            OnConflict::column(resource::Column::Uri)
                .do_nothing()
                .to_owned(),
        )
        .try_insert()
        .exec_without_returning(db)
        .await
        .map_err(AppError::map_source(CommonErrorCode::ResourceLookupFailed))?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sea_orm::{DatabaseBackend, MockDatabase, MockExecResult};

    #[tokio::test]
    async fn initialization_never_overwrites_existing_resource_policy() {
        let db = MockDatabase::new(DatabaseBackend::Postgres)
            .append_exec_results([MockExecResult {
                last_insert_id: 0,
                rows_affected: 0,
            }])
            .into_connection();
        OAuthResourceDefaultsSeed.run(&db).await.unwrap();
        let log = format!("{:?}", db.into_transaction_log());
        assert!(log.contains(r#"ON CONFLICT (\"uri\") DO NOTHING"#), "{log}");
        assert!(log.contains("urn:identity:graphql"));
    }
}
