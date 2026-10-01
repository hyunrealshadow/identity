use crate::database::entity::resource;
use async_trait::async_trait;
use identity_domain::openid_connect::resource::{
    OAuthResource, OAuthResourceRepository, OAuthResourceRepositoryError,
};
use sea_orm::{ColumnTrait, DatabaseConnection, EntityTrait, QueryFilter};
use std::sync::Arc;

pub struct OAuthResourceRepositoryImpl {
    db: Arc<DatabaseConnection>,
}
impl OAuthResourceRepositoryImpl {
    pub fn new(db: DatabaseConnection) -> Self {
        Self { db: Arc::new(db) }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sea_orm::{DatabaseBackend, MockDatabase};

    #[tokio::test]
    async fn lookup_preserves_exact_identifiers_scopes_and_disabled_state() {
        let uri = "https://API.example.com/resource?tenant=1";
        let model = resource::Model {
            oid: uuid::Uuid::new_v4(),
            uri: uri.to_owned(),
            name: "Resource".to_owned(),
            scopes: serde_json::json!(["account.read"]),
            enabled: false,
            created_at: chrono::Utc::now().into(),
            updated_at: None,
        };
        let db = MockDatabase::new(DatabaseBackend::Postgres)
            .append_query_results([vec![model]])
            .into_connection();
        let repo = OAuthResourceRepositoryImpl::new(db.clone());
        let resource = repo.find_by_uri(uri).await.unwrap().unwrap();
        assert_eq!(resource.uri, uri);
        assert_eq!(resource.scopes, ["account.read"]);
        assert!(!resource.enabled);
        let log = db.into_transaction_log();
        assert!(format!("{log:?}").contains(uri));
    }
}
#[async_trait]
impl OAuthResourceRepository for OAuthResourceRepositoryImpl {
    async fn find_by_uri(
        &self,
        uri: &str,
    ) -> Result<Option<OAuthResource>, OAuthResourceRepositoryError> {
        let row = resource::Entity::find()
            .filter(resource::Column::Uri.eq(uri))
            .one(&*self.db)
            .await
            .map_err(|error| OAuthResourceRepositoryError(error.to_string()))?;
        row.map(|row| {
            Ok(OAuthResource {
                uri: row.uri,
                scopes: serde_json::from_value(row.scopes)
                    .map_err(|error| OAuthResourceRepositoryError(error.to_string()))?,
                enabled: row.enabled,
            })
        })
        .transpose()
    }
}
