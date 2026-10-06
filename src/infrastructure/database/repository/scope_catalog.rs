use identity_domain::openid_connect::scope_catalog::{
    ScopeCatalogError, ScopeCatalogRepository, ScopeDescription,
};
use sea_orm::{ColumnTrait, DatabaseConnection, EntityTrait, QueryFilter, QueryOrder, QuerySelect};
use serde_json::from_value;

use crate::database::entity::scope;

pub struct ScopeCatalogRepositoryImpl {
    db: DatabaseConnection,
}

impl ScopeCatalogRepositoryImpl {
    pub fn new(db: DatabaseConnection) -> Self {
        Self { db }
    }
}

#[async_trait::async_trait]
impl ScopeCatalogRepository for ScopeCatalogRepositoryImpl {
    async fn list_names(&self) -> Result<Vec<String>, ScopeCatalogError> {
        scope::Entity::find()
            .filter(scope::Column::Protocol.eq("openid_connect"))
            .select_only()
            .column(scope::Column::Name)
            .order_by_asc(scope::Column::Name)
            .into_tuple::<String>()
            .all(&self.db)
            .await
            .map_err(|error| ScopeCatalogError(error.to_string()))
    }

    async fn find_by_names(
        &self,
        names: &[&str],
    ) -> Result<Vec<ScopeDescription>, ScopeCatalogError> {
        if names.is_empty() {
            return Ok(Vec::new());
        }
        scope::Entity::find()
            .filter(scope::Column::Protocol.eq("openid_connect"))
            .filter(scope::Column::Name.is_in(names.iter().copied()))
            .all(&self.db)
            .await
            .map_err(|error| ScopeCatalogError(error.to_string()))?
            .into_iter()
            .map(|row| {
                Ok(ScopeDescription {
                    name: row.name,
                    display_name: row.display_name,
                    description: row.description,
                    descriptions: from_value(row.descriptions)
                        .map_err(|error| ScopeCatalogError(error.to_string()))?,
                })
            })
            .collect()
    }
}
