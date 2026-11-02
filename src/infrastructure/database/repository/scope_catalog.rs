use std::collections::BTreeMap;

use identity_domain::openid_connect::scope_catalog::{
    ScopeCatalogError, ScopeCatalogRepository, ScopeDescription,
};
use sea_orm::{ConnectionTrait, DatabaseConnection, DbBackend, Statement, Value};
use serde_json::Value as JsonValue;

use super::localized;

pub struct ScopeCatalogRepositoryImpl {
    db: DatabaseConnection,
}

impl ScopeCatalogRepositoryImpl {
    pub fn new(db: DatabaseConnection) -> Self {
        Self { db }
    }
}

fn storage(error: sea_orm::DbErr) -> ScopeCatalogError {
    ScopeCatalogError(error.to_string())
}

fn text_map(value: JsonValue) -> Result<BTreeMap<String, String>, ScopeCatalogError> {
    localized::decode_text(value)
        .map(|entries| {
            entries
                .into_iter()
                .map(|entry| (entry.locale, entry.value))
                .collect()
        })
        .map_err(|error| ScopeCatalogError(error.to_string()))
}

fn resource_filter(index: usize, resources: &[String]) -> (String, Value) {
    let encoded = serde_json::to_string(resources).expect("string list is serializable");
    (
        format!(
            "scope.resource_id IS NULL OR (resource.oid = scope.resource_id \
             AND resource.enabled = true \
             AND resource.uri IN (SELECT jsonb_array_elements_text(${index}::jsonb)))"
        ),
        encoded.into(),
    )
}

#[async_trait::async_trait]
impl ScopeCatalogRepository for ScopeCatalogRepositoryImpl {
    async fn list_names(&self) -> Result<Vec<String>, ScopeCatalogError> {
        let rows = self
            .db
            .query_all_raw(Statement::from_string(
                DbBackend::Postgres,
                "SELECT code FROM \"scope\" WHERE enabled = true ORDER BY code".to_owned(),
            ))
            .await
            .map_err(storage)?;
        rows.into_iter()
            .map(|row| row.try_get::<String>("", "code").map_err(storage))
            .collect()
    }

    async fn find_by_names(
        &self,
        names: &[&str],
    ) -> Result<Vec<ScopeDescription>, ScopeCatalogError> {
        if names.is_empty() {
            return Ok(Vec::new());
        }
        let mut values: Vec<Value> = Vec::with_capacity(names.len());
        values.extend(names.iter().map(|name| (*name).to_owned().into()));
        let placeholders = (1..=names.len())
            .map(|index| format!("${index}"))
            .collect::<Vec<_>>()
            .join(", ");
        let rows = self
            .db
            .query_all_raw(Statement::from_sql_and_values(
                DbBackend::Postgres,
                format!(
                    "SELECT code, name, names, description, descriptions \
                     FROM \"scope\" WHERE enabled = true AND code IN ({placeholders})"
                ),
                values,
            ))
            .await
            .map_err(storage)?;
        rows.into_iter().map(description).collect()
    }

    async fn list_names_for_resources(
        &self,
        resources: &[String],
    ) -> Result<Vec<String>, ScopeCatalogError> {
        if resources.is_empty() {
            return self.list_names().await;
        }
        let (filter, value) = resource_filter(1, resources);
        let rows = self
            .db
            .query_all_raw(Statement::from_sql_and_values(
                DbBackend::Postgres,
                format!(
                    "SELECT DISTINCT scope.code \
                     FROM \"scope\" scope LEFT JOIN resource ON resource.oid = scope.resource_id \
                     WHERE scope.enabled = true AND ({filter}) \
                     ORDER BY scope.code"
                ),
                [value],
            ))
            .await
            .map_err(storage)?;
        rows.into_iter()
            .map(|row| row.try_get::<String>("", "code").map_err(storage))
            .collect()
    }

    async fn find_by_names_for_resources(
        &self,
        names: &[&str],
        resources: &[String],
    ) -> Result<Vec<ScopeDescription>, ScopeCatalogError> {
        if resources.is_empty() {
            return self.find_by_names(names).await;
        }
        if names.is_empty() {
            return Ok(Vec::new());
        }
        let mut values: Vec<Value> = Vec::with_capacity(names.len() + 1);
        values.extend(names.iter().map(|name| (*name).to_owned().into()));
        let (filter, resource_value) = resource_filter(names.len() + 1, resources);
        values.push(resource_value);
        let placeholders = (1..=names.len())
            .map(|index| format!("${index}"))
            .collect::<Vec<_>>()
            .join(", ");
        let rows = self
            .db
            .query_all_raw(Statement::from_sql_and_values(
                DbBackend::Postgres,
                format!(
                    "SELECT scope.code, scope.name, scope.names, scope.description, scope.descriptions \
                     FROM \"scope\" scope LEFT JOIN resource ON resource.oid = scope.resource_id \
                     WHERE scope.enabled = true AND scope.code IN ({placeholders}) AND ({filter})"
                ),
                values,
            ))
            .await
            .map_err(storage)?;
        rows.into_iter().map(description).collect()
    }
}

fn description(row: sea_orm::QueryResult) -> Result<ScopeDescription, ScopeCatalogError> {
    let names = text_map(row.try_get::<JsonValue>("", "names").map_err(storage)?)?;
    let descriptions = text_map(
        row.try_get::<JsonValue>("", "descriptions")
            .map_err(storage)?,
    )?;
    Ok(ScopeDescription {
        code: row.try_get::<String>("", "code").map_err(storage)?,
        name: row.try_get::<String>("", "name").map_err(storage)?,
        names,
        description: row.try_get::<String>("", "description").map_err(storage)?,
        descriptions,
    })
}
