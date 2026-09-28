use std::collections::HashMap;

use chrono::Utc;
use sea_orm::{ColumnTrait, ConnectionTrait, EntityTrait, QueryFilter, Set, sea_query::OnConflict};
use serde_json::Value;
use uuid::Uuid;

use crate::database::entity::setting;
use identity_application::{
    error::{AppError, codes::common::CommonErrorCode},
    setting::{SettingChanges, SettingDefinition, SettingRegistry, SettingSection},
};

/// The stored value of `S`, or its declared default when it has no row.
///
/// For reads that must see the database itself, such as inside a
/// transaction; everything else reads the settings snapshot.
pub async fn read_setting<S, C>(db: &C) -> Result<S::Value, AppError>
where
    S: SettingDefinition,
    C: ConnectionTrait,
{
    let row = setting::Entity::find()
        .filter(setting::Column::Key.eq(S::KEY))
        .one(db)
        .await
        .map_err(|error| AppError::from_code(CommonErrorCode::InternalError).with_source(error))?;
    match row {
        Some(row) => Ok(S::decode(&row.value)?),
        None => Ok(S::default_value()),
    }
}

/// Binds separate dotted keys beneath a section prefix from the database.
pub async fn read_section<T, C>(db: &C) -> Result<T, AppError>
where
    T: SettingSection,
    C: ConnectionTrait,
{
    let rows = setting::Entity::find()
        .filter(setting::Column::Key.starts_with(format!("{}.", T::PREFIX)))
        .all(db)
        .await
        .map_err(|error| AppError::from_code(CommonErrorCode::InternalError).with_source(error))?;
    let raw: HashMap<_, _> = rows.into_iter().map(|row| (row.key, row.value)).collect();
    let snapshot = SettingRegistry::default()
        .register_section::<T>()
        .resolve(&raw, None)?;
    Ok(snapshot.section::<T>())
}

/// Writes every change in one statement, replacing stored values.
///
/// Takes any connection, so the writes can join a larger transaction.
#[tracing::instrument(skip_all, name = "db.query", fields(db.system = "postgresql", db.operation = "write_settings"))]
pub async fn write_settings<C>(db: &C, changes: SettingChanges) -> Result<(), AppError>
where
    C: ConnectionTrait,
{
    insert_rows(
        db,
        changes,
        OnConflict::column(setting::Column::Key)
            .update_columns([setting::Column::Value, setting::Column::UpdatedAt])
            .to_owned(),
    )
    .await
}

/// Stores each value whose key has no row yet, keeping every stored value.
///
/// One `INSERT ... ON CONFLICT (key) DO NOTHING`: concurrent callers race
/// safely on the unique key.
#[tracing::instrument(skip_all, name = "db.query", fields(db.system = "postgresql", db.operation = "insert_missing_settings"))]
pub async fn insert_missing_settings<C>(
    db: &C,
    values: impl IntoIterator<Item = (String, Value)>,
) -> Result<(), AppError>
where
    C: ConnectionTrait,
{
    insert_rows(
        db,
        values,
        OnConflict::column(setting::Column::Key)
            .do_nothing()
            .to_owned(),
    )
    .await
}

async fn insert_rows<C>(
    db: &C,
    values: impl IntoIterator<Item = (String, Value)>,
    on_conflict: OnConflict,
) -> Result<(), AppError>
where
    C: ConnectionTrait,
{
    let now = Utc::now().naive_utc();
    let rows = values
        .into_iter()
        .map(|(key, value)| setting::ActiveModel {
            oid: Set(Uuid::new_v4()),
            key: Set(key),
            value: Set(value),
            created_at: Set(now),
            updated_at: Set(Some(now)),
            ..Default::default()
        })
        .collect::<Vec<_>>();
    if rows.is_empty() {
        return Ok(());
    }

    setting::Entity::insert_many(rows)
        .on_conflict(on_conflict)
        .exec_without_returning(db)
        .await
        .map_err(|error| AppError::from_code(CommonErrorCode::InternalError).with_source(error))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use identity_application::setting::{
        DynamicRegistrationSettings, InstallationSettings, LoginDomainSetting,
        OpenIdConnectSettings, SettingChanges,
    };
    use sea_orm::{DatabaseBackend, MockDatabase, MockExecResult};
    use serde_json::json;
    use uuid::Uuid;

    use super::{read_section, write_settings};
    use crate::database::entity::setting;

    #[tokio::test]
    async fn reads_a_section_from_separate_dotted_keys() {
        let now = chrono::Utc::now();
        let row = |id, key: &str, value| setting::Model {
            id,
            oid: Uuid::new_v4(),
            key: key.to_owned(),
            value,
            created_at: now.naive_utc(),
            updated_at: None,
        };
        let db = MockDatabase::new(DatabaseBackend::Postgres)
            .append_query_results([[
                row(1, "app.installation.initialized", json!(true)),
                row(2, "app.installation.initialized_at", json!(now)),
            ]])
            .into_connection();

        let installation = read_section::<InstallationSettings, _>(&db).await.unwrap();

        assert!(installation.initialized);
        assert_eq!(installation.initialized_at, Some(now));
        let sql = format!("{:?}", db.into_transaction_log()[0]);
        assert!(sql.contains("app.installation.%"), "{sql}");
    }

    #[tokio::test]
    async fn writes_every_change_in_one_upsert() {
        let db = MockDatabase::new(DatabaseBackend::Postgres)
            .append_exec_results([MockExecResult {
                last_insert_id: 0,
                rows_affected: 2,
            }])
            .into_connection();
        let changes = SettingChanges::default()
            .set_section_field(
                &OpenIdConnectSettings {
                    dynamic_registration: DynamicRegistrationSettings { enabled: true },
                    ..OpenIdConnectSettings::default()
                },
                "dynamic_registration.enabled",
            )
            .unwrap()
            .set::<LoginDomainSetting>(&Some("https://login.example".to_owned()))
            .unwrap();

        write_settings(&db, changes).await.unwrap();

        let log = db.into_transaction_log();
        assert_eq!(log.len(), 1);
        let sql = format!("{:?}", log[0]);
        assert!(
            sql.contains(r#"ON CONFLICT (\"key\") DO UPDATE SET \"value\" = \"excluded\".\"value\", \"updated_at\" = \"excluded\".\"updated_at\""#),
            "{sql}"
        );
        assert!(sql.contains("https://login.example"), "{sql}");
    }

    #[tokio::test]
    async fn empty_changes_touch_nothing() {
        let db = MockDatabase::new(DatabaseBackend::Postgres).into_connection();

        write_settings(&db, SettingChanges::default())
            .await
            .unwrap();

        assert!(db.into_transaction_log().is_empty());
    }
}
