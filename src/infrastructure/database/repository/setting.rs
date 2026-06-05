use async_trait::async_trait;
use chrono::{DateTime, Utc};
use sea_orm::{ActiveModelTrait, ColumnTrait, DatabaseConnection, EntityTrait, QueryFilter, Set};
use serde_json::Value;
use uuid::Uuid;

use crate::database::entity::{setting, setting::Entity as SettingEntity};
use identity_domain::setting::{
    SettingDefinition, SettingEntry,
    repository::{SettingRepository, SettingRepositoryError},
};

pub struct SettingRepositoryImpl {
    db: DatabaseConnection,
}

impl SettingRepositoryImpl {
    pub fn new(db: DatabaseConnection) -> Self {
        Self { db }
    }
}

fn serialize_value<S>(value: &S::Value) -> Result<Value, SettingRepositoryError>
where
    S: SettingDefinition,
{
    serde_json::to_value(value).map_err(SettingRepositoryError::Serialize)
}

fn to_domain<S>(model: setting::Model) -> Result<SettingEntry<S::Value>, SettingRepositoryError>
where
    S: SettingDefinition,
{
    let setting::Model {
        oid,
        key,
        value,
        created_at,
        updated_at,
        ..
    } = model;

    Ok(SettingEntry {
        oid: oid.into(),
        key,
        value: serde_json::from_value(value).map_err(SettingRepositoryError::Deserialize)?,
        created_at: DateTime::from_naive_utc_and_offset(created_at, Utc),
        updated_at: updated_at.map(|value| DateTime::from_naive_utc_and_offset(value, Utc)),
    })
}

#[async_trait]
impl SettingRepository for SettingRepositoryImpl {
    async fn get<S>(&self) -> Result<Option<SettingEntry<S::Value>>, SettingRepositoryError>
    where
        S: SettingDefinition,
    {
        SettingEntity::find()
            .filter(setting::Column::Key.eq(S::KEY))
            .one(&self.db)
            .await
            .map_err(|e| SettingRepositoryError::QueryFailed(Box::new(e)))?
            .map(to_domain::<S>)
            .transpose()
    }

    async fn upsert<S>(
        &self,
        value: &S::Value,
    ) -> Result<SettingEntry<S::Value>, SettingRepositoryError>
    where
        S: SettingDefinition,
    {
        S::validate(value)
            .map_err(|error| SettingRepositoryError::Validation(error.message().to_owned()))?;

        let now = Utc::now().naive_utc();
        let serialized = serialize_value::<S>(value)?;

        if let Some(model) = SettingEntity::find()
            .filter(setting::Column::Key.eq(S::KEY))
            .one(&self.db)
            .await
            .map_err(|e| SettingRepositoryError::QueryFailed(Box::new(e)))?
        {
            let mut active: setting::ActiveModel = model.into();
            active.value = Set(serialized);
            active.updated_at = Set(Some(now));

            to_domain::<S>(
                active
                    .update(&self.db)
                    .await
                    .map_err(|e| SettingRepositoryError::UpdateFailed(Box::new(e)))?,
            )
        } else {
            let active = setting::ActiveModel {
                oid: Set(Uuid::new_v4()),
                key: Set(S::KEY.to_owned()),
                value: Set(serialized),
                created_at: Set(now),
                updated_at: Set(Some(now)),
                ..Default::default()
            };

            to_domain::<S>(
                active
                    .insert(&self.db)
                    .await
                    .map_err(|e| SettingRepositoryError::CreateFailed(Box::new(e)))?,
            )
        }
    }
}
