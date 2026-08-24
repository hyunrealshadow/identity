use async_trait::async_trait;
use chrono::{DateTime, Utc};
use sea_orm::{
    ColumnTrait, DatabaseConnection, EntityTrait, QueryFilter, Set, sea_query::OnConflict,
};
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

    let value = serde_json::from_value(value).map_err(SettingRepositoryError::Deserialize)?;
    S::validate(&value)
        .map_err(|error| SettingRepositoryError::Validation(error.message().to_owned()))?;

    Ok(SettingEntry {
        oid: oid.into(),
        key,
        value,
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

        let active = setting::ActiveModel {
            oid: Set(Uuid::new_v4()),
            key: Set(S::KEY.to_owned()),
            value: Set(serialized),
            created_at: Set(now),
            updated_at: Set(Some(now)),
            ..Default::default()
        };

        let model = SettingEntity::insert(active)
            .on_conflict(
                OnConflict::column(setting::Column::Key)
                    .update_columns([setting::Column::Value, setting::Column::UpdatedAt])
                    .to_owned(),
            )
            .exec_with_returning(&self.db)
            .await
            .map_err(|e| SettingRepositoryError::UpdateFailed(Box::new(e)))?;
        to_domain::<S>(model)
    }
}

#[cfg(test)]
mod tests {
    use super::to_domain;
    use crate::database::entity::setting;
    use chrono::Utc;
    use identity_domain::setting::{SettingDefinition, SettingValidationError};
    use uuid::Uuid;

    struct PositiveSetting;

    impl SettingDefinition for PositiveSetting {
        type Value = i32;
        const KEY: &'static str = "positive";

        fn default_value() -> Self::Value {
            1
        }

        fn validate(value: &Self::Value) -> Result<(), SettingValidationError> {
            (*value > 0)
                .then_some(())
                .ok_or_else(|| SettingValidationError::new("must be positive"))
        }
    }

    #[test]
    fn persisted_setting_is_validated_before_entering_the_domain() {
        let now = Utc::now().naive_utc();
        let error = to_domain::<PositiveSetting>(setting::Model {
            id: 1,
            oid: Uuid::new_v4(),
            key: PositiveSetting::KEY.to_owned(),
            value: serde_json::json!(0),
            created_at: now,
            updated_at: None,
        })
        .unwrap_err();

        assert!(error.to_string().contains("must be positive"));
    }
}
