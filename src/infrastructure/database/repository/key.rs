use async_trait::async_trait;
use chrono::{DateTime, Utc};
use sea_orm::{ActiveModelTrait, ColumnTrait, DatabaseConnection, EntityTrait, QueryFilter, Set};
use serde_json::Value;
use uuid::Uuid;

use super::shared::{decode_nonnullable_expiry, encode_nonnullable_expiry};
use crate::domain::key::{
    Key, KeyData, KeyOid, KeyType, ParseKeyTypeError,
    repository::{KeyRepository, KeyRepositoryError},
};
use crate::infrastructure::database::entity::{key, key::Entity as KeyEntity};

pub struct KeyRepositoryImpl {
    db: DatabaseConnection,
}

impl KeyRepositoryImpl {
    pub fn new(db: DatabaseConnection) -> Self {
        Self { db }
    }

    async fn find_model_by_oid(
        &self,
        oid: KeyOid,
    ) -> Result<Option<key::Model>, KeyRepositoryError> {
        KeyEntity::find()
            .filter(key::Column::Oid.eq(Uuid::from(oid)))
            .one(&self.db)
            .await
            .map_err(KeyRepositoryError::QueryFailed)
    }
}

fn deserialize_key_data(raw: &Value) -> Result<KeyData, KeyRepositoryError> {
    serde_json::from_value(raw.clone()).map_err(KeyRepositoryError::Deserialize)
}

fn serialize_key_data(data: &KeyData) -> Result<Value, KeyRepositoryError> {
    serde_json::to_value(data).map_err(KeyRepositoryError::Serialize)
}

pub fn to_domain(model: key::Model) -> Result<Key, KeyRepositoryError> {
    Ok(Key {
        oid: model.oid.into(),
        r#type: model.r#type.parse().map_err(|error: ParseKeyTypeError| {
            KeyRepositoryError::InvalidKeyType(error.to_string())
        })?,
        data: deserialize_key_data(&model.data)?,
        expires_at: decode_nonnullable_expiry(model.expires_at),
        revoked_at: model.revoked_at.map(|value| value.with_timezone(&Utc)),
        created_at: DateTime::from_naive_utc_and_offset(model.created_at, Utc),
        updated_at: model
            .updated_at
            .map(|value| DateTime::from_naive_utc_and_offset(value, Utc)),
    })
}

#[async_trait]
impl KeyRepository for KeyRepositoryImpl {
    async fn find_by_oid(&self, oid: KeyOid) -> Result<Option<Key>, KeyRepositoryError> {
        self.find_model_by_oid(oid)
            .await?
            .map(to_domain)
            .transpose()
    }

    async fn list_available_asymmetric(&self) -> Result<Vec<Key>, KeyRepositoryError> {
        KeyEntity::find()
            .filter(key::Column::Type.eq(KeyType::Asymmetric.to_string()))
            .filter(key::Column::RevokedAt.is_null())
            .all(&self.db)
            .await
            .map_err(KeyRepositoryError::ListAvailableFailed)?
            .into_iter()
            .map(to_domain)
            .collect()
    }

    async fn list_available_symmetric(&self) -> Result<Vec<Key>, KeyRepositoryError> {
        KeyEntity::find()
            .filter(key::Column::Type.eq(KeyType::Symmetric.to_string()))
            .filter(key::Column::RevokedAt.is_null())
            .all(&self.db)
            .await
            .map_err(KeyRepositoryError::ListAvailableFailed)?
            .into_iter()
            .map(to_domain)
            .collect()
    }

    async fn create(
        &self,
        key_type: KeyType,
        data: &KeyData,
        expires_at: Option<DateTime<Utc>>,
    ) -> Result<Key, KeyRepositoryError> {
        let now = Utc::now();
        let active = key::ActiveModel {
            oid: Set(Uuid::new_v4()),
            r#type: Set(key_type.to_string()),
            data: Set(serialize_key_data(data)?),
            expires_at: Set(encode_nonnullable_expiry(expires_at)),
            revoked_at: Set(None),
            created_at: Set(now.naive_utc()),
            updated_at: Set(Some(now.naive_utc())),
            ..Default::default()
        };

        to_domain(
            active
                .insert(&self.db)
                .await
                .map_err(KeyRepositoryError::CreateFailed)?,
        )
    }

    async fn update_certificate_by_oid(
        &self,
        oid: KeyOid,
        certificate_pem: &str,
    ) -> Result<Option<Key>, KeyRepositoryError> {
        let Some(model) = self.find_model_by_oid(oid).await? else {
            return Ok(None);
        };

        let data = match deserialize_key_data(&model.data)? {
            KeyData::Asymmetric(mut data) => {
                data.certificate = Some(certificate_pem.to_owned());
                KeyData::Asymmetric(data)
            }
            KeyData::Symmetric(_) => {
                return Err(KeyRepositoryError::CertificateRequiresAsymmetricKey);
            }
        };

        let mut active: key::ActiveModel = model.into();
        active.data = Set(serialize_key_data(&data)?);
        active.updated_at = Set(Some(Utc::now().naive_utc()));
        to_domain(
            active
                .update(&self.db)
                .await
                .map_err(KeyRepositoryError::UpdateFailed)?,
        )
        .map(Some)
    }

    async fn revoke_by_oid(
        &self,
        oid: KeyOid,
        revoked_at: DateTime<Utc>,
    ) -> Result<Option<Key>, KeyRepositoryError> {
        let Some(model) = self.find_model_by_oid(oid).await? else {
            return Ok(None);
        };

        let mut active: key::ActiveModel = model.into();
        active.revoked_at = Set(Some(revoked_at.into()));
        active.updated_at = Set(Some(Utc::now().naive_utc()));
        to_domain(
            active
                .update(&self.db)
                .await
                .map_err(KeyRepositoryError::UpdateFailed)?,
        )
        .map(Some)
    }
}

#[cfg(test)]
mod tests {
    use super::to_domain;
    use chrono::{DateTime, NaiveDateTime, Utc};
    use serde_json::json;
    use uuid::Uuid;

    use crate::domain::key::KeyData;
    use crate::infrastructure::database::entity::key;

    #[test]
    fn to_domain_wraps_required_expiry_in_some() {
        let model = key::Model {
            id: 1,
            oid: Uuid::new_v4(),
            r#type: "asymmetric".to_owned(),
            data: json!({
                "public_key": "public",
                "private_key": "private",
                "certificate": null,
            }),
            expires_at: DateTime::parse_from_rfc3339("2026-01-01T00:00:00+00:00").unwrap(),
            revoked_at: None,
            created_at: NaiveDateTime::parse_from_str("2026-01-01 00:00:00", "%Y-%m-%d %H:%M:%S")
                .unwrap(),
            updated_at: None,
        };

        let key = to_domain(model).unwrap();

        assert!(matches!(key.data, KeyData::Asymmetric(_)));
        assert_eq!(
            key.expires_at,
            Some(
                DateTime::parse_from_rfc3339("2026-01-01T00:00:00+00:00")
                    .unwrap()
                    .with_timezone(&Utc)
            )
        );
    }
}
