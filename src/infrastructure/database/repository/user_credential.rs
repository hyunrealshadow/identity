use crate::database::entity::{
    user, user::Entity as UserEntity, user_credential,
    user_credential::Entity as UserCredentialEntity,
};
use async_trait::async_trait;
use chrono::Utc;
use identity_domain::user::{
    CredentialData, CredentialType, Password, UserCredential, UserCredentialOid, UserOid,
    repository::{UserCredentialRepository, UserCredentialRepositoryError},
};
use sea_orm::{
    ActiveModelTrait, ColumnTrait, DatabaseConnection, EntityTrait, QueryFilter, QuerySelect, Set,
    TransactionTrait,
};

pub struct UserCredentialRepositoryImpl {
    db: DatabaseConnection,
}

impl UserCredentialRepositoryImpl {
    pub fn new(db: DatabaseConnection) -> Self {
        Self { db }
    }
}

#[async_trait]
impl UserCredentialRepository for UserCredentialRepositoryImpl {
    async fn find_by_user_oid_and_type(
        &self,
        user_oid: UserOid,
        credential_type: CredentialType,
    ) -> Result<Vec<UserCredential>, UserCredentialRepositoryError> {
        let credential_type_str = match credential_type {
            CredentialType::Password => "password",
            CredentialType::Otp => "otp",
            CredentialType::RecoveryCode => "recovery_code",
        };

        let rows = UserEntity::find()
            .filter(user::Column::Oid.eq(uuid::Uuid::from(user_oid)))
            .inner_join(UserCredentialEntity)
            .filter(user_credential::Column::Type.eq(credential_type_str))
            .select_only()
            .columns([
                user_credential::Column::Id,
                user_credential::Column::Oid,
                user_credential::Column::UserId,
                user_credential::Column::Type,
                user_credential::Column::Data,
                user_credential::Column::CreatedAt,
                user_credential::Column::UpdatedAt,
            ])
            .into_model::<user_credential::Model>()
            .all(&self.db)
            .await
            .map_err(|e| UserCredentialRepositoryError::QueryFailed(Box::new(e)))?;

        // Deserialize only the requested credential type.
        let credentials = rows
            .into_iter()
            .filter_map(|m| {
                let data = match m.r#type.as_str() {
                    "password" => match serde_json::from_value(m.data) {
                        Ok(p) => CredentialData::Password(p),
                        Err(e) => {
                            tracing::error!(
                                error = %e,
                                credential_oid = %m.oid,
                                "failed to deserialize password credential; skipping"
                            );
                            return None;
                        }
                    },
                    "otp" => match serde_json::from_value(m.data) {
                        Ok(o) => CredentialData::Otp(o),
                        Err(e) => {
                            tracing::error!(
                                error = %e,
                                credential_oid = %m.oid,
                                "failed to deserialize otp credential; skipping"
                            );
                            return None;
                        }
                    },
                    "recovery_code" => match serde_json::from_value(m.data) {
                        Ok(r) => CredentialData::RecoveryCode(r),
                        Err(e) => {
                            tracing::error!(
                                error = %e,
                                credential_oid = %m.oid,
                                "failed to deserialize recovery_code credential; skipping"
                            );
                            return None;
                        }
                    },
                    other => {
                        tracing::warn!(
                            credential_oid = %m.oid,
                            r#type = other,
                            "unknown credential type; skipping"
                        );
                        return None;
                    }
                };
                Some(UserCredential {
                    oid: m.oid.into(),
                    r#type: credential_type.clone(),
                    data,
                })
            })
            .collect();

        Ok(credentials)
    }

    async fn update_password_by_oid(
        &self,
        credential_oid: UserCredentialOid,
        password: &Password,
    ) -> Result<(), UserCredentialRepositoryError> {
        let cred = UserCredentialEntity::find()
            .filter(user_credential::Column::Oid.eq(uuid::Uuid::from(credential_oid)))
            .one(&self.db)
            .await
            .map_err(|e| UserCredentialRepositoryError::QueryFailed(Box::new(e)))?
            .ok_or(UserCredentialRepositoryError::CredentialNotFound)?;

        let new_data =
            serde_json::to_value(password).map_err(UserCredentialRepositoryError::Serialization)?;

        let mut active: user_credential::ActiveModel = cred.into();
        active.data = Set(new_data);
        active.updated_at = Set(Some(Utc::now().into()));
        active
            .update(&self.db)
            .await
            .map_err(|e| UserCredentialRepositoryError::UpdatePasswordFailed(Box::new(e)))?;
        Ok(())
    }

    async fn replace_by_user_oid(
        &self,
        user_oid: UserOid,
        replacements: Vec<(CredentialType, Vec<CredentialData>)>,
    ) -> Result<(), UserCredentialRepositoryError> {
        let user = UserEntity::find()
            .filter(user::Column::Oid.eq(uuid::Uuid::from(user_oid)))
            .one(&self.db)
            .await
            .map_err(|e| UserCredentialRepositoryError::QueryFailed(Box::new(e)))?
            .ok_or(UserCredentialRepositoryError::CredentialNotFound)?;
        let replacements = replacements
            .into_iter()
            .map(|(credential_type, data)| {
                let serialized = data
                    .into_iter()
                    .map(|data| match data {
                        CredentialData::Password(value) => serde_json::to_value(value),
                        CredentialData::Otp(value) => serde_json::to_value(value),
                        CredentialData::RecoveryCode(value) => serde_json::to_value(value),
                    })
                    .collect::<Result<Vec<_>, _>>()?;
                Ok((credential_type.as_ref().to_owned(), serialized))
            })
            .collect::<Result<Vec<_>, serde_json::Error>>()
            .map_err(UserCredentialRepositoryError::Serialization)?;
        let txn = self
            .db
            .begin()
            .await
            .map_err(|e| UserCredentialRepositoryError::ReplaceFailed(Box::new(e)))?;
        for (credential_type, serialized) in replacements {
            UserCredentialEntity::delete_many()
                .filter(user_credential::Column::UserId.eq(user.id))
                .filter(user_credential::Column::Type.eq(&credential_type))
                .exec(&txn)
                .await
                .map_err(|e| UserCredentialRepositoryError::ReplaceFailed(Box::new(e)))?;
            for value in serialized {
                user_credential::ActiveModel {
                    oid: Set(uuid::Uuid::new_v4()),
                    user_id: Set(user.id),
                    r#type: Set(credential_type.clone()),
                    data: Set(value),
                    expires_at: Set(None),
                    created_at: Set(Utc::now().into()),
                    ..Default::default()
                }
                .insert(&txn)
                .await
                .map_err(|e| UserCredentialRepositoryError::ReplaceFailed(Box::new(e)))?;
            }
        }
        txn.commit()
            .await
            .map_err(|e| UserCredentialRepositoryError::ReplaceFailed(Box::new(e)))?;
        Ok(())
    }

    async fn delete_by_oid(
        &self,
        credential_oid: UserCredentialOid,
    ) -> Result<bool, UserCredentialRepositoryError> {
        let result = UserCredentialEntity::delete_many()
            .filter(user_credential::Column::Oid.eq(uuid::Uuid::from(credential_oid)))
            .exec(&self.db)
            .await
            .map_err(|e| UserCredentialRepositoryError::DeleteFailed(Box::new(e)))?;
        Ok(result.rows_affected == 1)
    }
}
