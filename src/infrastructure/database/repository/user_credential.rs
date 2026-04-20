use crate::domain::user::{
    CredentialData, CredentialType, Password, UserCredential, UserCredentialOid, UserOid,
    repository::{UserCredentialRepository, UserCredentialRepositoryError},
};
use crate::infrastructure::database::entity::{
    user, user::Entity as UserEntity, user_credential,
    user_credential::Entity as UserCredentialEntity,
};
use async_trait::async_trait;
use chrono::Utc;
use sea_orm::{
    ActiveModelTrait, ColumnTrait, DatabaseConnection, EntityTrait, QueryFilter, QuerySelect, Set,
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
            .map_err(UserCredentialRepositoryError::QueryFailed)?;

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
            .map_err(UserCredentialRepositoryError::QueryFailed)?
            .ok_or(UserCredentialRepositoryError::CredentialNotFound)?;

        let new_data =
            serde_json::to_value(password).map_err(UserCredentialRepositoryError::Serialization)?;

        let mut active: user_credential::ActiveModel = cred.into();
        active.data = Set(new_data);
        active.updated_at = Set(Some(Utc::now().into()));
        active
            .update(&self.db)
            .await
            .map_err(UserCredentialRepositoryError::UpdatePasswordFailed)?;
        Ok(())
    }
}
