use async_trait::async_trait;
use chrono::Utc;
use sea_orm::{
    ActiveModelTrait, ColumnTrait, DatabaseConnection, EntityTrait, QueryFilter, QuerySelect, Set,
};
use uuid::Uuid;

use crate::domain::user::{
    model::{
        CredentialData, CredentialType, OtpCredentialData, Password, RecoveryCodeCredentialData,
        UserCredential,
    },
    repository::{UserCredentialRepository, UserCredentialRepositoryError},
};
use crate::infrastructure::database::entity::{
    user, user::Entity as UserEntity, user_credential,
    user_credential::Entity as UserCredentialEntity,
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
        user_oid: Uuid,
        credential_type: CredentialType,
    ) -> Result<Vec<UserCredential>, UserCredentialRepositoryError> {
        let credential_type_str = match credential_type {
            CredentialType::Password => "password",
            CredentialType::Otp => "otp",
            CredentialType::RecoveryCode => "recovery_code",
        };

        let rows = UserEntity::find()
            .filter(user::Column::Oid.eq(user_oid))
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
                    "password" => {
                        let p: Password = serde_json::from_value(m.data).ok()?;
                        CredentialData::Password(p)
                    }
                    "otp" => {
                        let o: OtpCredentialData = serde_json::from_value(m.data).ok()?;
                        CredentialData::Otp(o)
                    }
                    "recovery_code" => {
                        let r: RecoveryCodeCredentialData = serde_json::from_value(m.data).ok()?;
                        CredentialData::RecoveryCode(r)
                    }
                    _ => return None,
                };
                Some(UserCredential {
                    oid: m.oid,
                    r#type: credential_type.clone(),
                    data,
                })
            })
            .collect();

        Ok(credentials)
    }

    async fn update_password_by_oid(
        &self,
        credential_oid: Uuid,
        password: &Password,
    ) -> Result<(), UserCredentialRepositoryError> {
        let cred = UserCredentialEntity::find()
            .filter(user_credential::Column::Oid.eq(credential_oid))
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
