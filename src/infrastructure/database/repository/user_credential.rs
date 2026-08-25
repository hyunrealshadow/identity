use crate::database::entity::{
    user, user::Entity as UserEntity, user_credential,
    user_credential::Entity as UserCredentialEntity,
};
use async_trait::async_trait;
use chrono::Utc;
use identity_domain::user::{
    CredentialData, CredentialType, OtpCredentialData, Password, RecoveryCodeCredentialData,
    UserCredential, UserCredentialOid, UserOid,
    repository::{UserCredentialRepository, UserCredentialRepositoryError},
};

use super::shared::lock_user_credentials;
use sea_orm::{
    ActiveModelTrait, ColumnTrait, Condition, DatabaseConnection, EntityTrait, QueryFilter,
    QuerySelect, Set, TransactionTrait, sea_query::Expr,
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
        let rows = UserEntity::find()
            .filter(user::Column::Oid.eq(uuid::Uuid::from(user_oid)))
            .inner_join(UserCredentialEntity)
            .filter(user_credential::Column::Type.eq(credential_type.as_ref()))
            .filter(
                Condition::any()
                    .add(user_credential::Column::ExpiresAt.is_null())
                    .add(user_credential::Column::ExpiresAt.gt(Utc::now())),
            )
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

        let credentials = rows
            .into_iter()
            .map(|m| {
                let data = match &credential_type {
                    CredentialType::Password => {
                        serde_json::from_value(m.data).map(CredentialData::Password)
                    }
                    CredentialType::Otp => serde_json::from_value(m.data).map(CredentialData::Otp),
                    CredentialType::RecoveryCode => {
                        serde_json::from_value(m.data).map(CredentialData::RecoveryCode)
                    }
                };
                Ok(UserCredential {
                    oid: m.oid.into(),
                    r#type: credential_type,
                    data: data.map_err(UserCredentialRepositoryError::Deserialization)?,
                })
            })
            .collect::<Result<Vec<_>, UserCredentialRepositoryError>>()?;

        Ok(credentials)
    }

    async fn update_password_by_oid(
        &self,
        credential_oid: UserCredentialOid,
        password: &Password,
    ) -> Result<(), UserCredentialRepositoryError> {
        let new_data =
            serde_json::to_value(password).map_err(UserCredentialRepositoryError::Serialization)?;

        let result = UserCredentialEntity::update_many()
            .col_expr(user_credential::Column::Data, Expr::value(new_data))
            .col_expr(
                user_credential::Column::UpdatedAt,
                Expr::value(Some(Utc::now().fixed_offset())),
            )
            .filter(user_credential::Column::Oid.eq(uuid::Uuid::from(credential_oid)))
            .filter(user_credential::Column::Type.eq(CredentialType::Password.as_ref()))
            .filter(
                Condition::any()
                    .add(user_credential::Column::ExpiresAt.is_null())
                    .add(user_credential::Column::ExpiresAt.gt(Utc::now())),
            )
            .exec(&self.db)
            .await
            .map_err(|e| UserCredentialRepositoryError::UpdatePasswordFailed(Box::new(e)))?;
        if result.rows_affected != 1 {
            return Err(UserCredentialRepositoryError::CredentialNotFound);
        }
        Ok(())
    }

    async fn consume_totp_counter(
        &self,
        credential_oid: UserCredentialOid,
        counter: u64,
    ) -> Result<bool, UserCredentialRepositoryError> {
        let counter = i64::try_from(counter)
            .map_err(|error| UserCredentialRepositoryError::ConsumeTotpFailed(Box::new(error)))?;
        let result = UserCredentialEntity::update_many()
            .col_expr(
                user_credential::Column::Data,
                Expr::cust_with_values(
                    r#"jsonb_set("user_credential"."data", '{last_used_counter}', to_jsonb($1::bigint), true)"#,
                    [counter],
                ),
            )
            .col_expr(
                user_credential::Column::UpdatedAt,
                Expr::value(Some(Utc::now().fixed_offset())),
            )
            .filter(user_credential::Column::Oid.eq(uuid::Uuid::from(credential_oid)))
            .filter(user_credential::Column::Type.eq(CredentialType::Otp.as_ref()))
            .filter(
                Condition::any()
                    .add(user_credential::Column::ExpiresAt.is_null())
                    .add(user_credential::Column::ExpiresAt.gt(Utc::now())),
            )
            .filter(Expr::cust_with_values(
                r#"COALESCE(("user_credential"."data"->>'last_used_counter')::bigint, -1) < $1"#,
                [counter],
            ))
            .exec(&self.db)
            .await
            .map_err(|error| {
                UserCredentialRepositoryError::ConsumeTotpFailed(Box::new(error))
            })?;
        Ok(result.rows_affected == 1)
    }

    async fn replace_by_user_oid(
        &self,
        user_oid: UserOid,
        replacements: Vec<(CredentialType, Vec<CredentialData>)>,
    ) -> Result<(), UserCredentialRepositoryError> {
        let replacements = replacements
            .into_iter()
            .map(|(credential_type, data)| {
                if data
                    .iter()
                    .any(|value| value.credential_type() != credential_type)
                {
                    return Err(UserCredentialRepositoryError::CredentialTypeMismatch(
                        credential_type,
                    ));
                }
                let serialized = data
                    .into_iter()
                    .map(|data| match data {
                        CredentialData::Password(value) => serde_json::to_value(value),
                        CredentialData::Otp(value) => serde_json::to_value(value),
                        CredentialData::RecoveryCode(value) => serde_json::to_value(value),
                    })
                    .collect::<Result<Vec<_>, _>>()
                    .map_err(UserCredentialRepositoryError::Serialization)?;
                Ok((credential_type.as_ref().to_owned(), serialized))
            })
            .collect::<Result<Vec<_>, UserCredentialRepositoryError>>()?;
        let txn = self
            .db
            .begin()
            .await
            .map_err(|e| UserCredentialRepositoryError::ReplaceFailed(Box::new(e)))?;
        lock_user_credentials(&txn, user_oid)
            .await
            .map_err(|e| UserCredentialRepositoryError::ReplaceFailed(Box::new(e)))?;
        let user = UserEntity::find()
            .filter(user::Column::Oid.eq(uuid::Uuid::from(user_oid)))
            .one(&txn)
            .await
            .map_err(|e| UserCredentialRepositoryError::QueryFailed(Box::new(e)))?
            .ok_or(UserCredentialRepositoryError::CredentialNotFound)?;
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

    async fn enable_totp_if_disabled(
        &self,
        user_oid: UserOid,
        otp: OtpCredentialData,
        recovery_codes: Vec<RecoveryCodeCredentialData>,
    ) -> Result<bool, UserCredentialRepositoryError> {
        let otp =
            serde_json::to_value(otp).map_err(UserCredentialRepositoryError::Serialization)?;
        let recovery_codes = recovery_codes
            .into_iter()
            .map(serde_json::to_value)
            .collect::<Result<Vec<_>, _>>()
            .map_err(UserCredentialRepositoryError::Serialization)?;
        let txn = self
            .db
            .begin()
            .await
            .map_err(|e| UserCredentialRepositoryError::ReplaceFailed(Box::new(e)))?;
        lock_user_credentials(&txn, user_oid)
            .await
            .map_err(|e| UserCredentialRepositoryError::ReplaceFailed(Box::new(e)))?;
        let user = UserEntity::find()
            .filter(user::Column::Oid.eq(uuid::Uuid::from(user_oid)))
            .one(&txn)
            .await
            .map_err(|e| UserCredentialRepositoryError::QueryFailed(Box::new(e)))?
            .ok_or(UserCredentialRepositoryError::CredentialNotFound)?;
        let totp_exists = UserCredentialEntity::find()
            .filter(user_credential::Column::UserId.eq(user.id))
            .filter(user_credential::Column::Type.eq(CredentialType::Otp.as_ref()))
            .filter(
                Condition::any()
                    .add(user_credential::Column::ExpiresAt.is_null())
                    .add(user_credential::Column::ExpiresAt.gt(Utc::now())),
            )
            .one(&txn)
            .await
            .map_err(|e| UserCredentialRepositoryError::ReplaceFailed(Box::new(e)))?
            .is_some();
        if totp_exists {
            txn.commit()
                .await
                .map_err(|e| UserCredentialRepositoryError::ReplaceFailed(Box::new(e)))?;
            return Ok(false);
        }
        UserCredentialEntity::delete_many()
            .filter(user_credential::Column::UserId.eq(user.id))
            .filter(
                Condition::any()
                    .add(user_credential::Column::Type.eq(CredentialType::Otp.as_ref()))
                    .add(user_credential::Column::Type.eq(CredentialType::RecoveryCode.as_ref())),
            )
            .exec(&txn)
            .await
            .map_err(|e| UserCredentialRepositoryError::ReplaceFailed(Box::new(e)))?;
        user_credential::ActiveModel {
            oid: Set(uuid::Uuid::new_v4()),
            user_id: Set(user.id),
            r#type: Set(CredentialType::Otp.to_string()),
            data: Set(otp),
            expires_at: Set(None),
            created_at: Set(Utc::now().into()),
            ..Default::default()
        }
        .insert(&txn)
        .await
        .map_err(|e| UserCredentialRepositoryError::ReplaceFailed(Box::new(e)))?;
        for value in recovery_codes {
            user_credential::ActiveModel {
                oid: Set(uuid::Uuid::new_v4()),
                user_id: Set(user.id),
                r#type: Set(CredentialType::RecoveryCode.to_string()),
                data: Set(value),
                expires_at: Set(None),
                created_at: Set(Utc::now().into()),
                ..Default::default()
            }
            .insert(&txn)
            .await
            .map_err(|e| UserCredentialRepositoryError::ReplaceFailed(Box::new(e)))?;
        }
        txn.commit()
            .await
            .map_err(|e| UserCredentialRepositoryError::ReplaceFailed(Box::new(e)))?;
        Ok(true)
    }

    async fn replace_recovery_codes_if_totp_enabled(
        &self,
        user_oid: UserOid,
        recovery_codes: Vec<RecoveryCodeCredentialData>,
    ) -> Result<bool, UserCredentialRepositoryError> {
        let serialized = recovery_codes
            .into_iter()
            .map(serde_json::to_value)
            .collect::<Result<Vec<_>, _>>()
            .map_err(UserCredentialRepositoryError::Serialization)?;
        let txn = self
            .db
            .begin()
            .await
            .map_err(|e| UserCredentialRepositoryError::ReplaceFailed(Box::new(e)))?;
        lock_user_credentials(&txn, user_oid)
            .await
            .map_err(|e| UserCredentialRepositoryError::ReplaceFailed(Box::new(e)))?;
        let user = UserEntity::find()
            .filter(user::Column::Oid.eq(uuid::Uuid::from(user_oid)))
            .one(&txn)
            .await
            .map_err(|e| UserCredentialRepositoryError::QueryFailed(Box::new(e)))?
            .ok_or(UserCredentialRepositoryError::CredentialNotFound)?;
        let totp_exists = UserCredentialEntity::find()
            .filter(user_credential::Column::UserId.eq(user.id))
            .filter(user_credential::Column::Type.eq(CredentialType::Otp.as_ref()))
            .filter(
                Condition::any()
                    .add(user_credential::Column::ExpiresAt.is_null())
                    .add(user_credential::Column::ExpiresAt.gt(Utc::now())),
            )
            .one(&txn)
            .await
            .map_err(|e| UserCredentialRepositoryError::ReplaceFailed(Box::new(e)))?
            .is_some();
        if !totp_exists {
            txn.commit()
                .await
                .map_err(|e| UserCredentialRepositoryError::ReplaceFailed(Box::new(e)))?;
            return Ok(false);
        }
        UserCredentialEntity::delete_many()
            .filter(user_credential::Column::UserId.eq(user.id))
            .filter(user_credential::Column::Type.eq(CredentialType::RecoveryCode.as_ref()))
            .exec(&txn)
            .await
            .map_err(|e| UserCredentialRepositoryError::ReplaceFailed(Box::new(e)))?;
        for value in serialized {
            user_credential::ActiveModel {
                oid: Set(uuid::Uuid::new_v4()),
                user_id: Set(user.id),
                r#type: Set(CredentialType::RecoveryCode.to_string()),
                data: Set(value),
                expires_at: Set(None),
                created_at: Set(Utc::now().into()),
                ..Default::default()
            }
            .insert(&txn)
            .await
            .map_err(|e| UserCredentialRepositoryError::ReplaceFailed(Box::new(e)))?;
        }
        txn.commit()
            .await
            .map_err(|e| UserCredentialRepositoryError::ReplaceFailed(Box::new(e)))?;
        Ok(true)
    }

    async fn consume_recovery_code_by_oid(
        &self,
        credential_oid: UserCredentialOid,
    ) -> Result<bool, UserCredentialRepositoryError> {
        let result = UserCredentialEntity::delete_many()
            .filter(user_credential::Column::Oid.eq(uuid::Uuid::from(credential_oid)))
            .filter(user_credential::Column::Type.eq(CredentialType::RecoveryCode.as_ref()))
            .filter(
                Condition::any()
                    .add(user_credential::Column::ExpiresAt.is_null())
                    .add(user_credential::Column::ExpiresAt.gt(Utc::now())),
            )
            .exec(&self.db)
            .await
            .map_err(|e| UserCredentialRepositoryError::DeleteFailed(Box::new(e)))?;
        Ok(result.rows_affected == 1)
    }
}

#[cfg(test)]
mod tests {
    use crate::database::entity::user_credential;
    use chrono::Utc;
    use identity_domain::user::{
        CredentialData, CredentialType, OtpCredentialData, UserCredentialOid, UserOid,
        repository::{UserCredentialRepository as _, UserCredentialRepositoryError},
    };
    use sea_orm::{DatabaseBackend, MockDatabase, MockExecResult};
    use uuid::Uuid;

    use super::UserCredentialRepositoryImpl;

    #[tokio::test]
    async fn consume_totp_counter_uses_an_atomic_jsonb_condition() {
        let db = MockDatabase::new(DatabaseBackend::Postgres)
            .append_exec_results([MockExecResult {
                last_insert_id: 0,
                rows_affected: 1,
            }])
            .into_connection();
        let repo = UserCredentialRepositoryImpl::new(db);

        let consumed = repo
            .consume_totp_counter(UserCredentialOid(Uuid::new_v4()), 42)
            .await
            .unwrap();

        assert!(consumed);
        let statements = format!("{:?}", repo.db.into_transaction_log());
        assert!(statements.contains("jsonb_set"));
        assert!(statements.contains("last_used_counter"));
        assert!(statements.contains("<"));
        assert!(statements.contains("expires_at"));
    }

    #[tokio::test]
    async fn consume_totp_counter_reports_a_replay_when_no_row_is_updated() {
        let db = MockDatabase::new(DatabaseBackend::Postgres)
            .append_exec_results([MockExecResult {
                last_insert_id: 0,
                rows_affected: 0,
            }])
            .into_connection();
        let repo = UserCredentialRepositoryImpl::new(db);

        let consumed = repo
            .consume_totp_counter(UserCredentialOid(Uuid::new_v4()), 42)
            .await
            .unwrap();

        assert!(!consumed);
    }

    #[tokio::test]
    async fn replacements_reject_data_that_does_not_match_the_declared_type() {
        let db = MockDatabase::new(DatabaseBackend::Postgres).into_connection();
        let repo = UserCredentialRepositoryImpl::new(db);
        let otp = OtpCredentialData {
            secret: "secret".to_owned(),
            algorithm: identity_domain::user::OtpAlgorithm::Sha1,
            digits: 6,
            period: 30,
            last_used_counter: None,
        };

        let error = repo
            .replace_by_user_oid(
                UserOid(Uuid::new_v4()),
                vec![(CredentialType::Password, vec![CredentialData::Otp(otp)])],
            )
            .await
            .unwrap_err();

        assert!(matches!(
            error,
            UserCredentialRepositoryError::CredentialTypeMismatch(CredentialType::Password)
        ));
    }

    #[tokio::test]
    async fn corrupt_credential_payload_is_not_treated_as_missing() {
        let db = MockDatabase::new(DatabaseBackend::Postgres)
            .append_query_results([[user_credential::Model {
                id: 1,
                oid: Uuid::new_v4(),
                user_id: 1,
                r#type: "password".to_owned(),
                data: serde_json::json!({"unexpected": true}),
                expires_at: None,
                created_at: Utc::now().into(),
                updated_at: None,
            }]])
            .into_connection();
        let repo = UserCredentialRepositoryImpl::new(db);

        let error = repo
            .find_by_user_oid_and_type(UserOid(Uuid::new_v4()), CredentialType::Password)
            .await
            .unwrap_err();

        assert!(matches!(
            error,
            UserCredentialRepositoryError::Deserialization(_)
        ));
    }
}
