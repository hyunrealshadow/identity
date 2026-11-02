use async_trait::async_trait;
use chrono::Utc;
use identity_application::error::{
    AppError,
    codes::{auth::AuthErrorCode, authorization::AuthorizationErrorCode},
};
use identity_application::user::{
    CredentialData, CredentialType, OtpCredentialData, Password, RecoveryCodeCredentialData,
    UserCredential, UserCredentialOid, UserOid,
    credential::{MAX_PASSKEYS_PER_USER, StoredPasskey},
    repository::{
        PasskeyCredentialRepository, UserCredentialRepository, UserCredentialRepositoryError,
    },
};
use identity_domain::authorization::owner::OwnerProtectionError;
use sea_orm::{
    ActiveModelTrait, ColumnTrait, Condition, DatabaseConnection, DbErr, EntityTrait, QueryFilter,
    QuerySelect, Set, TransactionTrait,
    sea_query::{Expr, ExprTrait, Func},
};
use serde_json::{from_value, to_value};
use uuid::Uuid;

use super::authorization_lifecycle::{
    ensure_recoverable_authorization_administrator, lock_owner_lifecycle,
    withdraw_user_authority_in_txn,
};
use super::shared::lock_user_credentials;
use crate::database::{
    audit,
    entity::{
        user, user::Entity as UserEntity, user_credential,
        user_credential::Entity as UserCredentialEntity,
    },
    query::{json_text, jsonb_set},
};

mod mfa;
mod password_change;

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
    #[tracing::instrument(skip_all, name = "db.query", fields(db.system = "postgresql", db.operation = "find_by_user_oid_and_type"))]
    async fn find_by_user_oid_and_type(
        &self,
        user_oid: UserOid,
        credential_type: CredentialType,
    ) -> Result<Vec<UserCredential>, UserCredentialRepositoryError> {
        let rows = UserEntity::find()
            .filter(user::Column::Oid.eq(Uuid::from(user_oid)))
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
                user_credential::Column::ExpiresAt,
            ])
            .into_model::<user_credential::Model>()
            .all(&self.db)
            .await
            .map_err(|e| UserCredentialRepositoryError::QueryFailed(Box::new(e)))?;

        let credentials = rows
            .into_iter()
            .map(|m| {
                let data = match &credential_type {
                    CredentialType::Passkey => from_value(m.data).map(CredentialData::Passkey),
                    CredentialType::Password => from_value(m.data).map(CredentialData::Password),
                    CredentialType::Otp => from_value(m.data).map(CredentialData::Otp),
                    CredentialType::RecoveryCode => {
                        from_value(m.data).map(CredentialData::RecoveryCode)
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

    #[tracing::instrument(skip_all, name = "db.query", fields(db.system = "postgresql", db.operation = "update_password_by_oid"))]
    async fn update_password_by_oid(
        &self,
        credential_oid: UserCredentialOid,
        expected: &Password,
        password: &Password,
    ) -> Result<(), UserCredentialRepositoryError> {
        let new_data = to_value(password).map_err(UserCredentialRepositoryError::Serialization)?;

        let result = UserCredentialEntity::update_many()
            .col_expr(user_credential::Column::Data, Expr::value(new_data))
            .col_expr(
                user_credential::Column::UpdatedAt,
                Expr::value(Some(Utc::now().fixed_offset())),
            )
            .filter(user_credential::Column::Oid.eq(Uuid::from(credential_oid)))
            .filter(
                user_credential::Column::Data
                    .eq(to_value(expected).map_err(UserCredentialRepositoryError::Serialization)?),
            )
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

    async fn change_password_and_revoke(
        &self,
        user: UserOid,
        credential: UserCredentialOid,
        expected: &Password,
        password: &Password,
        keep: Option<identity_domain::auth::SessionOid>,
    ) -> Result<u32, UserCredentialRepositoryError> {
        self.change_password_transaction(user, credential, expected, password, keep)
            .await
    }

    #[tracing::instrument(skip_all, name = "db.query", fields(db.system = "postgresql", db.operation = "consume_totp_counter"))]
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
                jsonb_set(
                    (user_credential::Entity, user_credential::Column::Data),
                    "last_used_counter",
                    Func::cust("to_jsonb").arg(Expr::value(counter).cast_as("bigint")),
                ),
            )
            .col_expr(
                user_credential::Column::UpdatedAt,
                Expr::value(Some(Utc::now().fixed_offset())),
            )
            .filter(user_credential::Column::Oid.eq(Uuid::from(credential_oid)))
            .filter(user_credential::Column::Type.eq(CredentialType::Otp.as_ref()))
            .filter(
                Condition::any()
                    .add(user_credential::Column::ExpiresAt.is_null())
                    .add(user_credential::Column::ExpiresAt.gt(Utc::now())),
            )
            .filter(
                Expr::expr(Func::coalesce([
                    json_text(
                        (user_credential::Entity, user_credential::Column::Data),
                        "last_used_counter",
                    )
                    .cast_as("bigint"),
                    Expr::value(-1_i64),
                ]))
                .lt(counter),
            )
            .exec(&self.db)
            .await
            .map_err(|error| UserCredentialRepositoryError::ConsumeTotpFailed(Box::new(error)))?;
        Ok(result.rows_affected == 1)
    }

    #[tracing::instrument(skip_all, name = "db.query", fields(db.system = "postgresql", db.operation = "replace_by_user_oid"))]
    async fn replace_by_user_oid(
        &self,
        user_oid: UserOid,
        replacements: Vec<(CredentialType, Vec<CredentialData>)>,
    ) -> Result<(), UserCredentialRepositoryError> {
        // Only password/passkey replacement can remove a login path. Recovery
        // code and OTP maintenance must not contend on the global owner lock.
        let touches_login_credential = replacements.iter().any(|(credential_type, _)| {
            matches!(
                credential_type,
                CredentialType::Password | CredentialType::Passkey
            )
        });
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
                        CredentialData::Password(value) => to_value(value),
                        CredentialData::Otp(value) => to_value(value),
                        CredentialData::RecoveryCode(value) => to_value(value),
                        CredentialData::Passkey(value) => to_value(value),
                    })
                    .collect::<Result<Vec<_>, _>>()
                    .map_err(UserCredentialRepositoryError::Serialization)?;
                Ok((credential_type.as_ref().to_owned(), serialized))
            })
            .collect::<Result<Vec<_>, UserCredentialRepositoryError>>()?;
        let txn = audit::begin(&self.db, "security.replace_by_user_oid")
            .await
            .map_err(|e| UserCredentialRepositoryError::ReplaceFailed(Box::new(e)))?;
        // Owner-removing writes share one cross-entry serialization point.
        if touches_login_credential {
            lock_owner_lifecycle(&txn)
                .await
                .map_err(|e| UserCredentialRepositoryError::ReplaceFailed(Box::new(e)))?;
        }
        lock_user_credentials(&txn, user_oid)
            .await
            .map_err(|e| UserCredentialRepositoryError::ReplaceFailed(Box::new(e)))?;
        let user = UserEntity::find()
            .filter(user::Column::Oid.eq(Uuid::from(user_oid)))
            .one(&txn)
            .await
            .map_err(|e| UserCredentialRepositoryError::QueryFailed(Box::new(e)))?
            .ok_or(UserCredentialRepositoryError::CredentialNotFound)?;
        let mut authority_changed = false;
        for (credential_type, serialized) in replacements {
            let affects_authority =
                matches!(credential_type.as_str(), "password" | "passkey" | "otp");
            let deleted = UserCredentialEntity::delete_many()
                .filter(user_credential::Column::UserId.eq(user.id))
                .filter(user_credential::Column::Type.eq(&credential_type))
                .exec(&txn)
                .await
                .map_err(|e| UserCredentialRepositoryError::ReplaceFailed(Box::new(e)))?
                .rows_affected
                > 0;
            if affects_authority && (deleted || !serialized.is_empty()) {
                authority_changed = true;
            }
            for value in serialized {
                user_credential::ActiveModel {
                    oid: Set(Uuid::new_v4()),
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
        // Replacement may delete the final password/passkey. Check the
        // capability-based recovery invariant AFTER the credential mutation and
        // before commit; a full-capability user must remain recoverable.
        if touches_login_credential {
            match ensure_recoverable_authorization_administrator(&txn).await {
                Ok(()) => {}
                Err(DbErr::Custom(message))
                    if message == "no recoverable authorization administrator remains" =>
                {
                    return Err(UserCredentialRepositoryError::ReplaceFailed(Box::new(
                        OwnerProtectionError::LastOwnerProtected,
                    )));
                }
                Err(error) => {
                    return Err(UserCredentialRepositoryError::ReplaceFailed(Box::new(
                        error,
                    )));
                }
            }
        }
        if authority_changed {
            // Removing or replacing a fingerprinted credential (password,
            // passkey or OTP) is a permanent authorization boundary. Rotate the
            // CAS token and tombstone every subject artifact, including already
            // consumed single-use parents, so later re-creation cannot revive
            // credentials minted under an earlier credential set. A no-op
            // (nothing deleted and nothing inserted) leaves authority intact.
            withdraw_user_authority_in_txn(&txn, user.id)
                .await
                .map_err(|e| UserCredentialRepositoryError::ReplaceFailed(Box::new(e)))?;
        }
        audit::record(
            &txn,
            "security.replace_by_user_oid",
            "user",
            Uuid::from(user_oid),
        )
        .await
        .map_err(|e| UserCredentialRepositoryError::ReplaceFailed(Box::new(e)))?;
        txn.commit()
            .await
            .map_err(|e| UserCredentialRepositoryError::ReplaceFailed(Box::new(e)))?;
        Ok(())
    }

    #[tracing::instrument(skip_all, name = "db.query", fields(db.system = "postgresql", db.operation = "enable_totp_if_disabled"))]
    async fn enable_totp_if_disabled(
        &self,
        user_oid: UserOid,
        otp: OtpCredentialData,
        recovery_codes: Vec<RecoveryCodeCredentialData>,
    ) -> Result<bool, UserCredentialRepositoryError> {
        let otp = to_value(otp).map_err(UserCredentialRepositoryError::Serialization)?;
        let txn = audit::begin(&self.db, "security.enable_totp_if_disabled")
            .await
            .map_err(|e| UserCredentialRepositoryError::ReplaceFailed(Box::new(e)))?;
        lock_user_credentials(&txn, user_oid)
            .await
            .map_err(|e| UserCredentialRepositoryError::ReplaceFailed(Box::new(e)))?;
        let user = UserEntity::find()
            .filter(user::Column::Oid.eq(Uuid::from(user_oid)))
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
        mfa::install_recovery_codes(&txn, user.id, &recovery_codes).await?;
        UserCredentialEntity::delete_many()
            .filter(user_credential::Column::UserId.eq(user.id))
            .filter(user_credential::Column::Type.eq(CredentialType::Otp.as_ref()))
            .exec(&txn)
            .await
            .map_err(|error| UserCredentialRepositoryError::ReplaceFailed(Box::new(error)))?;
        user_credential::ActiveModel {
            oid: Set(Uuid::new_v4()),
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
        // Adding a fingerprinted OTP credential is an authority boundary even
        // though this path is reached only when TOTP was disabled. Any artifact
        // issued under the earlier credential set must stay withdrawn.
        withdraw_user_authority_in_txn(&txn, user.id)
            .await
            .map_err(|e| UserCredentialRepositoryError::ReplaceFailed(Box::new(e)))?;
        audit::record(
            &txn,
            "security.enable_totp_if_disabled",
            "user",
            Uuid::from(user_oid),
        )
        .await
        .map_err(|e| UserCredentialRepositoryError::ReplaceFailed(Box::new(e)))?;
        txn.commit()
            .await
            .map_err(|e| UserCredentialRepositoryError::ReplaceFailed(Box::new(e)))?;
        Ok(true)
    }

    async fn disable_totp(&self, user_oid: UserOid) -> Result<bool, UserCredentialRepositoryError> {
        mfa::disable_totp(&self.db, user_oid).await
    }

    #[tracing::instrument(skip_all, name = "db.query", fields(db.system = "postgresql", db.operation = "replace_recovery_codes_if_mfa_enabled"))]
    async fn replace_recovery_codes_if_mfa_enabled(
        &self,
        user_oid: UserOid,
        recovery_codes: Vec<RecoveryCodeCredentialData>,
    ) -> Result<bool, UserCredentialRepositoryError> {
        let serialized = recovery_codes
            .into_iter()
            .map(to_value)
            .collect::<Result<Vec<_>, _>>()
            .map_err(UserCredentialRepositoryError::Serialization)?;
        let txn = audit::begin(&self.db, "security.replace_recovery_codes_if_mfa_enabled")
            .await
            .map_err(|e| UserCredentialRepositoryError::ReplaceFailed(Box::new(e)))?;
        lock_user_credentials(&txn, user_oid)
            .await
            .map_err(|e| UserCredentialRepositoryError::ReplaceFailed(Box::new(e)))?;
        let user = UserEntity::find()
            .filter(user::Column::Oid.eq(Uuid::from(user_oid)))
            .one(&txn)
            .await
            .map_err(|e| UserCredentialRepositoryError::QueryFailed(Box::new(e)))?
            .ok_or(UserCredentialRepositoryError::CredentialNotFound)?;
        if !mfa::has_active_mfa(&txn, user.id).await? {
            txn.commit()
                .await
                .map_err(|error| UserCredentialRepositoryError::ReplaceFailed(Box::new(error)))?;
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
                oid: Set(Uuid::new_v4()),
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
        audit::record(
            &txn,
            "security.replace_recovery_codes_if_mfa_enabled",
            "user",
            Uuid::from(user_oid),
        )
        .await
        .map_err(|e| UserCredentialRepositoryError::ReplaceFailed(Box::new(e)))?;
        txn.commit()
            .await
            .map_err(|e| UserCredentialRepositoryError::ReplaceFailed(Box::new(e)))?;
        Ok(true)
    }

    #[tracing::instrument(skip_all, name = "db.query", fields(db.system = "postgresql", db.operation = "consume_recovery_code_by_oid"))]
    async fn consume_recovery_code_by_oid(
        &self,
        credential_oid: UserCredentialOid,
    ) -> Result<bool, UserCredentialRepositoryError> {
        mfa::consume_recovery_code(&self.db, credential_oid).await
    }
}

#[cfg(test)]
mod tests {
    use chrono::Utc;
    use identity_application::user::{
        CredentialData, CredentialType, OtpAlgorithm, OtpCredentialData, UserCredentialOid,
        UserOid,
        repository::{UserCredentialRepository as _, UserCredentialRepositoryError},
    };
    use sea_orm::{DatabaseBackend, MockDatabase, MockExecResult};
    use serde_json::json;
    use uuid::Uuid;

    use super::UserCredentialRepositoryImpl;
    use crate::database::entity::user_credential;

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
            algorithm: OtpAlgorithm::Sha1,
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
                data: json!({"unexpected": true}),
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

#[async_trait]
impl PasskeyCredentialRepository for UserCredentialRepositoryImpl {
    async fn list(&self, user: UserOid) -> Result<Vec<StoredPasskey>, AppError> {
        self.find_by_user_oid_and_type(user, CredentialType::Passkey)
            .await?
            .into_iter()
            .map(|credential| match credential.data {
                CredentialData::Passkey(data) => Ok(StoredPasskey {
                    id: credential.oid.0,
                    data,
                }),
                _ => Err(AppError::internal(
                    UserCredentialRepositoryError::CredentialTypeMismatch(CredentialType::Passkey),
                )),
            })
            .collect()
    }

    async fn insert(
        &self,
        user_oid: UserOid,
        key: StoredPasskey,
        recovery_codes: Vec<RecoveryCodeCredentialData>,
    ) -> Result<(), AppError> {
        let txn = audit::begin(&self.db, "security.insert")
            .await
            .map_err(AppError::internal)?;
        lock_user_credentials(&txn, user_oid)
            .await
            .map_err(AppError::internal)?;
        let user_id = UserEntity::find()
            .select_only()
            .column(user::Column::Id)
            .filter(user::Column::Oid.eq(Uuid::from(user_oid)))
            .into_tuple::<i64>()
            .one(&txn)
            .await
            .map_err(AppError::internal)?
            .ok_or(UserCredentialRepositoryError::CredentialNotFound)?;
        // The credential lock covers both the limit check and insertion, so
        // registrations completed in parallel cannot exceed the account limit.
        let existing = UserCredentialEntity::find()
            .select_only()
            .column(user_credential::Column::Id)
            .filter(user_credential::Column::UserId.eq(user_id))
            .filter(user_credential::Column::Type.eq(CredentialType::Passkey.as_ref()))
            .filter(
                Condition::any()
                    .add(user_credential::Column::ExpiresAt.is_null())
                    .add(user_credential::Column::ExpiresAt.gt(Utc::now())),
            )
            .limit(MAX_PASSKEYS_PER_USER as u64)
            .into_tuple::<i64>()
            .all(&txn)
            .await
            .map_err(AppError::internal)?;
        if existing.len() >= MAX_PASSKEYS_PER_USER {
            return Err(AppError::from_code(AuthErrorCode::PasskeyLimitReached)
                .with_param("limit", MAX_PASSKEYS_PER_USER.to_string()));
        }
        mfa::install_recovery_codes(&txn, user_id, &recovery_codes).await?;
        let passkey_oid = key.id;
        user_credential::ActiveModel {
            oid: Set(key.id),
            user_id: Set(user_id),
            r#type: Set(CredentialType::Passkey.to_string()),
            data: Set(to_value(key.data).map_err(AppError::internal)?),
            expires_at: Set(None),
            created_at: Set(Utc::now().into()),
            ..Default::default()
        }
        .insert(&txn)
        .await
        .map_err(AppError::internal)?;
        // A new passkey is a fingerprinted credential addition. Permanently
        // withdraw authority so artifacts from the prior credential set cannot
        // be revived by later removal/replacement.
        withdraw_user_authority_in_txn(&txn, user_id)
            .await
            .map_err(AppError::internal)?;
        audit::record(&txn, "security.insert", "user_credential", passkey_oid)
            .await
            .map_err(AppError::internal)?;
        txn.commit().await.map_err(AppError::internal)
    }

    async fn update(
        &self,
        user: UserOid,
        before: &StoredPasskey,
        after: &StoredPasskey,
    ) -> Result<bool, AppError> {
        use sea_orm::{ConnectionTrait, DbBackend, Statement};
        if before.id != after.id || before.data.credential_id != after.data.credential_id {
            return Ok(false);
        }
        let txn = audit::begin(&self.db, "security.update")
            .await
            .map_err(AppError::internal)?;
        let result = txn.execute_raw(Statement::from_sql_and_values(DbBackend::Postgres,
            "UPDATE user_credential SET data = $1, updated_at = now() WHERE oid = $2 AND user_id = (SELECT id FROM \"user\" WHERE oid = $3) AND type = 'passkey' AND data = $4 AND (expires_at IS NULL OR expires_at > now())",
            [to_value(&after.data).map_err(AppError::internal)?.into(), before.id.into(), Uuid::from(user).into(), to_value(&before.data).map_err(AppError::internal)?.into()]
        )).await.map_err(AppError::internal)?;
        let updated = result.rows_affected() == 1;
        if updated {
            audit::record(&txn, "security.update", "user_credential", before.id)
                .await
                .map_err(AppError::internal)?;
        }
        txn.commit().await.map_err(AppError::internal)?;
        Ok(updated)
    }

    async fn delete(&self, user: UserOid, id: Uuid) -> Result<bool, AppError> {
        let txn = audit::begin(&self.db, "security.delete")
            .await
            .map_err(AppError::internal)?;
        // Serialize with owner binding/account changes before touching the
        // credential set.
        lock_owner_lifecycle(&txn)
            .await
            .map_err(AppError::internal)?;
        lock_user_credentials(&txn, user)
            .await
            .map_err(AppError::internal)?;
        let user_id = UserEntity::find()
            .select_only()
            .column(user::Column::Id)
            .filter(user::Column::Oid.eq(Uuid::from(user)))
            .into_tuple::<i64>()
            .one(&txn)
            .await
            .map_err(AppError::internal)?
            .ok_or(UserCredentialRepositoryError::CredentialNotFound)?;
        let deleted = UserCredentialEntity::delete_many()
            .filter(user_credential::Column::UserId.eq(user_id))
            .filter(user_credential::Column::Oid.eq(id))
            .filter(user_credential::Column::Type.eq(CredentialType::Passkey.as_ref()))
            .exec(&txn)
            .await
            .map_err(AppError::internal)?
            .rows_affected
            > 0;
        if deleted {
            // The deletion is visible in this transaction; reject before audit
            // and commit if it removed the last recoverable full-capability
            // administrator login path.
            ensure_recoverable_authorization_administrator(&txn)
                .await
                .map_err(|error| match &error {
                    DbErr::Custom(message)
                        if message == "no recoverable authorization administrator remains" =>
                    {
                        AppError::from_code(AuthorizationErrorCode::LastOwnerProtected)
                    }
                    _ => AppError::internal(error),
                })?;
            mfa::clear_recovery_codes_without_mfa(&txn, user_id).await?;
            // Removing a passkey can remove the last MFA method; a later
            // re-enrollment or replacement must not revive earlier artifacts.
            withdraw_user_authority_in_txn(&txn, user_id)
                .await
                .map_err(AppError::internal)?;
            audit::record(&txn, "security.delete", "user_credential", id)
                .await
                .map_err(AppError::internal)?;
        }
        txn.commit().await.map_err(AppError::internal)?;
        Ok(deleted)
    }
}

#[cfg(test)]
mod passkey_tests {
    use super::*;
    use identity_application::error::code::AppErrorCode as _;
    use sea_orm::{DatabaseBackend, MockDatabase, MockExecResult, Value};
    use serde_json::json;
    use std::collections::BTreeMap;

    #[tokio::test]
    async fn passkey_insert_checks_the_active_limit_under_the_credential_lock() {
        for count in [MAX_PASSKEYS_PER_USER - 1, MAX_PASSKEYS_PER_USER] {
            let user = UserOid(Uuid::new_v4());
            let key = StoredPasskey {
                id: Uuid::new_v4(),
                data: identity_application::user::credential::PasskeyCredentialData {
                    name: "Laptop".to_owned(),
                    credential_id: "new-key".to_owned(),
                    key: json!({}),
                },
            };
            let id_row = |id: i64| BTreeMap::from([("id".to_owned(), Value::BigInt(Some(id)))]);
            let mut exec_results = vec![MockExecResult {
                rows_affected: 0,
                last_insert_id: 0,
            }];
            if count < MAX_PASSKEYS_PER_USER {
                // Permanent authority withdrawal writes the client_authorization
                // tombstone before the semantic audit insert.
                exec_results.push(MockExecResult {
                    rows_affected: 0,
                    last_insert_id: 0,
                });
                exec_results.push(MockExecResult {
                    rows_affected: 1,
                    last_insert_id: 0,
                });
            }
            let db = MockDatabase::new(DatabaseBackend::Postgres)
                .append_exec_results(exec_results)
                .append_query_results([
                    vec![id_row(7)],
                    (0..count).map(|id| id_row(id as i64)).collect(),
                ])
                .append_query_results([[BTreeMap::from([(
                    "data".to_owned(),
                    Value::from(json!({"hash":"existing"})),
                )])]])
                .append_query_results([[user_credential::Model {
                    id: 42,
                    oid: key.id,
                    user_id: 7,
                    r#type: "passkey".to_owned(),
                    data: to_value(&key.data).unwrap(),
                    expires_at: None,
                    created_at: Utc::now().into(),
                    updated_at: None,
                }]])
                // The withdrawal rotates the user CAS UUID before tombstoning
                // artifacts.
                .append_query_results([[BTreeMap::from([(
                    "version".to_owned(),
                    Value::from(Uuid::new_v4()),
                )])]])
                .into_connection();
            let result = PasskeyCredentialRepository::insert(
                &UserCredentialRepositoryImpl::new(db.clone()),
                user,
                key,
                Vec::new(),
            )
            .await;
            if count < MAX_PASSKEYS_PER_USER {
                result.unwrap();
            } else {
                assert_eq!(
                    result.unwrap_err().code(),
                    AuthErrorCode::PasskeyLimitReached.code()
                );
            }
            let sql = format!("{:?}", db.into_transaction_log());
            assert!(
                sql.find("pg_advisory_xact_lock").unwrap() < sql.find("user_credential").unwrap(),
                "{sql}"
            );
            assert!(
                sql.contains("expires_at")
                    && sql.contains("IS NULL")
                    && sql.contains("user_id")
                    && sql.contains("passkey"),
                "{sql}"
            );
            assert_eq!(
                sql.contains("INSERT INTO"),
                count < MAX_PASSKEYS_PER_USER,
                "{sql}"
            );
        }
    }
}
