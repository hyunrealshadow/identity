//! Recovery-code invariants shared by all credential mutations.
use super::*;
use sea_orm::{ConnectionTrait, DatabaseTransaction, Select};

#[cfg(test)]
mod tests;

fn active(user_id: i64, types: &[CredentialType]) -> Select<user_credential::Entity> {
    UserCredentialEntity::find()
        .filter(user_credential::Column::UserId.eq(user_id))
        .filter(user_credential::Column::Type.is_in(types.iter().map(CredentialType::as_ref)))
        .filter(
            Condition::any()
                .add(user_credential::Column::ExpiresAt.is_null())
                .add(user_credential::Column::ExpiresAt.gt(Utc::now())),
        )
}

pub(super) async fn has_active_mfa<C: ConnectionTrait>(
    connection: &C,
    user_id: i64,
) -> Result<bool, UserCredentialRepositoryError> {
    active(user_id, &[CredentialType::Otp, CredentialType::Passkey])
        .select_only()
        .column(user_credential::Column::Id)
        .into_tuple::<i64>()
        .one(connection)
        .await
        .map(|row| row.is_some())
        .map_err(|error| UserCredentialRepositoryError::QueryFailed(Box::new(error)))
}

/// Caller must hold the account credential lock for the entire transaction.
/// Never overwrite a surviving batch or resurrect already consumed codes.
pub(super) async fn install_recovery_codes(
    txn: &DatabaseTransaction,
    user_id: i64,
    prepared: &[RecoveryCodeCredentialData],
) -> Result<(), UserCredentialRepositoryError> {
    let existing = active(user_id, &[CredentialType::RecoveryCode])
        .select_only()
        .column(user_credential::Column::Data)
        .into_tuple::<serde_json::Value>()
        .all(txn)
        .await
        .map_err(|error| UserCredentialRepositoryError::QueryFailed(Box::new(error)))?
        .into_iter()
        .map(from_value::<RecoveryCodeCredentialData>)
        .collect::<Result<Vec<_>, _>>()
        .map_err(UserCredentialRepositoryError::Deserialization)?;
    if !existing.is_empty() {
        if !prepared.is_empty()
            && existing
                .iter()
                .any(|stored| !prepared.iter().any(|code| code.hash == stored.hash))
        {
            return Err(UserCredentialRepositoryError::InvalidMfaEnrollment);
        }
        return Ok(());
    }
    if prepared.is_empty() {
        return Err(UserCredentialRepositoryError::InvalidMfaEnrollment);
    }
    UserCredentialEntity::delete_many()
        .filter(user_credential::Column::UserId.eq(user_id))
        .filter(user_credential::Column::Type.eq(CredentialType::RecoveryCode.as_ref()))
        .exec(txn)
        .await
        .map_err(|error| UserCredentialRepositoryError::ReplaceFailed(Box::new(error)))?;
    for code in prepared {
        user_credential::ActiveModel {
            oid: Set(Uuid::new_v4()),
            user_id: Set(user_id),
            r#type: Set(CredentialType::RecoveryCode.to_string()),
            data: Set(to_value(code).map_err(UserCredentialRepositoryError::Serialization)?),
            expires_at: Set(None),
            created_at: Set(Utc::now().into()),
            ..Default::default()
        }
        .insert(txn)
        .await
        .map_err(|error| UserCredentialRepositoryError::ReplaceFailed(Box::new(error)))?;
    }
    Ok(())
}

/// Caller must hold the same account lock used for all MFA additions/removals.
pub(super) async fn clear_recovery_codes_without_mfa(
    txn: &DatabaseTransaction,
    user_id: i64,
) -> Result<(), UserCredentialRepositoryError> {
    if !has_active_mfa(txn, user_id).await? {
        UserCredentialEntity::delete_many()
            .filter(user_credential::Column::UserId.eq(user_id))
            .filter(user_credential::Column::Type.eq(CredentialType::RecoveryCode.as_ref()))
            .exec(txn)
            .await
            .map_err(|error| UserCredentialRepositoryError::DeleteFailed(Box::new(error)))?;
    }
    Ok(())
}

pub(super) async fn disable_totp(
    db: &DatabaseConnection,
    user_oid: UserOid,
) -> Result<bool, UserCredentialRepositoryError> {
    let failure = |error| UserCredentialRepositoryError::DeleteFailed(Box::new(error));
    let txn = db.begin().await.map_err(failure)?;
    lock_user_credentials(&txn, user_oid)
        .await
        .map_err(failure)?;
    let user_id = UserEntity::find()
        .select_only()
        .column(user::Column::Id)
        .filter(user::Column::Oid.eq(Uuid::from(user_oid)))
        .into_tuple::<i64>()
        .one(&txn)
        .await
        .map_err(failure)?
        .ok_or(UserCredentialRepositoryError::CredentialNotFound)?;
    let deleted = UserCredentialEntity::delete_many()
        .filter(user_credential::Column::UserId.eq(user_id))
        .filter(user_credential::Column::Type.eq(CredentialType::Otp.as_ref()))
        .exec(&txn)
        .await
        .map_err(failure)?
        .rows_affected
        > 0;
    if deleted {
        clear_recovery_codes_without_mfa(&txn, user_id).await?;
    }
    txn.commit().await.map_err(failure)?;
    Ok(deleted)
}

pub(super) async fn consume_recovery_code(
    db: &DatabaseConnection,
    credential: UserCredentialOid,
) -> Result<bool, UserCredentialRepositoryError> {
    use sea_orm::{JoinType, RelationTrait};
    let failure = |error| UserCredentialRepositoryError::DeleteFailed(Box::new(error));
    let txn = db.begin().await.map_err(failure)?;
    let owner = UserCredentialEntity::find()
        .select_only()
        .column(user::Column::Oid)
        .join(JoinType::InnerJoin, user_credential::Relation::User.def())
        .filter(user_credential::Column::Oid.eq(Uuid::from(credential)))
        .filter(user_credential::Column::Type.eq(CredentialType::RecoveryCode.as_ref()))
        .into_tuple::<Uuid>()
        .one(&txn)
        .await
        .map_err(failure)?;
    let Some(owner) = owner else {
        txn.commit().await.map_err(failure)?;
        return Ok(false);
    };
    lock_user_credentials(&txn, UserOid(owner))
        .await
        .map_err(failure)?;
    let deleted = UserCredentialEntity::delete_many()
        .filter(user_credential::Column::Oid.eq(Uuid::from(credential)))
        .filter(user_credential::Column::Type.eq(CredentialType::RecoveryCode.as_ref()))
        .filter(
            Condition::any()
                .add(user_credential::Column::ExpiresAt.is_null())
                .add(user_credential::Column::ExpiresAt.gt(Utc::now())),
        )
        .exec(&txn)
        .await
        .map_err(failure)?
        .rows_affected
        == 1;
    txn.commit().await.map_err(failure)?;
    Ok(deleted)
}
