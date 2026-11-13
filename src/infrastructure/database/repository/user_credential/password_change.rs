//! Account security transition: all mutations commit or roll back together.
use super::*;
use identity_domain::auth::SessionOid;
use sea_orm::{ConnectionTrait, DbBackend, Statement};
use user::Column as UserColumn;
use user_credential::Column as UserCredentialColumn;
use uuid::Uuid as UuidUuid;

use super::super::{authorization_lifecycle::withdraw_user_authority_in_txn, session};
use crate::database::audit as database_audit;

impl UserCredentialRepositoryImpl {
    pub(super) async fn change_password_transaction(
        &self,
        user: UserOid,
        credential: UserCredentialOid,
        expected: &Password,
        password: &Password,
        keep: Option<SessionOid>,
    ) -> Result<u32, UserCredentialRepositoryError> {
        let fail = |error| UserCredentialRepositoryError::UpdatePasswordFailed(Box::new(error));
        let txn = database_audit::begin(&self.db, "security.change_password_transaction")
            .await
            .map_err(fail)?;
        lock_user_credentials(&txn, user).await.map_err(fail)?;
        let owner = UserEntity::find()
            .filter(UserColumn::Oid.eq(Uuid::from(user)))
            .one(&txn)
            .await
            .map_err(fail)?
            .ok_or(UserCredentialRepositoryError::CredentialNotFound)?;
        // Match token issuance's session advisory locks before touching grants.
        let sessions = session::lock_account_sessions(&txn, owner.id)
            .await
            .map_err(fail)?;
        if let Some(keep) = keep
            && !sessions.iter().any(|s| {
                s.oid == keep.0
                    && s.status == "active"
                    && s.revoked_at.is_none()
                    && s.expires_at > Utc::now().fixed_offset()
            })
        {
            return Err(UserCredentialRepositoryError::CredentialNotFound);
        }
        // A semantic password replacement receives a new stable credential OID
        // in the same transaction. Credential usage-only paths keep their OID.
        // The authority fingerprint hashes this OID, never password material.
        let replacement_oid = UuidUuid::new_v4();
        let changed = UserCredentialEntity::update_many()
            .col_expr(UserCredentialColumn::Oid, Expr::value(replacement_oid))
            .col_expr(
                UserCredentialColumn::Data,
                Expr::value(
                    to_value(password).map_err(UserCredentialRepositoryError::Serialization)?,
                ),
            )
            .col_expr(
                UserCredentialColumn::UpdatedAt,
                Expr::value(Some(Utc::now().fixed_offset())),
            )
            .filter(UserCredentialColumn::Oid.eq(Uuid::from(credential)))
            .filter(UserCredentialColumn::UserId.eq(owner.id))
            .filter(UserCredentialColumn::Type.eq("password"))
            .filter(
                UserCredentialColumn::Data
                    .eq(to_value(expected).map_err(UserCredentialRepositoryError::Serialization)?),
            )
            .filter(
                Condition::any()
                    .add(UserCredentialColumn::ExpiresAt.is_null())
                    .add(UserCredentialColumn::ExpiresAt.gt(Utc::now())),
            )
            .exec(&txn)
            .await
            .map_err(fail)?;
        if changed.rows_affected != 1 {
            return Err(UserCredentialRepositoryError::CredentialNotFound);
        }
        let keep_oid = keep.map(|s| s.0);
        let result = txn.execute_raw(Statement::from_sql_and_values(DbBackend::Postgres,
            "UPDATE session SET status = 'revoked', revoked_at = now(), updated_at = now() WHERE user_id = $1 AND ($2::uuid IS NULL OR oid <> $2) AND status = 'active' AND revoked_at IS NULL",
            [owner.id.into(), keep_oid.into()])).await.map_err(fail)?;
        // Invalidating pending flows also closes an already-verified password/MFA race.
        txn.execute_raw(Statement::from_sql_and_values(DbBackend::Postgres,
            "UPDATE login SET status = 'failed', updated_at = now() WHERE user_id = $1 AND status IN ('created', 'identifier_verified', 'mfa_required', 'mfa_enrollment_required')", [owner.id.into()])).await.map_err(fail)?;
        txn.execute_raw(Statement::from_sql_and_values(
            DbBackend::Postgres,
            "DELETE FROM authentication_challenge WHERE user_id = $1",
            [owner.id.into()],
        ))
        .await
        .map_err(fail)?;
        // Device grants are withdrawn first: redemption locks this relation before
        // inserting tokens. Tokens already redeemed are covered by the next update.
        txn.execute_raw(Statement::from_sql_and_values(DbBackend::Postgres,
            "UPDATE client_authorization SET revoked_at = now(), updated_at = now() WHERE type = 'device_authorization' AND revoked_at IS NULL AND data->>'user_oid' = $1", [Uuid::from(user).to_string().into()])).await.map_err(fail)?;
        txn.execute_raw(Statement::from_sql_and_values(DbBackend::Postgres,
            "UPDATE client_authorization SET revoked_at = now(), updated_at = now() WHERE revoked_at IS NULL AND type IN ('authorization_code','access_token','refresh_token') AND (data->>'session_oid' IN (SELECT oid::text FROM session WHERE user_id = $1 AND ($2::uuid IS NULL OR oid <> $2)) OR data->>'device_authorization_oid' IN (SELECT oid::text FROM client_authorization WHERE type = 'device_authorization' AND data->>'user_oid' = $3))",
            [owner.id.into(), keep_oid.into(), Uuid::from(user).to_string().into()])).await.map_err(fail)?;
        // A password change is a permanent authority boundary even when a
        // caller intentionally keeps one session: rotate the CAS token and mark
        // every subject artifact (including already consumed single-use
        // parents) withdrawn.
        withdraw_user_authority_in_txn(&txn, owner.id)
            .await
            .map_err(fail)?;
        audit::record(
            &txn,
            "security.change_password_transaction",
            "user_credential",
            credential.0,
        )
        .await
        .map_err(fail)?;
        txn.commit().await.map_err(fail)?;
        Ok(u32::try_from(result.rows_affected()).unwrap_or(u32::MAX))
    }
}
