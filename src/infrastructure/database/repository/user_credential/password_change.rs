//! Account security transition: all mutations commit or roll back together.
use super::*;
use identity_application::user::repository::PasswordReplacementKind;
use identity_domain::auth::LOGIN_EXPIRY;
use sea_orm::{ConnectionTrait, DbBackend, Statement};
use user::Column as UserColumn;
use uuid::Uuid as UuidUuid;

use super::super::{authorization_lifecycle::withdraw_user_authority_for_login_in_txn, session};

impl UserCredentialRepositoryImpl {
    pub(super) async fn change_password_transaction(
        &self,
        user: UserOid,
        credential: UserCredentialOid,
        expected: &Password,
        password: &Password,
        replacement: PasswordReplacement,
    ) -> Result<u32, UserCredentialRepositoryError> {
        let (keep, kept_login, kept_status) = match replacement.kind {
            PasswordReplacementKind::Change { keep } => (keep, None, ""),
            PasswordReplacementKind::Reset { login } => (None, Some(login), "identifier_verified"),
            PasswordReplacementKind::Required { login, keep } => {
                (keep, Some(login), "password_change_required")
            }
        };
        let fail = |error| UserCredentialRepositoryError::UpdatePasswordFailed(Box::new(error));
        let txn = self.db.begin().await.map_err(fail)?;
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
        // The replaced hash stays as an expired password credential for the
        // history check: every credential read ignores expired rows. Admin
        // temporary passwords are not recorded so they never displace a user
        // password from history.
        if replacement.keep_history > 0 {
            txn.execute_raw(Statement::from_sql_and_values(
                DbBackend::Postgres,
                "INSERT INTO user_credential (oid, user_id, type, data, expires_at, created_at, updated_at) \
                 SELECT gen_random_uuid(), user_id, type, data, now(), created_at, updated_at \
                 FROM user_credential WHERE oid = $1 AND user_id = $2 AND type = 'password' \
                 AND COALESCE(data->>'temporary', 'false') <> 'true'",
                [Uuid::from(credential).into(), owner.id.into()],
            ))
            .await
            .map_err(fail)?;
        }
        prune_password_history(&txn, owner.id, replacement.keep_history)
            .await
            .map_err(fail)?;
        // A semantic password replacement receives a new stable credential OID
        // in the same transaction. Credential usage-only paths keep their OID.
        // The authority fingerprint hashes this OID, never password material.
        let replacement_oid = UuidUuid::new_v4();
        let new_data = to_value(password).map_err(UserCredentialRepositoryError::Serialization)?;
        let expected_data =
            to_value(expected).map_err(UserCredentialRepositoryError::Serialization)?;
        let changed = txn
            .execute_raw(Statement::from_sql_and_values(
                DbBackend::Postgres,
                "UPDATE user_credential SET oid = $1, data = $2::jsonb, updated_at = now() \
                 WHERE oid = $3 AND user_id = $4 AND type = 'password' \
                 AND (data - 'temporary') = $5::jsonb \
                 AND (expires_at IS NULL OR expires_at > now())",
                [
                    replacement_oid.into(),
                    new_data.into(),
                    Uuid::from(credential).into(),
                    owner.id.into(),
                    expected_data.into(),
                ],
            ))
            .await
            .map_err(fail)?;
        if changed.rows_affected() != 1 {
            return Err(UserCredentialRepositoryError::CredentialNotFound);
        }
        let keep_oid = keep.map(|s| s.0);
        let result = txn.execute_raw(Statement::from_sql_and_values(DbBackend::Postgres,
            "UPDATE session SET status = 'revoked', revoked_at = now(), updated_at = now() WHERE user_id = $1 AND ($2::uuid IS NULL OR oid <> $2) AND status = 'active' AND revoked_at IS NULL",
            [owner.id.into(), keep_oid.into()])).await.map_err(fail)?;
        // Invalidating pending flows also closes an already-verified password/MFA race.
        // A reset or a required change keeps the login it came from, so the
        // account can finish signing in with the new password.
        txn.execute_raw(Statement::from_sql_and_values(DbBackend::Postgres,
            "UPDATE login SET status = 'failed', updated_at = now() WHERE user_id = $1 AND status IN ('created', 'identifier_verified', 'mfa_required', 'mfa_enrollment_required', 'password_change_required') AND NOT ($2::uuid IS NOT NULL AND oid = $2 AND status = $3)", [owner.id.into(), kept_login.into(), kept_status.into()])).await.map_err(fail)?;
        if let Some(login) = kept_login {
            txn.execute_raw(Statement::from_sql_and_values(DbBackend::Postgres,
                "UPDATE login SET failed_attempts = 0, failure_reason = NULL, expires_at = GREATEST(expires_at, now() + make_interval(secs => $3)), updated_at = now() WHERE user_id = $1 AND oid = $2 AND status = $4",
                [owner.id.into(), login.into(), (LOGIN_EXPIRY.as_secs_f64()).into(), kept_status.into()])).await.map_err(fail)?;
        }
        // A new password fulfils a required password change.
        txn.execute_raw(Statement::from_sql_and_values(
            DbBackend::Postgres,
            "UPDATE \"user\" SET required_actions = required_actions - 'change_password' \
             WHERE id = $1 AND required_actions @> '[\"change_password\"]'",
            [owner.id.into()],
        ))
        .await
        .map_err(fail)?;
        if matches!(replacement.kind, PasswordReplacementKind::Reset { .. }) {
            // Proving the email address ends a lockout caused by wrong passwords.
            UserEntity::update_many()
                .col_expr(UserColumn::FailedAttempts, Expr::value(0i32))
                .col_expr(UserColumn::Locked, Expr::value(false))
                .col_expr(
                    UserColumn::LockedUntil,
                    Expr::value(Option::<chrono::DateTime<chrono::FixedOffset>>::None),
                )
                .filter(UserColumn::Id.eq(owner.id))
                .filter(
                    UserColumn::LockedUntil
                        .is_not_null()
                        .or(UserColumn::Locked.eq(false)),
                )
                .exec(&txn)
                .await
                .map_err(fail)?;
        }
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
        // parents) withdrawn, sparing only the pending request of the active
        // reset or required-password-change login so it can finish.
        withdraw_user_authority_for_login_in_txn(
            &txn,
            owner.id,
            kept_login.map(|oid| (oid, kept_status)),
        )
        .await
        .map_err(fail)?;
        audit::record(
            &txn,
            AuditRecord::success(
                if matches!(replacement.kind, PasswordReplacementKind::Reset { .. }) {
                    AuditAction::AccountPasswordReset
                } else {
                    AuditAction::AccountPasswordChange
                },
                Uuid::from(user),
            )
            .default_actor(AuditActor::user(Uuid::from(user)))
            .with_changes(|changes| {
                changes.secret(AuditField::Password);
            }),
        )
        .await
        .map_err(fail)?;
        txn.commit().await.map_err(fail)?;
        Ok(u32::try_from(result.rows_affected()).unwrap_or(u32::MAX))
    }
}

/// Keep the `keep` most recently replaced password hashes of `user_id`.
pub(crate) async fn prune_password_history<C: ConnectionTrait>(
    txn: &C,
    user_id: i64,
    keep: u32,
) -> Result<(), sea_orm::DbErr> {
    txn.execute_raw(Statement::from_sql_and_values(
        DbBackend::Postgres,
        "DELETE FROM user_credential WHERE id IN ( \
             SELECT id FROM user_credential \
             WHERE user_id = $1 AND type = 'password' AND expires_at IS NOT NULL AND expires_at <= now() \
             ORDER BY expires_at DESC, id DESC OFFSET $2)",
        [user_id.into(), i64::from(keep).into()],
    ))
    .await
    .map(|_| ())
}
