//! Shared challenge persistence; cryptographic and OTP verification stay in use cases.
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use identity_application::{
    auth::challenge::ChallengeRepository,
    error::{AppError, codes::auth::AuthErrorCode},
};
use identity_domain::auth::challenge::{
    AuthenticationChallenge, ChallengeBinding, ChallengeContext,
};
use sea_orm::{ConnectionTrait, DatabaseConnection, DbBackend, DbErr, Statement};
use uuid::Uuid;

pub struct ChallengeRepositoryImpl {
    db: DatabaseConnection,
}

impl ChallengeRepositoryImpl {
    pub fn new(db: DatabaseConnection) -> Self {
        Self { db }
    }
}

fn location(binding: ChallengeBinding) -> (&'static str, &'static str, &'static str, Uuid) {
    match binding {
        ChallengeBinding::Login(id) => (
            "login",
            "login_id",
            "status IN ('identifier_verified', 'mfa_required') AND expires_at > now()",
            id,
        ),
        ChallengeBinding::Session(id) => (
            "session",
            "session_id",
            "status = 'active' AND revoked_at IS NULL AND expires_at > now()",
            id,
        ),
    }
}

/// Called inside the owner's transition transaction, after locking/updating it.
pub(super) async fn clear_for_binding(
    db: &impl ConnectionTrait,
    binding: ChallengeBinding,
) -> Result<(), DbErr> {
    let (table, column, _, oid) = location(binding);
    db.execute_raw(Statement::from_sql_and_values(
        DbBackend::Postgres,
        format!(
            r#"DELETE FROM authentication_challenge AS challenge USING "{table}" AS owner
            WHERE challenge.{column} = owner.id AND owner.oid = $1"#
        ),
        [oid.into()],
    ))
    .await?;
    Ok(())
}

#[async_trait]
impl ChallengeRepository for ChallengeRepositoryImpl {
    async fn store(
        &self,
        context: ChallengeContext,
        challenge: AuthenticationChallenge,
    ) -> Result<(), AppError> {
        let (table, column, active, binding) = location(context.binding);
        // Lock the owner first, matching login transitions and session revocation.
        // Different challenge IDs remain independent, including in multiple tabs.
        // Prune a bounded batch of expired rows on writes, using the expiry index.
        let sql = format!(
            r#"
            WITH owner AS MATERIALIZED (
                SELECT id, user_id FROM "{table}"
                WHERE oid = $1 AND user_id = (SELECT id FROM "user" WHERE oid = $2)
                  AND {active} FOR UPDATE
            ), expired AS (
                DELETE FROM authentication_challenge WHERE id IN (
                    SELECT id FROM authentication_challenge WHERE expires_at <= now()
                    ORDER BY expires_at LIMIT 100 FOR UPDATE SKIP LOCKED
                )
            )
            INSERT INTO authentication_challenge
                (oid, user_id, {column}, method, purpose, state, expires_at)
            SELECT $3, user_id, id, $4, $5, $6, $7 FROM owner
        "#
        );
        let result = self
            .db
            .execute_raw(Statement::from_sql_and_values(
                DbBackend::Postgres,
                sql,
                [
                    binding.into(),
                    context.user_oid.into(),
                    challenge.id.into(),
                    context.method.as_str().into(),
                    context.purpose.as_str().into(),
                    challenge.state.into(),
                    challenge.expires_at.into(),
                ],
            ))
            .await
            .map_err(AppError::internal)?;
        if result.rows_affected() != 1 {
            return Err(AppError::from_code(AuthErrorCode::InvalidCredential));
        }
        Ok(())
    }

    async fn take(
        &self,
        context: ChallengeContext,
        id: Uuid,
    ) -> Result<Option<AuthenticationChallenge>, AppError> {
        let (table, column, active, binding) = location(context.binding);
        let sql = format!(
            r#"
            WITH owner AS MATERIALIZED (
                SELECT id, user_id FROM "{table}"
                WHERE oid = $1 AND user_id = (SELECT id FROM "user" WHERE oid = $2)
                  AND {active} FOR UPDATE
            )
            DELETE FROM authentication_challenge AS challenge USING owner
            WHERE challenge.{column} = owner.id AND challenge.user_id = owner.user_id
              AND challenge.oid = $3 AND challenge.method = $4 AND challenge.purpose = $5
              AND challenge.expires_at > now()
            RETURNING challenge.oid, challenge.state, challenge.expires_at
        "#
        );
        self.db
            .query_one_raw(Statement::from_sql_and_values(
                DbBackend::Postgres,
                sql,
                [
                    binding.into(),
                    context.user_oid.into(),
                    id.into(),
                    context.method.as_str().into(),
                    context.purpose.as_str().into(),
                ],
            ))
            .await
            .map_err(AppError::internal)?
            .map(|row| {
                Ok(AuthenticationChallenge {
                    id: row.try_get("", "oid").map_err(AppError::internal)?,
                    state: row.try_get("", "state").map_err(AppError::internal)?,
                    expires_at: DateTime::<Utc>::from(
                        row.try_get::<DateTime<chrono::FixedOffset>>("", "expires_at")
                            .map_err(AppError::internal)?,
                    ),
                })
            })
            .transpose()
    }
}
