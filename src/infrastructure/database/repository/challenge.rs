//! Shared challenge persistence; cryptographic and OTP verification stay in use cases.
use async_trait::async_trait;
use chrono::{DateTime, Duration, Utc};
use identity_application::{
    auth::challenge::ChallengeRepository,
    error::{AppError, codes::auth::AuthErrorCode},
};
use identity_domain::auth::{
    LoginStatus,
    challenge::{
        AuthenticationChallenge, ChallengeBinding, ChallengeContext, ChallengeMethod,
        ChallengePurpose, DeliveryChallengeAdmission, DeliveryChallengeContext,
        DeliveryChallengeRequest, DeliveryChallengeState, DeliveryChallengeStatus,
    },
};
use sea_orm::{ConnectionTrait, DatabaseConnection, DbBackend, DbErr, Statement, TransactionTrait};
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
            "status IN ('identifier_verified', 'mfa_required', 'mfa_enrollment_required') AND expires_at > now()",
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

    async fn admit_delivery(
        &self,
        context: DeliveryChallengeContext,
        request: DeliveryChallengeRequest,
    ) -> Result<DeliveryChallengeAdmission, AppError> {
        let txn = self.db.begin().await.map_err(AppError::internal)?;
        let expected_user_id = match context.user_oid {
            Some(user_oid) => {
                let row = txn
                    .query_one_raw(Statement::from_sql_and_values(
                        DbBackend::Postgres,
                        r#"SELECT id FROM "user" WHERE oid = $1"#,
                        [user_oid.into()],
                    ))
                    .await
                    .map_err(AppError::internal)?;
                let Some(row) = row else {
                    return Ok(DeliveryChallengeAdmission::InvalidState);
                };
                Some(row.try_get::<i64>("", "id").map_err(AppError::internal)?)
            }
            None => None,
        };

        let (owner_id, owner_expires_at, column) = match context.binding {
            ChallengeBinding::Login(login_oid) => {
                let Some(row) = txn
                    .query_one_raw(Statement::from_sql_and_values(
                        DbBackend::Postgres,
                        r#"SELECT id, user_id, status, expires_at FROM "login" WHERE oid = $1 FOR UPDATE"#,
                        [login_oid.into()],
                    ))
                    .await
                    .map_err(AppError::internal)?
                else {
                    return Ok(DeliveryChallengeAdmission::InvalidState);
                };
                let owner_id: i64 = row.try_get("", "id").map_err(AppError::internal)?;
                let owner_user_id: Option<i64> =
                    row.try_get("", "user_id").map_err(AppError::internal)?;
                let status_str: String = row.try_get("", "status").map_err(AppError::internal)?;
                let owner_expires_at = DateTime::<Utc>::from(
                    row.try_get::<DateTime<chrono::FixedOffset>>("", "expires_at")
                        .map_err(AppError::internal)?,
                );
                let Ok(status) = status_str.parse::<LoginStatus>() else {
                    return Ok(DeliveryChallengeAdmission::InvalidState);
                };
                let status_ok = match request.required_login_status {
                    Some(required) => status == required,
                    None => matches!(
                        status,
                        LoginStatus::IDENTIFIER_VERIFIED
                            | LoginStatus::MFA_REQUIRED
                            | LoginStatus::MFA_ENROLLMENT_REQUIRED
                    ),
                };
                if !status_ok
                    || owner_user_id != expected_user_id
                    || owner_expires_at <= request.now
                {
                    return Ok(DeliveryChallengeAdmission::InvalidState);
                }
                (owner_id, owner_expires_at, "login_id")
            }
            ChallengeBinding::Session(session_oid) => {
                let Some(row) = txn
                    .query_one_raw(Statement::from_sql_and_values(
                        DbBackend::Postgres,
                        r#"SELECT id, user_id, status, revoked_at, expires_at FROM "session" WHERE oid = $1 FOR UPDATE"#,
                        [session_oid.into()],
                    ))
                    .await
                    .map_err(AppError::internal)?
                else {
                    return Ok(DeliveryChallengeAdmission::InvalidState);
                };
                let owner_id: i64 = row.try_get("", "id").map_err(AppError::internal)?;
                let owner_user_id: i64 = row.try_get("", "user_id").map_err(AppError::internal)?;
                let status_str: String = row.try_get("", "status").map_err(AppError::internal)?;
                let revoked_at: Option<DateTime<chrono::FixedOffset>> =
                    row.try_get("", "revoked_at").map_err(AppError::internal)?;
                let owner_expires_at = DateTime::<Utc>::from(
                    row.try_get::<DateTime<chrono::FixedOffset>>("", "expires_at")
                        .map_err(AppError::internal)?,
                );
                if Some(owner_user_id) != expected_user_id
                    || status_str != "active"
                    || revoked_at.is_some()
                    || owner_expires_at <= request.now
                {
                    return Ok(DeliveryChallengeAdmission::InvalidState);
                }
                (owner_id, owner_expires_at, "session_id")
            }
        };

        let existing = txn
            .query_one_raw(Statement::from_sql_and_values(
                DbBackend::Postgres,
                format!(
                    r#"
                    SELECT id, state
                    FROM authentication_challenge
                    WHERE {column} = $1 AND method = $2 AND purpose = $3
                    ORDER BY created_at DESC, id DESC
                    LIMIT 1
                    FOR UPDATE
                "#
                ),
                [
                    owner_id.into(),
                    context.method.as_str().into(),
                    context.purpose.as_str().into(),
                ],
            ))
            .await
            .map_err(AppError::internal)?;

        let interval =
            Duration::from_std(request.resend_interval).unwrap_or_else(|_| Duration::seconds(60));
        let (existing_id, prev_send_count) = if let Some(row) = existing {
            let existing_id: i64 = row.try_get("", "id").map_err(AppError::internal)?;
            let state_json: serde_json::Value =
                row.try_get("", "state").map_err(AppError::internal)?;
            let state: DeliveryChallengeState =
                serde_json::from_value(state_json).map_err(AppError::internal)?;
            if state.send_count >= request.max_sends {
                return Ok(DeliveryChallengeAdmission::LimitReached);
            }
            let available_at = state.sent_at + interval;
            if available_at > request.now {
                return Ok(DeliveryChallengeAdmission::TooSoon { available_at });
            }
            (Some(existing_id), state.send_count)
        } else {
            (None, 0)
        };

        let send_count = prev_send_count + 1;
        let resend_available_at = request.now + interval;
        let new_state = serde_json::to_value(DeliveryChallengeState {
            sent_at: request.now,
            send_count,
            code_expires_at: request.code_expires_at,
            verifier: request.verifier,
        })
        .map_err(AppError::internal)?;

        let row_expires_at = match context.binding {
            ChallengeBinding::Login(_) => {
                txn.execute_raw(Statement::from_sql_and_values(
                    DbBackend::Postgres,
                    r#"UPDATE "login" SET expires_at = GREATEST(expires_at, $1), updated_at = $2 WHERE id = $3"#,
                    [
                        request.code_expires_at.fixed_offset().into(),
                        request.now.fixed_offset().into(),
                        owner_id.into(),
                    ],
                ))
                .await
                .map_err(AppError::internal)?;
                owner_expires_at.max(request.code_expires_at)
            }
            ChallengeBinding::Session(_) => owner_expires_at,
        };

        let new_oid = Uuid::new_v4();
        if let Some(existing_id) = existing_id {
            txn.execute_raw(Statement::from_sql_and_values(
                DbBackend::Postgres,
                r#"
                UPDATE authentication_challenge
                SET oid = $1, user_id = $2, state = $3, expires_at = $4, created_at = $5
                WHERE id = $6
            "#,
                [
                    new_oid.into(),
                    expected_user_id.into(),
                    new_state.into(),
                    row_expires_at.fixed_offset().into(),
                    request.now.fixed_offset().into(),
                    existing_id.into(),
                ],
            ))
            .await
            .map_err(AppError::internal)?;
        } else {
            txn.execute_raw(Statement::from_sql_and_values(
                DbBackend::Postgres,
                format!(
                    r#"
                    WITH expired AS (
                        DELETE FROM authentication_challenge WHERE id IN (
                            SELECT id FROM authentication_challenge WHERE expires_at <= now()
                            ORDER BY expires_at LIMIT 100 FOR UPDATE SKIP LOCKED
                        )
                    )
                    INSERT INTO authentication_challenge
                        (oid, user_id, {column}, method, purpose, state, expires_at, created_at)
                    VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
                "#
                ),
                [
                    new_oid.into(),
                    expected_user_id.into(),
                    owner_id.into(),
                    context.method.as_str().into(),
                    context.purpose.as_str().into(),
                    new_state.into(),
                    row_expires_at.fixed_offset().into(),
                    request.now.fixed_offset().into(),
                ],
            ))
            .await
            .map_err(AppError::internal)?;
        }

        txn.commit().await.map_err(AppError::internal)?;
        Ok(DeliveryChallengeAdmission::Admitted {
            sent_at: request.now,
            send_count,
            resend_available_at,
        })
    }

    async fn delivery_status(
        &self,
        binding: ChallengeBinding,
        method: ChallengeMethod,
        purpose: ChallengePurpose,
    ) -> Result<Option<DeliveryChallengeStatus>, AppError> {
        let (table, column, active, binding_oid) = location(binding);
        let sql = format!(
            r#"
            WITH owner AS MATERIALIZED (
                SELECT id FROM "{table}"
                WHERE oid = $1 AND {active}
            )
            SELECT challenge.state
            FROM authentication_challenge AS challenge JOIN owner
              ON challenge.{column} = owner.id
            WHERE challenge.method = $2 AND challenge.purpose = $3
              AND challenge.expires_at > now()
            ORDER BY challenge.created_at DESC, challenge.id DESC
            LIMIT 1
        "#
        );
        let Some(row) = self
            .db
            .query_one_raw(Statement::from_sql_and_values(
                DbBackend::Postgres,
                sql,
                [
                    binding_oid.into(),
                    method.as_str().into(),
                    purpose.as_str().into(),
                ],
            ))
            .await
            .map_err(AppError::internal)?
        else {
            return Ok(None);
        };
        let state_json: serde_json::Value = row.try_get("", "state").map_err(AppError::internal)?;
        let state: DeliveryChallengeState =
            serde_json::from_value(state_json).map_err(AppError::internal)?;
        Ok(Some(DeliveryChallengeStatus {
            sent_at: state.sent_at,
            send_count: state.send_count,
        }))
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

    async fn latest(
        &self,
        context: ChallengeContext,
    ) -> Result<Option<AuthenticationChallenge>, AppError> {
        let (table, column, active, binding) = location(context.binding);
        let sql = format!(
            r#"
            WITH owner AS MATERIALIZED (
                SELECT id, user_id FROM "{table}"
                WHERE oid = $1 AND user_id = (SELECT id FROM "user" WHERE oid = $2)
                  AND {active}
            )
            SELECT challenge.oid, challenge.state, challenge.expires_at
            FROM authentication_challenge AS challenge JOIN owner
              ON challenge.{column} = owner.id AND challenge.user_id = owner.user_id
            WHERE challenge.method = $3 AND challenge.purpose = $4
              AND challenge.expires_at > now()
            ORDER BY challenge.created_at DESC, challenge.id DESC
            LIMIT 1
        "#
        );
        self.db
            .query_one_raw(Statement::from_sql_and_values(
                DbBackend::Postgres,
                sql,
                [
                    binding.into(),
                    context.user_oid.into(),
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
