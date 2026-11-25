//! Persistence of self-registration. The account is created in the same
//! transaction that uses up the login's registration challenge and binds the
//! login to the new account.

use async_trait::async_trait;
use chrono::Utc;
use identity_application::{
    authentication::login::{NewAccount, RegistrationOutcome, RegistrationRepository},
    error::AppError,
};
use identity_domain::{
    audit::{AuditAction, AuditActor, AuditRecord},
    auth::{
        LoginStatus,
        challenge::{AuthenticationChallenge, ChallengeMethod, ChallengePurpose},
    },
};
use sea_orm::{
    ActiveModelTrait, ConnectionTrait, DatabaseConnection, DbBackend, Set, Statement,
    TransactionTrait,
};
use serde_json::{json, to_value};
use uuid::Uuid;

use crate::database::{
    audit,
    entity::{user, user_credential},
};

pub struct RegistrationRepositoryImpl {
    db: DatabaseConnection,
}

impl RegistrationRepositoryImpl {
    #[must_use]
    pub fn new(db: DatabaseConnection) -> Self {
        Self { db }
    }
}

fn internal(error: impl std::error::Error + Send + Sync + 'static) -> AppError {
    AppError::internal(error)
}

async fn identifier_taken<C: ConnectionTrait>(
    db: &C,
    column: &str,
    normalized: &str,
) -> Result<bool, AppError> {
    // `column` is one of two fixed identifiers, never input.
    Ok(db
        .query_one_raw(Statement::from_sql_and_values(
            DbBackend::Postgres,
            format!(r#"SELECT 1 AS present FROM "user" WHERE {column} = $1"#),
            [normalized.into()],
        ))
        .await
        .map_err(internal)?
        .is_some())
}

#[async_trait]
impl RegistrationRepository for RegistrationRepositoryImpl {
    #[tracing::instrument(skip_all, name = "db.query", fields(db.system = "postgresql", db.operation = "registration.email_registered"))]
    async fn email_registered(&self, email_normalized: &str) -> Result<bool, AppError> {
        identifier_taken(&self.db, "email_normalized", email_normalized).await
    }

    #[tracing::instrument(skip_all, name = "db.query", fields(db.system = "postgresql", db.operation = "registration.latest"))]
    async fn latest(&self, login_oid: Uuid) -> Result<Option<AuthenticationChallenge>, AppError> {
        let row = self
            .db
            .query_one_raw(Statement::from_sql_and_values(
                DbBackend::Postgres,
                r#"SELECT challenge.oid, challenge.state, challenge.expires_at
                   FROM authentication_challenge AS challenge
                   JOIN "login" AS owner ON challenge.login_id = owner.id
                   WHERE owner.oid = $1 AND owner.status = $2 AND owner.user_id IS NULL
                     AND owner.expires_at > now()
                     AND challenge.user_id IS NULL
                     AND challenge.method = $3 AND challenge.purpose = $4
                     AND challenge.expires_at > now()
                   ORDER BY challenge.created_at DESC, challenge.id DESC
                   LIMIT 1"#,
                [
                    login_oid.into(),
                    LoginStatus::CREATED.as_str().into(),
                    ChallengeMethod::EmailOtp.as_str().into(),
                    ChallengePurpose::Registration.as_str().into(),
                ],
            ))
            .await
            .map_err(internal)?;
        row.map(|row| {
            Ok(AuthenticationChallenge {
                id: row.try_get("", "oid").map_err(internal)?,
                state: row.try_get("", "state").map_err(internal)?,
                expires_at: row
                    .try_get::<chrono::DateTime<chrono::FixedOffset>>("", "expires_at")
                    .map_err(internal)?
                    .with_timezone(&Utc),
            })
        })
        .transpose()
    }

    #[tracing::instrument(skip_all, name = "db.query", fields(db.system = "postgresql", db.operation = "registration.register"))]
    async fn register(&self, account: NewAccount) -> Result<RegistrationOutcome, AppError> {
        let txn = self.db.begin().await.map_err(internal)?;
        let Some(login) = txn
            .query_one_raw(Statement::from_sql_and_values(
                DbBackend::Postgres,
                r#"SELECT id FROM "login"
                   WHERE oid = $1 AND status = $2 AND user_id IS NULL AND expires_at > now()
                   FOR UPDATE"#,
                [
                    account.login_oid.into(),
                    LoginStatus::CREATED.as_str().into(),
                ],
            ))
            .await
            .map_err(internal)?
        else {
            return Ok(RegistrationOutcome::LinkInvalid);
        };
        let login_id: i64 = login.try_get("", "id").map_err(internal)?;
        let used = txn
            .execute_raw(Statement::from_sql_and_values(
                DbBackend::Postgres,
                r#"DELETE FROM authentication_challenge
                   WHERE login_id = $1 AND oid = $2 AND user_id IS NULL
                     AND method = $3 AND purpose = $4 AND expires_at > now()"#,
                [
                    login_id.into(),
                    account.challenge_oid.into(),
                    ChallengeMethod::EmailOtp.as_str().into(),
                    ChallengePurpose::Registration.as_str().into(),
                ],
            ))
            .await
            .map_err(internal)?;
        if used.rows_affected() != 1 {
            return Ok(RegistrationOutcome::LinkInvalid);
        }
        // Checked here for a field error; the unique indexes still decide a
        // race, which then fails the transaction.
        if identifier_taken(&txn, "name_normalized", &account.username_normalized).await? {
            return Ok(RegistrationOutcome::UsernameExists);
        }
        if identifier_taken(&txn, "email_normalized", &account.email_normalized).await? {
            return Ok(RegistrationOutcome::EmailExists);
        }

        let now = Utc::now();
        let user_oid = Uuid::new_v4();
        let model = user::ActiveModel {
            oid: Set(user_oid),
            name: Set(account.username),
            name_normalized: Set(account.username_normalized),
            email: Set(account.email),
            email_normalized: Set(account.email_normalized),
            // Following the emailed link proved the address.
            email_verified: Set(true),
            preferences: Set(json!({})),
            failed_attempts: Set(0),
            enabled: Set(true),
            locked: Set(false),
            created_at: Set(now.into()),
            ..Default::default()
        }
        .insert(&txn)
        .await
        .map_err(internal)?;
        user_credential::ActiveModel {
            oid: Set(Uuid::new_v4()),
            user_id: Set(model.id),
            r#type: Set("password".to_owned()),
            data: Set(to_value(&account.password).map_err(internal)?),
            expires_at: Set(None),
            created_at: Set(now.into()),
            ..Default::default()
        }
        .insert(&txn)
        .await
        .map_err(internal)?;
        let bound = txn
            .execute_raw(Statement::from_sql_and_values(
                DbBackend::Postgres,
                r#"UPDATE "login" SET user_id = $1, submitted_identifier = NULL, status = $2,
                     updated_at = now()
                   WHERE id = $3 AND status = $4 AND user_id IS NULL"#,
                [
                    model.id.into(),
                    LoginStatus::IDENTIFIER_VERIFIED.as_str().into(),
                    login_id.into(),
                    LoginStatus::CREATED.as_str().into(),
                ],
            ))
            .await
            .map_err(internal)?;
        if bound.rows_affected() != 1 {
            return Ok(RegistrationOutcome::LinkInvalid);
        }
        audit::record(
            &txn,
            AuditRecord::success(AuditAction::AccountRegister, user_oid)
                .default_actor(AuditActor::user(user_oid)),
        )
        .await
        .map_err(internal)?;
        txn.commit().await.map_err(internal)?;
        Ok(RegistrationOutcome::Registered)
    }
}
