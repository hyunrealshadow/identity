use async_trait::async_trait;
use chrono::{DateTime, Duration, Utc};
use identity_domain::audit::{AuditAction, AuditActor, AuditFailureReason, AuditRecord};
use identity_domain::auth::{
    AuthenticationContextClass, LOGIN_EXPIRY, LoginFailureReason, LoginStatus, SessionOid,
    SessionStatus,
    challenge::ChallengeBinding,
    model::Login,
    repository::{LoginRepository, LoginRepositoryError},
};
use sea_orm::{
    ActiveModelTrait, ColumnTrait, ConnectionTrait, DatabaseConnection, DbErr, EntityTrait,
    ExprTrait, QueryFilter, QuerySelect, Set, TransactionTrait, sea_query::Expr,
};
use uuid::Uuid;

use super::{challenge, shared};
use crate::database::{
    audit,
    entity::{
        client::{Column as ClientColumn, Entity as ClientEntity},
        client_authorization::{
            Column as ClientAuthorizationColumn, Entity as ClientAuthorizationEntity,
        },
        login,
        login::{Column as LoginColumn, Entity as LoginEntity},
        session::{Column as SessionColumn, Entity as SessionEntity},
        user::{Column as UserColumn, Entity as UserEntity},
    },
};

/// The identified user, if any, and the client application of a login.
async fn login_parties<C: ConnectionTrait>(
    conn: &C,
    login: &login::Model,
) -> Result<(Option<Uuid>, Uuid), DbErr> {
    let user_oid = match login.user_id {
        Some(user_id) => {
            UserEntity::find_by_id(user_id)
                .select_only()
                .column(UserColumn::Oid)
                .into_tuple::<Uuid>()
                .one(conn)
                .await?
        }
        None => None,
    };
    Ok((user_oid, login_client_oid(conn, login.client_id).await?))
}

/// The OID of the client application a login belongs to.
async fn login_client_oid<C: ConnectionTrait>(conn: &C, client_id: i64) -> Result<Uuid, DbErr> {
    ClientEntity::find_by_id(client_id)
        .select_only()
        .column(ClientColumn::Oid)
        .into_tuple::<Uuid>()
        .one(conn)
        .await?
        .ok_or_else(|| DbErr::RecordNotFound("login client".to_owned()))
}

fn decode_acr(
    value: Option<String>,
) -> Result<Option<AuthenticationContextClass>, LoginRepositoryError> {
    value
        .map(|value| value.parse())
        .transpose()
        .map_err(|_| LoginRepositoryError::InvalidStoredAcr)
}

fn to_domain(
    m: login::Model,
    client_oid: Uuid,
    client_authorization_oid: Uuid,
    session_oid: Option<SessionOid>,
    user_oid: Option<Uuid>,
) -> Result<Login, LoginRepositoryError> {
    let status = m
        .status
        .parse()
        .map_err(|_| LoginRepositoryError::InvalidStoredStatus)?;
    Ok(Login {
        oid: m.oid,
        client_oid,
        client_authorization_oid,
        session_oid,
        user_oid,
        submitted_identifier: m.submitted_identifier,
        status,
        failed_attempts: m.failed_attempts,
        created_at: DateTime::<Utc>::from(m.created_at),
        expires_at: DateTime::<Utc>::from(m.expires_at),
        acr: decode_acr(m.acr)?,
        requested_acr_values: serde_json::from_value(m.requested_acr_values)
            .map_err(|_| LoginRepositoryError::InvalidStoredAcr)?,
    })
}

pub struct LoginRepositoryImpl {
    db: DatabaseConnection,
}

impl LoginRepositoryImpl {
    pub fn new(db: DatabaseConnection) -> Self {
        Self { db }
    }

    /// Move a newly-created login to `identifier_verified`, binding the
    /// matched account (if any) and the identifier kept for presentation.
    async fn bind_identity(
        &self,
        login_oid: Uuid,
        user_oid: Option<Uuid>,
        submitted_identifier: Option<&str>,
    ) -> Result<Login, LoginRepositoryError> {
        let txn = self
            .db
            .begin()
            .await
            .map_err(|e| LoginRepositoryError::UpdateFailed(Box::new(e)))?;
        let user_id = match user_oid {
            Some(user_oid) => {
                shared::lock_user_credentials(&txn, user_oid.into())
                    .await
                    .map_err(|e| LoginRepositoryError::UpdateFailed(Box::new(e)))?;
                let user = UserEntity::find()
                    .filter(UserColumn::Oid.eq(user_oid))
                    .one(&txn)
                    .await
                    .map_err(|e| LoginRepositoryError::QueryFailed(Box::new(e)))?
                    .ok_or(LoginRepositoryError::UserNotFound)?;
                Some(user.id)
            }
            None => None,
        };

        let now = Utc::now();
        let model = LoginEntity::update_many()
            .col_expr(LoginColumn::UserId, Expr::value(user_id))
            .col_expr(
                LoginColumn::SubmittedIdentifier,
                Expr::value(submitted_identifier.map(str::to_owned)),
            )
            .col_expr(
                LoginColumn::Status,
                Expr::value(LoginStatus::IDENTIFIER_VERIFIED.as_str()),
            )
            .col_expr(
                LoginColumn::UpdatedAt,
                Expr::value(Some(now.fixed_offset())),
            )
            .filter(LoginColumn::Oid.eq(login_oid))
            .filter(LoginColumn::Status.eq(LoginStatus::CREATED.as_str()))
            .filter(LoginColumn::UserId.is_null())
            .exec_with_returning(&txn)
            .await
            .map_err(|e| LoginRepositoryError::UpdateFailed(Box::new(e)))?
            .into_iter()
            .next()
            .ok_or(LoginRepositoryError::LoginNotFound)?;

        let client_model = ClientEntity::find_by_id(model.client_id)
            .one(&txn)
            .await
            .map_err(|e| LoginRepositoryError::QueryFailed(Box::new(e)))?
            .ok_or(LoginRepositoryError::UserNotFound)?;

        let client_authorization_model =
            ClientAuthorizationEntity::find_by_id(model.client_authorization_id)
                .one(&txn)
                .await
                .map_err(|e| LoginRepositoryError::QueryFailed(Box::new(e)))?
                .ok_or(LoginRepositoryError::LoginNotFound)?;

        txn.commit()
            .await
            .map_err(|e| LoginRepositoryError::UpdateFailed(Box::new(e)))?;
        to_domain(
            model,
            client_model.oid,
            client_authorization_model.oid,
            None,
            user_oid,
        )
    }
}

#[async_trait]
impl LoginRepository for LoginRepositoryImpl {
    #[tracing::instrument(skip_all, name = "db.query", fields(db.system = "postgresql", db.operation = "find_by_oid"))]
    async fn find_by_oid(&self, oid: Uuid) -> Result<Option<Login>, LoginRepositoryError> {
        let Some(model) = LoginEntity::find()
            .filter(LoginColumn::Oid.eq(oid))
            .one(&self.db)
            .await
            .map_err(|e| LoginRepositoryError::QueryFailed(Box::new(e)))?
        else {
            return Ok(None);
        };

        let client_model = ClientEntity::find_by_id(model.client_id)
            .one(&self.db)
            .await
            .map_err(|e| LoginRepositoryError::QueryFailed(Box::new(e)))?
            .ok_or(LoginRepositoryError::UserNotFound)?;

        let client_authorization_model =
            ClientAuthorizationEntity::find_by_id(model.client_authorization_id)
                .one(&self.db)
                .await
                .map_err(|e| LoginRepositoryError::QueryFailed(Box::new(e)))?
                .ok_or(LoginRepositoryError::LoginNotFound)?;

        let user_oid = match model.user_id {
            Some(user_id) => UserEntity::find_by_id(user_id)
                .one(&self.db)
                .await
                .map_err(|e| LoginRepositoryError::QueryFailed(Box::new(e)))?
                .map(|user| user.oid),
            None => None,
        };

        let session_oid = match model.session_id {
            Some(session_id) => SessionEntity::find_by_id(session_id)
                .one(&self.db)
                .await
                .map_err(|e| LoginRepositoryError::QueryFailed(Box::new(e)))?
                .map(|session| SessionOid(session.oid)),
            None => None,
        };

        Ok(Some(to_domain(
            model,
            client_model.oid,
            client_authorization_model.oid,
            session_oid,
            user_oid,
        )?))
    }

    #[tracing::instrument(skip_all, name = "db.query", fields(db.system = "postgresql", db.operation = "create_pending"))]
    async fn create_pending(
        &self,
        client_oid: Uuid,
        client_authorization_oid: Uuid,
        requested_acr_values: &[AuthenticationContextClass],
    ) -> Result<Login, LoginRepositoryError> {
        let client = ClientEntity::find()
            .filter(ClientColumn::Oid.eq(client_oid))
            .one(&self.db)
            .await
            .map_err(|e| LoginRepositoryError::QueryFailed(Box::new(e)))?
            .ok_or(LoginRepositoryError::UserNotFound)?;

        let client_authorization_model = ClientAuthorizationEntity::find()
            .filter(ClientAuthorizationColumn::Oid.eq(client_authorization_oid))
            .one(&self.db)
            .await
            .map_err(|e| LoginRepositoryError::QueryFailed(Box::new(e)))?
            .ok_or(LoginRepositoryError::UserNotFound)?;

        let now = Utc::now();
        let expiry_duration =
            Duration::from_std(LOGIN_EXPIRY).unwrap_or_else(|_| Duration::minutes(5));
        let active = login::ActiveModel {
            oid: Set(Uuid::new_v4()),
            client_id: Set(client.id),
            client_authorization_id: Set(client_authorization_model.id),
            user_id: Set(None),
            status: Set(LoginStatus::CREATED.to_string()),
            failed_attempts: Set(0),
            requested_acr_values: Set(serde_json::json!(requested_acr_values)),
            created_at: Set(now.into()),
            expires_at: Set((now + expiry_duration).into()),
            ..Default::default()
        };
        let transaction = self
            .db
            .begin()
            .await
            .map_err(|e| LoginRepositoryError::CreateFailed(Box::new(e)))?;
        let model = active
            .insert(&transaction)
            .await
            .map_err(|e| LoginRepositoryError::CreateFailed(Box::new(e)))?;
        transaction
            .commit()
            .await
            .map_err(|e| LoginRepositoryError::CreateFailed(Box::new(e)))?;
        to_domain(model, client_oid, client_authorization_oid, None, None)
    }

    #[tracing::instrument(skip_all, name = "db.query", fields(db.system = "postgresql", db.operation = "bind_user"))]
    async fn bind_user(
        &self,
        login_oid: Uuid,
        user_oid: Uuid,
    ) -> Result<Login, LoginRepositoryError> {
        self.bind_identity(login_oid, Some(user_oid), None).await
    }

    #[tracing::instrument(skip_all, name = "db.query", fields(db.system = "postgresql", db.operation = "bind_concealed_identifier"))]
    async fn bind_concealed_identifier(
        &self,
        login_oid: Uuid,
        identifier: &str,
        user_oid: Option<Uuid>,
    ) -> Result<Login, LoginRepositoryError> {
        self.bind_identity(login_oid, user_oid, Some(identifier))
            .await
    }

    #[tracing::instrument(skip_all, name = "db.query", fields(db.system = "postgresql", db.operation = "update_status"))]
    async fn update_status(
        &self,
        login_oid: Uuid,
        status: LoginStatus,
        session_oid: Option<SessionOid>,
        acr: Option<AuthenticationContextClass>,
    ) -> Result<(), LoginRepositoryError> {
        let model = LoginEntity::find()
            .filter(LoginColumn::Oid.eq(login_oid))
            .one(&self.db)
            .await
            .map_err(|e| LoginRepositoryError::QueryFailed(Box::new(e)))?
            .ok_or(LoginRepositoryError::LoginNotFound)?;

        let current_status = model
            .status
            .parse::<LoginStatus>()
            .map_err(|_| LoginRepositoryError::InvalidStoredStatus)?;
        if !current_status.can_transition(status) {
            return Err(LoginRepositoryError::InvalidTransition);
        }

        let session_id = if let Some(s_oid) = session_oid {
            let user_id = model
                .user_id
                .ok_or(LoginRepositoryError::InvalidTransition)?;
            let now = Utc::now();
            let session = SessionEntity::find()
                .filter(SessionColumn::Oid.eq(Uuid::from(s_oid)))
                .filter(SessionColumn::UserId.eq(user_id))
                .filter(SessionColumn::Status.eq(SessionStatus::ACTIVE.as_str()))
                .filter(SessionColumn::RevokedAt.is_null())
                .filter(SessionColumn::ExpiresAt.gt(now))
                .one(&self.db)
                .await
                .map_err(|e| LoginRepositoryError::QueryFailed(Box::new(e)))?
                .ok_or(LoginRepositoryError::SessionNotFound)?;
            Some(session.id)
        } else {
            None
        };

        if status == LoginStatus::AUTHENTICATED && (session_id.is_none() || acr.is_none()) {
            return Err(LoginRepositoryError::InvalidTransition);
        }

        let transaction = self
            .db
            .begin()
            .await
            .map_err(|e| LoginRepositoryError::UpdateFailed(Box::new(e)))?;
        let previous_status = model.status;
        let mut update = LoginEntity::update_many()
            .col_expr(LoginColumn::Status, Expr::value(status.as_str()))
            .col_expr(
                LoginColumn::UpdatedAt,
                Expr::value(Some(Utc::now().fixed_offset())),
            )
            .filter(LoginColumn::Oid.eq(login_oid))
            .filter(LoginColumn::Status.eq(previous_status));
        if let Some(sid) = session_id {
            update = update.col_expr(LoginColumn::SessionId, Expr::value(Some(sid)));
        }
        if let Some(a) = acr {
            update = update.col_expr(LoginColumn::Acr, Expr::value(Some(a.to_string())));
        }
        let result = update
            .exec(&transaction)
            .await
            .map_err(|e| LoginRepositoryError::UpdateFailed(Box::new(e)))?;
        if result.rows_affected != 1 {
            return Err(LoginRepositoryError::InvalidTransition);
        }
        challenge::clear_for_binding(&transaction, ChallengeBinding::Login(login_oid))
            .await
            .map_err(|e| LoginRepositoryError::UpdateFailed(Box::new(e)))?;
        transaction
            .commit()
            .await
            .map_err(|e| LoginRepositoryError::UpdateFailed(Box::new(e)))?;
        Ok(())
    }

    #[tracing::instrument(skip_all, name = "db.query", fields(db.system = "postgresql", db.operation = "increment_failed_attempts"))]
    async fn increment_failed_attempts(
        &self,
        login_oid: Uuid,
        failure_reason: Option<LoginFailureReason>,
    ) -> Result<i32, LoginRepositoryError> {
        let now = Utc::now().fixed_offset();
        let mut update = LoginEntity::update_many()
            .col_expr(
                LoginColumn::FailedAttempts,
                Expr::col(LoginColumn::FailedAttempts).add(1),
            )
            .col_expr(LoginColumn::UpdatedAt, Expr::value(Some(now)))
            .filter(LoginColumn::Oid.eq(login_oid));

        if let Some(reason) = failure_reason {
            update = update.col_expr(
                LoginColumn::FailureReason,
                Expr::value(Option::<String>::Some(reason.as_str().to_owned())),
            );
        }

        let transaction = self
            .db
            .begin()
            .await
            .map_err(|e| LoginRepositoryError::IncrementFailedAttempts(Box::new(e)))?;
        let updated = update
            .exec_with_returning(&transaction)
            .await
            .map_err(|e| LoginRepositoryError::IncrementFailedAttempts(Box::new(e)))?
            .into_iter()
            .next()
            .ok_or(LoginRepositoryError::LoginNotFound)?;
        let (user_oid, client_oid) = login_parties(&transaction, &updated)
            .await
            .map_err(|e| LoginRepositoryError::IncrementFailedAttempts(Box::new(e)))?;
        let reason = match failure_reason {
            Some(LoginFailureReason::InvalidOtp) => AuditFailureReason::InvalidOtp,
            Some(LoginFailureReason::InvalidRecoveryCode) => {
                AuditFailureReason::InvalidRecoveryCode
            }
            Some(LoginFailureReason::InvalidCredential) | None => {
                AuditFailureReason::InvalidCredential
            }
        };
        audit::record(
            &transaction,
            AuditRecord::failure(AuditAction::SignIn, reason, user_oid)
                .actor(AuditActor::anonymous())
                .client(client_oid),
        )
        .await
        .map_err(|e| LoginRepositoryError::IncrementFailedAttempts(Box::new(e)))?;
        transaction
            .commit()
            .await
            .map_err(|e| LoginRepositoryError::IncrementFailedAttempts(Box::new(e)))?;
        Ok(updated.failed_attempts)
    }

    #[tracing::instrument(skip_all, name = "db.query", fields(db.system = "postgresql", db.operation = "reset_identity"))]
    async fn reset_identity(&self, login_oid: Uuid) -> Result<(), LoginRepositoryError> {
        let transaction = self
            .db
            .begin()
            .await
            .map_err(|e| LoginRepositoryError::UpdateFailed(Box::new(e)))?;
        let result = LoginEntity::update_many()
            .col_expr(
                LoginColumn::Status,
                Expr::value(LoginStatus::CREATED.as_str()),
            )
            .col_expr(LoginColumn::UserId, Expr::value(Option::<i64>::None))
            .col_expr(
                LoginColumn::SubmittedIdentifier,
                Expr::value(Option::<String>::None),
            )
            .col_expr(LoginColumn::SessionId, Expr::value(Option::<i64>::None))
            .col_expr(LoginColumn::Acr, Expr::value(Option::<String>::None))
            .col_expr(
                LoginColumn::FailureReason,
                Expr::value(Option::<String>::None),
            )
            .col_expr(LoginColumn::FailedAttempts, Expr::value(0))
            .col_expr(
                LoginColumn::UpdatedAt,
                Expr::value(Some(Utc::now().fixed_offset())),
            )
            .filter(LoginColumn::Oid.eq(login_oid))
            .filter(LoginColumn::Status.is_in([
                LoginStatus::IDENTIFIER_VERIFIED.as_str(),
                LoginStatus::MFA_REQUIRED.as_str(),
                LoginStatus::MFA_ENROLLMENT_REQUIRED.as_str(),
            ]))
            .exec(&transaction)
            .await
            .map_err(|e| LoginRepositoryError::UpdateFailed(Box::new(e)))?;

        if result.rows_affected != 1 {
            return Err(LoginRepositoryError::InvalidTransition);
        }
        challenge::clear_for_binding(&transaction, ChallengeBinding::Login(login_oid))
            .await
            .map_err(|e| LoginRepositoryError::UpdateFailed(Box::new(e)))?;
        transaction
            .commit()
            .await
            .map_err(|e| LoginRepositoryError::UpdateFailed(Box::new(e)))?;
        Ok(())
    }

    #[tracing::instrument(skip_all, name = "db.query", fields(db.system = "postgresql", db.operation = "bind_session"))]
    async fn bind_session(
        &self,
        login_oid: Uuid,
        session_oid: SessionOid,
    ) -> Result<(), LoginRepositoryError> {
        let transaction = self
            .db
            .begin()
            .await
            .map_err(|e| LoginRepositoryError::UpdateFailed(Box::new(e)))?;
        let session = SessionEntity::find()
            .filter(SessionColumn::Oid.eq(Uuid::from(session_oid)))
            .one(&transaction)
            .await
            .map_err(|e| LoginRepositoryError::QueryFailed(Box::new(e)))?
            .ok_or(LoginRepositoryError::SessionNotFound)?;

        let result = LoginEntity::update_many()
            .col_expr(LoginColumn::SessionId, Expr::value(Some(session.id)))
            .col_expr(
                LoginColumn::UpdatedAt,
                Expr::value(Some(Utc::now().fixed_offset())),
            )
            .filter(LoginColumn::Oid.eq(login_oid))
            .exec(&transaction)
            .await
            .map_err(|e| LoginRepositoryError::UpdateFailed(Box::new(e)))?;

        if result.rows_affected == 0 {
            return Err(LoginRepositoryError::LoginNotFound);
        }
        transaction
            .commit()
            .await
            .map_err(|e| LoginRepositoryError::UpdateFailed(Box::new(e)))?;

        Ok(())
    }

    #[tracing::instrument(skip_all, name = "db.query", fields(db.system = "postgresql", db.operation = "reset_failed_attempts"))]
    async fn reset_failed_attempts(&self, login_oid: Uuid) -> Result<(), LoginRepositoryError> {
        let now = Utc::now().fixed_offset();
        LoginEntity::update_many()
            .col_expr(LoginColumn::FailedAttempts, Expr::value(0))
            .col_expr(LoginColumn::UpdatedAt, Expr::value(Some(now)))
            .filter(LoginColumn::Oid.eq(login_oid))
            .filter(LoginColumn::FailedAttempts.ne(0_i32))
            .exec(&self.db)
            .await
            .map_err(|e| LoginRepositoryError::ResetFailedAttempts(Box::new(e)))?;
        Ok(())
    }

    #[tracing::instrument(skip_all, name = "db.query", fields(db.system = "postgresql", db.operation = "record_identification_failure"))]
    async fn record_identification_failure(
        &self,
        login_oid: Uuid,
        user_oid: Option<Uuid>,
        reason: AuditFailureReason,
    ) -> Result<(), LoginRepositoryError> {
        let client_id = LoginEntity::find()
            .select_only()
            .column(LoginColumn::ClientId)
            .filter(LoginColumn::Oid.eq(login_oid))
            .into_tuple::<i64>()
            .one(&self.db)
            .await
            .map_err(|e| LoginRepositoryError::QueryFailed(Box::new(e)))?
            .ok_or(LoginRepositoryError::LoginNotFound)?;
        let client_oid = login_client_oid(&self.db, client_id)
            .await
            .map_err(|e| LoginRepositoryError::QueryFailed(Box::new(e)))?;
        audit::record_standalone(
            &self.db,
            AuditRecord::failure(AuditAction::SignIn, reason, user_oid)
                .actor(AuditActor::anonymous())
                .client(client_oid),
        )
        .await
        .map_err(|e| LoginRepositoryError::UpdateFailed(Box::new(e)))
    }
}
