//! Serialize login completion with account-wide password replacement.
use super::{
    super::entity::login::{Column as LoginColumn, Entity as LoginEntity},
    challenge,
    session::{SessionRepositoryImpl, session_to_domain},
    shared::{encode_nonnullable_expiry, lock_session, lock_user_credentials},
};
use crate::database::{
    audit,
    entity::{
        session,
        session::{Column as SessionColumn, Entity as SessionEntity},
        user::{Column as UserColumn, Entity as UserEntity},
    },
};
use chrono::Utc;
use identity_domain::auth::{
    SessionOid,
    challenge::ChallengeBinding,
    model::Session,
    repository::{CreateSessionInput, SessionRepositoryError},
};
use sea_orm::{
    ActiveModelTrait, ColumnTrait, ConnectionTrait, DatabaseTransaction, DbBackend, DbErr,
    EntityTrait, QueryFilter, QueryOrder, QuerySelect, Set, Statement, sea_query::Expr,
};
use serde_json::json;
use uuid::Uuid;

pub(super) async fn lock_account_sessions(
    txn: &DatabaseTransaction,
    user_id: i64,
) -> Result<Vec<session::Model>, DbErr> {
    let sessions = SessionEntity::find()
        .filter(SessionColumn::UserId.eq(user_id))
        .order_by_asc(SessionColumn::Oid)
        .all(txn)
        .await?;
    for session in &sessions {
        lock_session(txn, SessionOid(session.oid)).await?;
    }
    // Re-read after the locks: an independent logout may have committed while
    // we waited, including revocation of the session the caller wants to keep.
    SessionEntity::find()
        .filter(SessionColumn::UserId.eq(user_id))
        .order_by_asc(SessionColumn::Oid)
        .all(txn)
        .await
}

impl SessionRepositoryImpl {
    pub(super) async fn complete_login(
        &self,
        login_oid: Uuid,
        existing: Option<SessionOid>,
        input: CreateSessionInput,
    ) -> Result<Session, SessionRepositoryError> {
        let fail = |e| SessionRepositoryError::CreateFailed(Box::new(e));
        let txn = audit::begin(&self.db, "session.complete_login")
            .await
            .map_err(fail)?;
        lock_user_credentials(&txn, input.user_oid.into())
            .await
            .map_err(fail)?;
        if let Some(oid) = existing {
            lock_session(&txn, oid).await.map_err(fail)?;
        }
        let login = LoginEntity::find()
            .filter(LoginColumn::Oid.eq(login_oid))
            .lock_exclusive()
            .one(&txn)
            .await
            .map_err(fail)?
            .ok_or(SessionRepositoryError::SessionNotFound)?;
        let owner = UserEntity::find()
            .filter(UserColumn::Oid.eq(input.user_oid))
            .one(&txn)
            .await
            .map_err(fail)?
            .ok_or(SessionRepositoryError::UserNotFound)?;
        if login.user_id != Some(owner.id)
            || !owner.enabled
            || owner.locked
            || login.expires_at <= Utc::now().fixed_offset()
            || !matches!(
                login.status.as_str(),
                "identifier_verified" | "mfa_required"
            )
        {
            return Err(SessionRepositoryError::SessionNotFound);
        }
        if let Some(bound) = login.session_id {
            let matches = match existing {
                Some(oid) => SessionEntity::find()
                    .filter(SessionColumn::Oid.eq(oid.0))
                    .filter(SessionColumn::Id.eq(bound))
                    .one(&txn)
                    .await
                    .map_err(fail)?
                    .is_some(),
                None => false,
            };
            if !matches {
                return Err(SessionRepositoryError::SessionNotFound);
            }
        }
        let now = Utc::now().fixed_offset();
        let model = if let Some(oid) = existing {
            SessionEntity::update_many()
                .col_expr(
                    SessionColumn::ExpiresAt,
                    Expr::value(encode_nonnullable_expiry(input.expires_at)),
                )
                .col_expr(SessionColumn::AuthenticatedAt, Expr::value(Some(now)))
                .col_expr(SessionColumn::LastActiveAt, Expr::value(now))
                .col_expr(SessionColumn::UpdatedAt, Expr::value(Some(now)))
                .col_expr(SessionColumn::Acr, Expr::value(input.acr))
                .col_expr(
                    SessionColumn::AcrExpiresAt,
                    Expr::value(input.acr_expires_at.map(|v| v.fixed_offset())),
                )
                .col_expr(SessionColumn::Amr, Expr::value(json!(input.amr)))
                .filter(SessionColumn::Oid.eq(oid.0))
                .filter(SessionColumn::UserId.eq(owner.id))
                .filter(SessionColumn::Status.eq("active"))
                .filter(SessionColumn::RevokedAt.is_null())
                .filter(SessionColumn::ExpiresAt.gt(now))
                .exec_with_returning(&txn)
                .await
                .map_err(fail)?
                .into_iter()
                .next()
                .ok_or(SessionRepositoryError::SessionNotFound)?
        } else {
            session::ActiveModel {
                oid: Set(Uuid::new_v4()),
                user_id: Set(owner.id),
                status: Set("active".into()),
                device_name: Set(input.device_name),
                device_type: Set(input.device_type),
                os_name: Set(input.os_name),
                os_version: Set(input.os_version),
                browser_name: Set(input.browser_name),
                browser_version: Set(input.browser_version),
                user_agent: Set(input.user_agent),
                ip_address: Set(input.ip_address),
                last_active_at: Set(now),
                authenticated_at: Set(Some(now)),
                expires_at: Set(encode_nonnullable_expiry(input.expires_at)),
                created_at: Set(now),
                updated_at: Set(None),
                acr: Set(input.acr),
                acr_expires_at: Set(input.acr_expires_at.map(Into::into)),
                amr: Set(json!(input.amr)),
                ..Default::default()
            }
            .insert(&txn)
            .await
            .map_err(fail)?
        };
        txn.execute_raw(Statement::from_sql_and_values(DbBackend::Postgres,
            "UPDATE login SET status = 'authenticated', session_id = $2, acr = $3, updated_at = now() WHERE oid = $1",
            [login_oid.into(), model.id.into(), model.acr.clone().into()])).await.map_err(fail)?;
        audit::record(&txn, "session.complete_login", "session", model.oid)
            .await
            .map_err(fail)?;
        challenge::clear_for_binding(&txn, ChallengeBinding::Login(login_oid))
            .await
            .map_err(fail)?;
        txn.commit().await.map_err(fail)?;
        session_to_domain(model, input.user_oid)
    }
}
