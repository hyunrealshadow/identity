//! Serialize login completion with account-wide password replacement.
use super::session::{SessionRepositoryImpl, session_to_domain};
use super::shared::lock_user_credentials;
use super::shared::{encode_nonnullable_expiry, lock_session};
use crate::database::entity::{
    session, session::Entity as SessionEntity, user, user::Entity as UserEntity,
};
use chrono::Utc;
use identity_domain::auth::{
    SessionOid,
    challenge::ChallengeBinding,
    model::Session,
    repository::{CreateSessionInput, SessionRepositoryError},
};
use sea_orm::{
    ActiveModelTrait, ColumnTrait, EntityTrait, QueryFilter, QueryOrder, Set, TransactionTrait,
    sea_query::Expr,
};
use sea_orm::{ConnectionTrait, DatabaseTransaction, DbBackend, DbErr, QuerySelect, Statement};
use serde_json::json;
use uuid::Uuid;

pub(super) async fn lock_account_sessions(
    txn: &DatabaseTransaction,
    user_id: i64,
) -> Result<Vec<session::Model>, DbErr> {
    let sessions = SessionEntity::find()
        .filter(session::Column::UserId.eq(user_id))
        .order_by_asc(session::Column::Oid)
        .all(txn)
        .await?;
    for session in &sessions {
        lock_session(txn, SessionOid(session.oid)).await?;
    }
    // Re-read after the locks: an independent logout may have committed while
    // we waited, including revocation of the session the caller wants to keep.
    SessionEntity::find()
        .filter(session::Column::UserId.eq(user_id))
        .order_by_asc(session::Column::Oid)
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
        let txn = self.db.begin().await.map_err(fail)?;
        lock_user_credentials(&txn, input.user_oid.into())
            .await
            .map_err(fail)?;
        if let Some(oid) = existing {
            lock_session(&txn, oid).await.map_err(fail)?;
        }
        let login = super::super::entity::login::Entity::find()
            .filter(super::super::entity::login::Column::Oid.eq(login_oid))
            .lock_exclusive()
            .one(&txn)
            .await
            .map_err(fail)?
            .ok_or(SessionRepositoryError::SessionNotFound)?;
        let owner = UserEntity::find()
            .filter(user::Column::Oid.eq(input.user_oid))
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
                    .filter(session::Column::Oid.eq(oid.0))
                    .filter(session::Column::Id.eq(bound))
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
                    session::Column::ExpiresAt,
                    Expr::value(encode_nonnullable_expiry(input.expires_at)),
                )
                .col_expr(session::Column::AuthenticatedAt, Expr::value(Some(now)))
                .col_expr(session::Column::LastActiveAt, Expr::value(now))
                .col_expr(session::Column::UpdatedAt, Expr::value(Some(now)))
                .col_expr(session::Column::Acr, Expr::value(input.acr))
                .col_expr(
                    session::Column::AcrExpiresAt,
                    Expr::value(input.acr_expires_at.map(|v| v.fixed_offset())),
                )
                .col_expr(session::Column::Amr, Expr::value(json!(input.amr)))
                .filter(session::Column::Oid.eq(oid.0))
                .filter(session::Column::UserId.eq(owner.id))
                .filter(session::Column::Status.eq("active"))
                .filter(session::Column::RevokedAt.is_null())
                .filter(session::Column::ExpiresAt.gt(now))
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
        super::challenge::clear_for_binding(&txn, ChallengeBinding::Login(login_oid))
            .await
            .map_err(fail)?;
        txn.commit().await.map_err(fail)?;
        session_to_domain(model, input.user_oid)
    }
}
