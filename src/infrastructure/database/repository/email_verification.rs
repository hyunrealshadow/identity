//! Persistence of outstanding email verifications. Admission and
//! confirmation each run in one transaction that locks the account row, so
//! concurrent requests, links, and address changes are serialized.

use async_trait::async_trait;
use chrono::{DateTime, Duration, Utc};
use identity_domain::{
    audit::{AuditAction, AuditActor, AuditRecord},
    user::{
        UserOid,
        email_verification::{
            EMAIL_VERIFICATION_RESEND_INTERVAL, EMAIL_VERIFICATION_SEND_WINDOW,
            EMAIL_VERIFICATION_TTL, EmailVerification, EmailVerificationAdmission,
            EmailVerificationOutcome, EmailVerificationRepository,
            EmailVerificationRepositoryError, EmailVerificationRequest,
            MAX_EMAIL_VERIFICATION_SENDS,
        },
    },
};
use sea_orm::{
    ActiveModelTrait, ColumnTrait, ConnectionTrait, DatabaseConnection, DbErr, EntityTrait,
    QueryFilter, QuerySelect, Set, TransactionTrait,
};
use uuid::Uuid;

use super::{authorization_lifecycle::renew_user_version_in_txn, user::user_attribute_changes};
use crate::database::{
    audit,
    entity::{
        email_verification::{self, Column as VerificationColumn, Entity as VerificationEntity},
        user::{self, Column as UserColumn, Entity as UserEntity},
    },
};

pub struct EmailVerificationRepositoryImpl {
    db: DatabaseConnection,
}

impl EmailVerificationRepositoryImpl {
    #[must_use]
    pub const fn new(db: DatabaseConnection) -> Self {
        Self { db }
    }
}

fn query_failed(
    error: impl std::error::Error + Send + Sync + 'static,
) -> EmailVerificationRepositoryError {
    EmailVerificationRepositoryError::QueryFailed(Box::new(error))
}

fn duration(value: std::time::Duration) -> Duration {
    Duration::from_std(value).unwrap_or(Duration::MAX)
}

fn to_domain(model: &email_verification::Model, user_oid: Uuid) -> EmailVerification {
    EmailVerification {
        oid: model.oid,
        user_oid: user_oid.into(),
        email: model.email.clone(),
        email_normalized: model.email_normalized.clone(),
        changes_email: model.email_normalized != model.current_email_normalized,
        sent_at: model.sent_at.into(),
        expires_at: model.expires_at.into(),
    }
}

/// Whether a stored verification can still be followed for `account`.
fn usable(model: &email_verification::Model, account: &user::Model, now: DateTime<Utc>) -> bool {
    DateTime::<Utc>::from(model.expires_at) > now
        && model.current_email_normalized == account.email_normalized
        && (model.email_normalized != account.email_normalized || !account.email_verified)
}

async fn email_taken(
    connection: &impl ConnectionTrait,
    normalized: &str,
    except_id: i64,
) -> Result<bool, DbErr> {
    Ok(UserEntity::find()
        .filter(UserColumn::EmailNormalized.eq(normalized))
        .filter(UserColumn::Id.ne(except_id))
        .one(connection)
        .await?
        .is_some())
}

/// Remove the account's outstanding verification inside a transaction that
/// changes its address.
pub(crate) async fn discard_for_user_in_txn(
    connection: &impl ConnectionTrait,
    user_id: i64,
) -> Result<(), DbErr> {
    VerificationEntity::delete_many()
        .filter(VerificationColumn::UserId.eq(user_id))
        .exec(connection)
        .await?;
    Ok(())
}

#[async_trait]
impl EmailVerificationRepository for EmailVerificationRepositoryImpl {
    #[tracing::instrument(skip_all, name = "db.query", fields(db.system = "postgresql", db.operation = "admit_email_verification"))]
    async fn admit(
        &self,
        request: EmailVerificationRequest,
    ) -> Result<EmailVerificationAdmission, EmailVerificationRepositoryError> {
        let txn = self.db.begin().await.map_err(query_failed)?;
        let Some(account) = UserEntity::find()
            .filter(UserColumn::Oid.eq(Uuid::from(request.user_oid)))
            .lock_exclusive()
            .one(&txn)
            .await
            .map_err(query_failed)?
        else {
            return Ok(EmailVerificationAdmission::UserNotFound);
        };
        let verifies_current = request.email_normalized == account.email_normalized;
        if verifies_current && account.email_verified {
            return Ok(EmailVerificationAdmission::AlreadyVerified);
        }
        if !verifies_current
            && email_taken(&txn, &request.email_normalized, account.id)
                .await
                .map_err(query_failed)?
        {
            return Ok(EmailVerificationAdmission::EmailExists);
        }

        let now = request.now;
        let existing = VerificationEntity::find()
            .filter(VerificationColumn::UserId.eq(account.id))
            .one(&txn)
            .await
            .map_err(query_failed)?;
        // The interval and limit apply to the account, whichever address
        // each email went to.
        let (window_started_at, send_count) = match &existing {
            Some(row) => {
                let available_at = DateTime::<Utc>::from(row.sent_at)
                    + duration(EMAIL_VERIFICATION_RESEND_INTERVAL);
                if now < available_at {
                    return Ok(EmailVerificationAdmission::TooSoon { available_at });
                }
                let window_started_at = DateTime::<Utc>::from(row.window_started_at);
                if now < window_started_at + duration(EMAIL_VERIFICATION_SEND_WINDOW) {
                    if row.send_count >= MAX_EMAIL_VERIFICATION_SENDS {
                        return Ok(EmailVerificationAdmission::LimitReached);
                    }
                    (window_started_at, row.send_count + 1)
                } else {
                    (now, 1)
                }
            }
            None => (now, 1),
        };

        let expires_at = now + duration(EMAIL_VERIFICATION_TTL);
        let model = match existing {
            Some(row) => {
                let mut active: email_verification::ActiveModel = row.into();
                active.oid = Set(Uuid::new_v4());
                active.email = Set(request.email.clone());
                active.email_normalized = Set(request.email_normalized.clone());
                active.current_email_normalized = Set(account.email_normalized.clone());
                active.token_digest = Set(request.token_digest.clone());
                active.send_count = Set(send_count);
                active.window_started_at = Set(window_started_at.into());
                active.sent_at = Set(now.into());
                active.expires_at = Set(expires_at.into());
                active.update(&txn).await.map_err(query_failed)?
            }
            None => email_verification::ActiveModel {
                oid: Set(Uuid::new_v4()),
                user_id: Set(account.id),
                email: Set(request.email.clone()),
                email_normalized: Set(request.email_normalized.clone()),
                current_email_normalized: Set(account.email_normalized.clone()),
                token_digest: Set(request.token_digest.clone()),
                send_count: Set(send_count),
                window_started_at: Set(window_started_at.into()),
                sent_at: Set(now.into()),
                expires_at: Set(expires_at.into()),
                created_at: Set(now.into()),
                ..Default::default()
            }
            .insert(&txn)
            .await
            .map_err(query_failed)?,
        };
        txn.commit().await.map_err(query_failed)?;
        Ok(EmailVerificationAdmission::Admitted {
            verification: to_domain(&model, account.oid),
            resend_available_at: now + duration(EMAIL_VERIFICATION_RESEND_INTERVAL),
        })
    }

    #[tracing::instrument(skip_all, name = "db.query", fields(db.system = "postgresql", db.operation = "pending_email_verification"))]
    async fn pending(
        &self,
        user_oid: UserOid,
        now: DateTime<Utc>,
    ) -> Result<Option<EmailVerification>, EmailVerificationRepositoryError> {
        let Some((row, Some(account))) = VerificationEntity::find()
            .find_also_related(UserEntity)
            .filter(UserColumn::Oid.eq(Uuid::from(user_oid)))
            .one(&self.db)
            .await
            .map_err(query_failed)?
        else {
            return Ok(None);
        };
        Ok(usable(&row, &account, now).then(|| to_domain(&row, account.oid)))
    }

    #[tracing::instrument(skip_all, name = "db.query", fields(db.system = "postgresql", db.operation = "cancel_email_verification"))]
    async fn cancel(&self, user_oid: UserOid) -> Result<bool, EmailVerificationRepositoryError> {
        let Some(account) = UserEntity::find()
            .filter(UserColumn::Oid.eq(Uuid::from(user_oid)))
            .one(&self.db)
            .await
            .map_err(query_failed)?
        else {
            return Ok(false);
        };
        let result = VerificationEntity::delete_many()
            .filter(VerificationColumn::UserId.eq(account.id))
            .exec(&self.db)
            .await
            .map_err(query_failed)?;
        Ok(result.rows_affected > 0)
    }

    #[tracing::instrument(skip_all, name = "db.query", fields(db.system = "postgresql", db.operation = "confirm_email_verification"))]
    async fn confirm(
        &self,
        token_digest: &str,
        now: DateTime<Utc>,
    ) -> Result<EmailVerificationOutcome, EmailVerificationRepositoryError> {
        let txn = self.db.begin().await.map_err(query_failed)?;
        let Some(row) = VerificationEntity::find()
            .filter(VerificationColumn::TokenDigest.eq(token_digest))
            .one(&txn)
            .await
            .map_err(query_failed)?
        else {
            return Ok(EmailVerificationOutcome::Invalid);
        };
        let Some(account) = UserEntity::find_by_id(row.user_id)
            .lock_exclusive()
            .one(&txn)
            .await
            .map_err(query_failed)?
        else {
            return Ok(EmailVerificationOutcome::Invalid);
        };
        // Re-read under the account lock: a concurrent confirmation or new
        // request may have replaced or consumed the row.
        let Some(row) = VerificationEntity::find_by_id(row.id)
            .filter(VerificationColumn::TokenDigest.eq(token_digest))
            .one(&txn)
            .await
            .map_err(query_failed)?
        else {
            return Ok(EmailVerificationOutcome::Invalid);
        };
        if !account.enabled || !usable(&row, &account, now) {
            return Ok(EmailVerificationOutcome::Invalid);
        }
        let changed = row.email_normalized != account.email_normalized;
        if changed
            && email_taken(&txn, &row.email_normalized, account.id)
                .await
                .map_err(query_failed)?
        {
            return Ok(EmailVerificationOutcome::EmailExists);
        }

        let before = account.clone();
        let mut active: user::ActiveModel = account.clone().into();
        if changed {
            active.email = Set(row.email.clone());
            active.email_normalized = Set(row.email_normalized.clone());
        }
        active.email_verified = Set(true);
        active.updated_at = Set(Some(now.into()));
        let mut model = active.update(&txn).await.map_err(query_failed)?;
        model.version = renew_user_version_in_txn(&txn, model.id)
            .await
            .map_err(query_failed)?
            .as_uuid();
        discard_for_user_in_txn(&txn, model.id)
            .await
            .map_err(query_failed)?;
        audit::record(
            &txn,
            AuditRecord::success(AuditAction::AccountEmailVerify, model.oid)
                .default_actor(AuditActor::user(model.oid))
                .with_changes(|changes| user_attribute_changes(changes, &before, &model)),
        )
        .await
        .map_err(query_failed)?;
        txn.commit().await.map_err(query_failed)?;
        Ok(EmailVerificationOutcome::Verified {
            user_oid: model.oid.into(),
            email: model.email,
            changed,
        })
    }
}
