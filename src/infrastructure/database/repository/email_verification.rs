//! Persistence of outstanding email verifications. Admission and
//! confirmation each run in one transaction that locks the account row, so
//! concurrent requests, links, and address changes are serialized.

use async_trait::async_trait;
use chrono::{DateTime, Duration, Utc};
use identity_domain::{
    audit::{AuditAction, AuditActor, AuditRecord},
    auth::challenge::{ChallengePurpose, DeliveryDecision},
    user::{
        UserOid,
        email_verification::{
            EMAIL_VERIFICATION_DELIVERY, EMAIL_VERIFICATION_TTL, EmailVerification,
            EmailVerificationAdmission, EmailVerificationOutcome, EmailVerificationRepository,
            EmailVerificationRepositoryError, EmailVerificationRequest,
        },
    },
};
use sea_orm::{
    ActiveModelTrait, ColumnTrait, ConnectionTrait, DatabaseConnection, DbErr, EntityTrait,
    QueryFilter, QuerySelect, Set, TransactionTrait,
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::{
    account_challenge::{self, AccountChallenge, AccountChallengeIssue},
    authorization_lifecycle::renew_user_version_in_txn,
    user::user_attribute_changes,
};
use crate::{
    database::{
        audit,
        entity::user::{self, Column as UserColumn, Entity as UserEntity},
    },
    email::EmailQueue,
};

const PURPOSE: ChallengePurpose = ChallengePurpose::EmailVerification;

/// What an email verification challenge keeps besides its link digest.
#[derive(Serialize, Deserialize)]
struct VerificationState {
    /// The address being verified, as entered, and its normalized form.
    email: String,
    email_normalized: String,
    /// The account's address when the verification was requested; any
    /// later change voids the link.
    current_email_normalized: String,
}

type Verification = AccountChallenge<VerificationState>;

pub struct EmailVerificationRepositoryImpl {
    db: DatabaseConnection,
    email_queue: EmailQueue,
}

impl EmailVerificationRepositoryImpl {
    #[must_use]
    pub const fn new(db: DatabaseConnection, email_queue: EmailQueue) -> Self {
        Self { db, email_queue }
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

fn to_domain(row: &Verification, user_oid: Uuid) -> EmailVerification {
    EmailVerification {
        oid: row.model.oid,
        user_oid: user_oid.into(),
        email: row.state.email.clone(),
        email_normalized: row.state.email_normalized.clone(),
        changes_email: row.state.email_normalized != row.state.current_email_normalized,
        sent_at: row.sent_at().unwrap_or_else(|| row.model.created_at.into()),
        expires_at: row.expires_at(),
    }
}

/// Whether a stored verification can still be followed for `account`.
fn usable(row: &Verification, account: &user::Model, now: DateTime<Utc>) -> bool {
    row.expires_at() > now
        && row.state.current_email_normalized == account.email_normalized
        && (row.state.email_normalized != account.email_normalized || !account.email_verified)
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
    account_challenge::discard(connection, user_id, PURPOSE).await?;
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
        let existing: Option<Verification> = account_challenge::find(&txn, account.id, PURPOSE)
            .await
            .map_err(query_failed)?;
        // The interval and limit apply to the account, whichever address
        // each email went to.
        let counter = match EMAIL_VERIFICATION_DELIVERY.admit(
            existing.as_ref().and_then(Verification::counter).as_ref(),
            now,
        ) {
            DeliveryDecision::Admit(counter) => counter,
            DeliveryDecision::TooSoon { available_at } => {
                return Ok(EmailVerificationAdmission::TooSoon { available_at });
            }
            DeliveryDecision::LimitReached => return Ok(EmailVerificationAdmission::LimitReached),
        };
        let state = VerificationState {
            email: request.email.clone(),
            email_normalized: request.email_normalized.clone(),
            current_email_normalized: account.email_normalized.clone(),
        };
        let model = account_challenge::issue(
            &txn,
            AccountChallengeIssue {
                user_id: account.id,
                purpose: PURPOSE,
                token_digest: &request.token_digest,
                counter,
                state: &state,
                expires_at: now + duration(EMAIL_VERIFICATION_TTL),
            },
        )
        .await
        .map_err(query_failed)?;
        let model = Verification { model, state };
        self.email_queue
            .enqueue(&txn, &request.message)
            .await
            .map_err(query_failed)?;
        txn.commit().await.map_err(query_failed)?;
        Ok(EmailVerificationAdmission::Admitted {
            verification: to_domain(&model, account.oid),
            resend_available_at: EMAIL_VERIFICATION_DELIVERY.resend_available_at(&counter),
        })
    }

    #[tracing::instrument(skip_all, name = "db.query", fields(db.system = "postgresql", db.operation = "pending_email_verification"))]
    async fn pending(
        &self,
        user_oid: UserOid,
        now: DateTime<Utc>,
    ) -> Result<Option<EmailVerification>, EmailVerificationRepositoryError> {
        let Some(account) = UserEntity::find()
            .filter(UserColumn::Oid.eq(Uuid::from(user_oid)))
            .one(&self.db)
            .await
            .map_err(query_failed)?
        else {
            return Ok(None);
        };
        let Some(row) = account_challenge::find::<VerificationState>(&self.db, account.id, PURPOSE)
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
        account_challenge::discard(&self.db, account.id, PURPOSE)
            .await
            .map_err(query_failed)
    }

    #[tracing::instrument(skip_all, name = "db.query", fields(db.system = "postgresql", db.operation = "confirm_email_verification"))]
    async fn confirm(
        &self,
        token_digest: &str,
        now: DateTime<Utc>,
    ) -> Result<EmailVerificationOutcome, EmailVerificationRepositoryError> {
        let txn = self.db.begin().await.map_err(query_failed)?;
        let Some(row) =
            account_challenge::find_by_digest::<VerificationState>(&txn, token_digest, PURPOSE)
                .await
                .map_err(query_failed)?
        else {
            return Ok(EmailVerificationOutcome::Invalid);
        };
        let Some(user_id) = row.model.user_id else {
            return Ok(EmailVerificationOutcome::Invalid);
        };
        let Some(account) = UserEntity::find_by_id(user_id)
            .lock_exclusive()
            .one(&txn)
            .await
            .map_err(query_failed)?
        else {
            return Ok(EmailVerificationOutcome::Invalid);
        };
        // Re-read under the account lock: a concurrent confirmation or new
        // request may have replaced or consumed the row.
        let Some(row) =
            account_challenge::find_by_digest::<VerificationState>(&txn, token_digest, PURPOSE)
                .await
                .map_err(query_failed)?
                .filter(|current| current.model.id == row.model.id)
        else {
            return Ok(EmailVerificationOutcome::Invalid);
        };
        if !account.enabled || !usable(&row, &account, now) {
            return Ok(EmailVerificationOutcome::Invalid);
        }
        let changed = row.state.email_normalized != account.email_normalized;
        if changed
            && email_taken(&txn, &row.state.email_normalized, account.id)
                .await
                .map_err(query_failed)?
        {
            return Ok(EmailVerificationOutcome::EmailExists);
        }

        let before = account.clone();
        let mut active: user::ActiveModel = account.clone().into();
        if changed {
            active.email = Set(row.state.email.clone());
            active.email_normalized = Set(row.state.email_normalized.clone());
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
