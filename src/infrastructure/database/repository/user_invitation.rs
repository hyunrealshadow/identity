//! Persistence of outstanding invitations. Accepting one runs in a single
//! transaction that locks the account's credentials and row, so it cannot
//! race an administrator setting a password, changing the address, or
//! sending a new link.

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use identity_application::{
    error::AppError,
    user::{
        Password,
        invitation::{
            InvitationAcceptance, InvitationIssue, UserInvitationRepository, UserInvitationStatus,
        },
    },
};
use identity_domain::{
    audit::{AuditAction, AuditActor, AuditField, AuditRecord},
    auth::challenge::{ChallengePurpose, DeliveryDecision, DeliveryPolicy},
    user::{User, UserOid},
};
use sea_orm::{
    ActiveModelTrait, ColumnTrait, ConnectionTrait, DatabaseConnection, DbBackend, DbErr,
    EntityTrait, QueryFilter, QuerySelect, Set, Statement, TransactionTrait,
};
use serde::{Deserialize, Serialize};
use serde_json::to_value;
use uuid::Uuid;

use super::{
    account_challenge::{self, AccountChallenge, AccountChallengeIssue},
    authorization_lifecycle::renew_user_version_in_txn,
    email_verification::discard_for_user_in_txn,
    shared::lock_user_credentials,
    user::to_domain,
};
use crate::{
    database::{
        audit,
        entity::{
            user::{self, Column as UserColumn, Entity as UserEntity},
            user_credential,
        },
    },
    email::EmailQueue,
};

const PURPOSE: ChallengePurpose = ChallengePurpose::Invitation;

/// What an invitation challenge keeps besides its link digest.
#[derive(Serialize, Deserialize)]
struct InvitationState {
    /// The account's address when the invitation was sent; a later change
    /// of the address voids the link.
    email_normalized: String,
}

type Invitation = AccountChallenge<InvitationState>;

pub struct UserInvitationRepositoryImpl {
    db: DatabaseConnection,
}

impl UserInvitationRepositoryImpl {
    #[must_use]
    pub fn new(db: DatabaseConnection) -> Self {
        Self { db }
    }
}

fn internal(error: impl std::error::Error + Send + Sync + 'static) -> AppError {
    AppError::internal(error)
}

/// Whether the account has a usable password.
pub(super) async fn has_password<C: ConnectionTrait>(db: &C, user_id: i64) -> Result<bool, DbErr> {
    Ok(db
        .query_one_raw(Statement::from_sql_and_values(
            DbBackend::Postgres,
            "SELECT 1 AS present FROM user_credential WHERE user_id = $1 AND type = 'password' \
             AND (expires_at IS NULL OR expires_at > now()) LIMIT 1",
            [user_id.into()],
        ))
        .await?
        .is_some())
}

/// What became of a new invitation link.
pub(super) enum InvitationIssueOutcome {
    /// Stored, and its email queued.
    Issued,
    /// Another email is not admitted before this time.
    TooSoon(DateTime<Utc>),
    /// The account no longer has the address the email was written for.
    AddressChanged,
}

/// Store `invitation` as the account's only one and queue its email, inside
/// the transaction that holds the account row lock with the account's
/// current normalized address `email_normalized`.
pub(super) async fn issue_in_txn<C: ConnectionTrait>(
    txn: &C,
    email_queue: &EmailQueue,
    user_id: i64,
    email_normalized: &str,
    invitation: &InvitationIssue,
    delivery: DeliveryPolicy,
) -> Result<InvitationIssueOutcome, DbErr> {
    if invitation.recipient_normalized != email_normalized {
        return Ok(InvitationIssueOutcome::AddressChanged);
    }
    let previous: Option<Invitation> = account_challenge::find(txn, user_id, PURPOSE).await?;
    let previous_counter = previous.as_ref().and_then(Invitation::counter);
    let counter = match delivery.admit(previous_counter.as_ref(), invitation.sent_at) {
        DeliveryDecision::Admit(counter) => counter,
        DeliveryDecision::TooSoon { available_at } => {
            return Ok(InvitationIssueOutcome::TooSoon(available_at));
        }
        // Only with a policy that limits sends; the earliest is the end of
        // the current window.
        DeliveryDecision::LimitReached => {
            let window_end = previous_counter
                .zip(delivery.window)
                .and_then(|(counter, window)| {
                    chrono::Duration::from_std(window)
                        .ok()
                        .and_then(|window| counter.window_started_at.checked_add_signed(window))
                })
                .unwrap_or(DateTime::<Utc>::MAX_UTC);
            return Ok(InvitationIssueOutcome::TooSoon(window_end));
        }
    };
    account_challenge::issue(
        txn,
        AccountChallengeIssue {
            user_id,
            purpose: PURPOSE,
            token_digest: &invitation.token_digest,
            counter,
            state: &InvitationState {
                email_normalized: email_normalized.to_owned(),
            },
            expires_at: invitation.expires_at,
        },
    )
    .await?;
    email_queue.enqueue(txn, &invitation.email).await?;
    Ok(InvitationIssueOutcome::Issued)
}

/// Remove the account's outstanding invitation, if any.
pub(super) async fn discard_invitation_in_txn<C: ConnectionTrait>(
    txn: &C,
    user_id: i64,
) -> Result<(), DbErr> {
    account_challenge::discard(txn, user_id, PURPOSE).await?;
    Ok(())
}

#[async_trait]
impl UserInvitationRepository for UserInvitationRepositoryImpl {
    #[tracing::instrument(skip_all, name = "db.query", fields(db.system = "postgresql", db.operation = "user_invitation.find_for_user"))]
    async fn find_for_user(
        &self,
        user_oid: UserOid,
    ) -> Result<Option<UserInvitationStatus>, AppError> {
        // An invitation sent to an earlier address, or to an account that
        // has since got a password, no longer applies.
        let Some(account) = UserEntity::find()
            .filter(UserColumn::Oid.eq(Uuid::from(user_oid)))
            .one(&self.db)
            .await
            .map_err(internal)?
        else {
            return Ok(None);
        };
        let Some(invitation) =
            account_challenge::find::<InvitationState>(&self.db, account.id, PURPOSE)
                .await
                .map_err(internal)?
                .filter(|invitation| invitation.state.email_normalized == account.email_normalized)
        else {
            return Ok(None);
        };
        if has_password(&self.db, account.id).await.map_err(internal)? {
            return Ok(None);
        }
        Ok(Some(UserInvitationStatus {
            sent_at: invitation
                .sent_at()
                .unwrap_or_else(|| invitation.model.created_at.into()),
            expires_at: invitation.expires_at(),
        }))
    }

    #[tracing::instrument(skip_all, name = "db.query", fields(db.system = "postgresql", db.operation = "user_invitation.find_by_token"))]
    async fn find_by_token(
        &self,
        token_digest: &str,
        now: DateTime<Utc>,
    ) -> Result<Option<User>, AppError> {
        let Some(invitation) =
            account_challenge::find_by_digest::<InvitationState>(&self.db, token_digest, PURPOSE)
                .await
                .map_err(internal)?
        else {
            return Ok(None);
        };
        let Some(user_id) = invitation.model.user_id else {
            return Ok(None);
        };
        let Some(account) = UserEntity::find_by_id(user_id)
            .one(&self.db)
            .await
            .map_err(internal)?
        else {
            return Ok(None);
        };
        if !usable(&invitation, &account, now)
            || has_password(&self.db, account.id).await.map_err(internal)?
        {
            return Ok(None);
        }
        to_domain(account).map(Some).map_err(internal)
    }

    #[tracing::instrument(skip_all, name = "db.query", fields(db.system = "postgresql", db.operation = "user_invitation.accept"))]
    async fn accept(
        &self,
        token_digest: &str,
        password: &Password,
        now: DateTime<Utc>,
    ) -> Result<InvitationAcceptance, AppError> {
        let txn = self.db.begin().await.map_err(internal)?;
        let Some(invitation) =
            account_challenge::find_by_digest::<InvitationState>(&txn, token_digest, PURPOSE)
                .await
                .map_err(internal)?
        else {
            return Ok(InvitationAcceptance::Invalid);
        };
        let Some(user_id) = invitation.model.user_id else {
            return Ok(InvitationAcceptance::Invalid);
        };
        let Some(account) = UserEntity::find_by_id(user_id)
            .one(&txn)
            .await
            .map_err(internal)?
        else {
            return Ok(InvitationAcceptance::Invalid);
        };
        // Lock order of every credential write: credentials, then the row.
        lock_user_credentials(&txn, account.oid.into())
            .await
            .map_err(internal)?;
        let Some(account) = UserEntity::find()
            .filter(UserColumn::Id.eq(account.id))
            .lock_exclusive()
            .one(&txn)
            .await
            .map_err(internal)?
        else {
            return Ok(InvitationAcceptance::Invalid);
        };
        // Re-read under the locks: a new link or a password may have
        // replaced this one in the meantime.
        let invitation_id = invitation.model.id;
        let Some(invitation) =
            account_challenge::find_by_digest::<InvitationState>(&txn, token_digest, PURPOSE)
                .await
                .map_err(internal)?
                .filter(|current| current.model.id == invitation_id)
        else {
            return Ok(InvitationAcceptance::Invalid);
        };
        if !usable(&invitation, &account, now)
            || has_password(&txn, account.id).await.map_err(internal)?
        {
            return Ok(InvitationAcceptance::Invalid);
        }

        let data = to_value(password).map_err(internal)?;
        user_credential::ActiveModel {
            oid: Set(Uuid::new_v4()),
            user_id: Set(account.id),
            r#type: Set("password".to_owned()),
            data: Set(data),
            expires_at: Set(None),
            created_at: Set(now.into()),
            ..Default::default()
        }
        .insert(&txn)
        .await
        .map_err(internal)?;
        let verified_now = !account.email_verified;
        let mut active: user::ActiveModel = account.clone().into();
        active.email_verified = Set(true);
        active.updated_at = Set(Some(now.into()));
        let model = active.update(&txn).await.map_err(internal)?;
        renew_user_version_in_txn(&txn, model.id)
            .await
            .map_err(internal)?;
        discard_invitation_in_txn(&txn, model.id)
            .await
            .map_err(internal)?;
        // The address is now verified, so a pending verification of it is moot.
        discard_for_user_in_txn(&txn, model.id)
            .await
            .map_err(internal)?;
        audit::record(
            &txn,
            AuditRecord::success(AuditAction::AccountInvitationAccept, model.oid)
                .default_actor(AuditActor::user(model.oid))
                .with_changes(|changes| {
                    changes.secret(AuditField::Password);
                    if verified_now {
                        changes.diff(AuditField::EmailVerified, &false, &true);
                    }
                }),
        )
        .await
        .map_err(internal)?;
        txn.commit().await.map_err(internal)?;
        Ok(InvitationAcceptance::Accepted {
            user_oid: model.oid.into(),
        })
    }
}

/// Whether the invitation still applies to the account as it is now.
fn usable(invitation: &Invitation, account: &user::Model, now: DateTime<Utc>) -> bool {
    account.enabled
        && invitation.state.email_normalized == account.email_normalized
        && invitation.expires_at() > now
}
