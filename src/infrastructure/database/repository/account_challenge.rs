//! Challenges bound to an account alone: followed from an emailed link with
//! neither a login nor a session, such as an email verification or an
//! invitation. An account has at most one of each purpose, and the link is
//! found by the digest of its token.
//!
//! Callers lock the account row first, so admissions, uses and address
//! changes of one account are serialized.

use chrono::{DateTime, Utc};
use identity_domain::{
    auth::challenge::{ChallengeMethod, ChallengePurpose, DeliveryCounter},
    email::EmailDeliveryReport,
};
use sea_orm::{
    ActiveModelTrait, ColumnTrait, ConnectionTrait, DbErr, EntityTrait, QueryFilter, Set,
};
use serde::{Serialize, de::DeserializeOwned};
use uuid::Uuid;

use crate::database::entity::authentication_challenge::{
    self, Column as ChallengeColumn, Entity as ChallengeEntity,
};

/// One stored account challenge with its decoded purpose state.
pub(super) struct AccountChallenge<S> {
    pub model: authentication_challenge::Model,
    pub state: S,
}

impl<S> AccountChallenge<S> {
    pub fn expires_at(&self) -> DateTime<Utc> {
        self.model.expires_at.into()
    }

    pub fn sent_at(&self) -> Option<DateTime<Utc>> {
        self.model.sent_at.map(Into::into)
    }

    pub fn counter(&self) -> Option<DeliveryCounter> {
        Some(DeliveryCounter {
            sent_at: self.model.sent_at?.into(),
            send_count: self.model.send_count,
            window_started_at: self.model.window_started_at?.into(),
        })
    }
}

fn account_bound() -> sea_orm::Condition {
    sea_orm::Condition::all()
        .add(ChallengeColumn::LoginId.is_null())
        .add(ChallengeColumn::SessionId.is_null())
}

fn decode<S: DeserializeOwned>(
    model: authentication_challenge::Model,
) -> Result<Option<AccountChallenge<S>>, DbErr> {
    // A row whose state no longer decodes is treated as absent.
    Ok(serde_json::from_value(model.state.clone())
        .ok()
        .map(|state| AccountChallenge { model, state }))
}

/// The account's challenge of `purpose`, expired or not.
pub(super) async fn find<S: DeserializeOwned>(
    connection: &impl ConnectionTrait,
    user_id: i64,
    purpose: ChallengePurpose,
) -> Result<Option<AccountChallenge<S>>, DbErr> {
    match ChallengeEntity::find()
        .filter(account_bound())
        .filter(ChallengeColumn::UserId.eq(user_id))
        .filter(ChallengeColumn::Purpose.eq(purpose.as_str()))
        .one(connection)
        .await?
    {
        Some(model) => decode(model),
        None => Ok(None),
    }
}

/// The challenge of `purpose` whose link token has `token_digest`.
pub(super) async fn find_by_digest<S: DeserializeOwned>(
    connection: &impl ConnectionTrait,
    token_digest: &str,
    purpose: ChallengePurpose,
) -> Result<Option<AccountChallenge<S>>, DbErr> {
    match ChallengeEntity::find()
        .filter(account_bound())
        .filter(ChallengeColumn::TokenDigest.eq(token_digest))
        .filter(ChallengeColumn::Purpose.eq(purpose.as_str()))
        .one(connection)
        .await?
    {
        Some(model) => decode(model),
        None => Ok(None),
    }
}

/// A new link for an account challenge: what replaces any earlier one.
pub(super) struct AccountChallengeIssue<'a, S> {
    pub user_id: i64,
    pub purpose: ChallengePurpose,
    pub token_digest: &'a str,
    pub counter: DeliveryCounter,
    pub state: &'a S,
    pub expires_at: DateTime<Utc>,
}

/// Store a new link, replacing the account's earlier challenge of the same
/// purpose so only the newest link works.
pub(super) async fn issue<S: Serialize>(
    connection: &impl ConnectionTrait,
    issue: AccountChallengeIssue<'_, S>,
) -> Result<authentication_challenge::Model, DbErr> {
    let state =
        serde_json::to_value(issue.state).map_err(|error| DbErr::Custom(error.to_string()))?;
    let existing = ChallengeEntity::find()
        .filter(account_bound())
        .filter(ChallengeColumn::UserId.eq(issue.user_id))
        .filter(ChallengeColumn::Purpose.eq(issue.purpose.as_str()))
        .one(connection)
        .await?;
    let now = issue.counter.sent_at;
    let replacing = existing.is_some();
    let mut active = match existing {
        Some(model) => model.into(),
        None => authentication_challenge::ActiveModel {
            user_id: Set(Some(issue.user_id)),
            login_id: Set(None),
            session_id: Set(None),
            method: Set(ChallengeMethod::EmailOtp.as_str().to_owned()),
            purpose: Set(issue.purpose.as_str().to_owned()),
            ..Default::default()
        },
    };
    active.oid = Set(Uuid::new_v4());
    active.state = Set(state);
    active.token_digest = Set(Some(issue.token_digest.to_owned()));
    active.sent_at = Set(Some(issue.counter.sent_at.into()));
    active.send_count = Set(issue.counter.send_count);
    active.window_started_at = Set(Some(issue.counter.window_started_at.into()));
    active.expires_at = Set(issue.expires_at.into());
    active.created_at = Set(now.into());
    if replacing {
        active.update(connection).await
    } else {
        active.insert(connection).await
    }
}

/// Remove the account's challenge of `purpose`. Returns whether one existed.
pub(super) async fn discard(
    connection: &impl ConnectionTrait,
    user_id: i64,
    purpose: ChallengePurpose,
) -> Result<bool, DbErr> {
    let result = ChallengeEntity::delete_many()
        .filter(account_bound())
        .filter(ChallengeColumn::UserId.eq(user_id))
        .filter(ChallengeColumn::Purpose.eq(purpose.as_str()))
        .exec(connection)
        .await?;
    Ok(result.rows_affected > 0)
}

/// Void the account's active challenge link of `purpose` while keeping its
/// delivery counter intact, so cancelling or confirming cannot reset rate
/// limits. Returns whether an unvoided challenge existed.
pub(super) async fn void(
    connection: &impl ConnectionTrait,
    user_id: i64,
    purpose: ChallengePurpose,
    now: DateTime<Utc>,
) -> Result<bool, DbErr> {
    let result = connection
        .execute_raw(sea_orm::Statement::from_sql_and_values(
            sea_orm::DbBackend::Postgres,
            "UPDATE authentication_challenge \
             SET token_digest = NULL, expires_at = LEAST(expires_at, $3) \
             WHERE login_id IS NULL AND session_id IS NULL AND user_id = $1 AND purpose = $2 \
               AND (token_digest IS NOT NULL OR expires_at > $3)",
            [
                user_id.into(),
                purpose.as_str().into(),
                now.fixed_offset().into(),
            ],
        ))
        .await?;
    Ok(result.rows_affected() > 0)
}

/// Record the delivery outcome of the email that carries the link of the
/// account challenge `oid`. A link replaced since has a new `oid`, so a late
/// outcome of an older email changes nothing.
pub async fn record_delivery(
    connection: &impl ConnectionTrait,
    oid: Uuid,
    report: &EmailDeliveryReport,
) -> Result<(), DbErr> {
    let report = serde_json::to_value(report).map_err(|error| DbErr::Custom(error.to_string()))?;
    connection
        .execute_raw(sea_orm::Statement::from_sql_and_values(
            sea_orm::DbBackend::Postgres,
            "UPDATE authentication_challenge SET state = jsonb_set(state, '{delivery}', $2) \
             WHERE oid = $1 AND login_id IS NULL AND session_id IS NULL \
               AND COALESCE(state->'delivery'->>'status', 'queued') <> 'delivered'",
            [oid.into(), report.into()],
        ))
        .await?;
    Ok(())
}
