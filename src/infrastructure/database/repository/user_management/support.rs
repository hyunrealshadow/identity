//! Locks, live-authority rechecks, cursor conditions and access invalidation shared by user writes.

use super::*;

pub(super) fn storage(error: DbErr) -> UserManagementRepositoryError {
    UserManagementRepositoryError::Storage(Box::new(error))
}

pub(super) fn corrupt() -> UserManagementRepositoryError {
    UserManagementRepositoryError::CorruptRecord
}

pub(super) async fn stored_user_version<C: ConnectionTrait>(
    db: &C,
    user_id: i64,
) -> Result<Uuid, UserManagementRepositoryError> {
    let row = db
        .query_one_raw(Statement::from_sql_and_values(
            DbBackend::Postgres,
            "SELECT version FROM \"user\" WHERE id = $1",
            [user_id.into()],
        ))
        .await
        .map_err(storage)?
        .ok_or_else(corrupt)?;
    row.try_get::<Uuid>("", "version").map_err(storage)
}

pub(super) fn map_domain_user(error: UserRepositoryError) -> UserManagementRepositoryError {
    match error {
        UserRepositoryError::QueryFailed(source) => UserManagementRepositoryError::Storage(source),
        _ => UserManagementRepositoryError::CorruptRecord,
    }
}

pub(super) fn map_authorization(
    error: ManagementAuthorizationError,
) -> UserManagementRepositoryError {
    UserManagementRepositoryError::Authorization(error)
}

pub(super) async fn identifier_exists<C: ConnectionTrait>(
    db: &C,
    column: user::Column,
    normalized: &str,
    except_id: Option<i64>,
) -> Result<bool, UserManagementRepositoryError> {
    let mut query = UserEntity::find().filter(column.eq(normalized));
    if let Some(exclude) = except_id {
        query = query.filter(UserColumn::Id.ne(exclude));
    }
    query
        .one(db)
        .await
        .map(|model| model.is_some())
        .map_err(storage)
}

pub(super) use crate::database::repository::sql_support::escape_like;

pub(super) async fn current_authority(
    txn: &DatabaseTransaction,
    authority: &UserManagementAuthority,
) -> Result<Option<CurrentManagementAuthority>, UserManagementRepositoryError> {
    match &authority.actor.principal {
        ActorPrincipal::User { user_oid, .. } => {
            let authority =
                crate::database::repository::management_authority::lock_and_load_user_authority(
                    txn, *user_oid,
                )
                .await
                .map_err(|error| UserManagementRepositoryError::Storage(Box::new(error)))?;
            Ok(authority.map(CurrentManagementAuthority::UserPermissions))
        }
        ActorPrincipal::Client { client_oid } => {
            authorization::load_client_scope_authority(txn, *client_oid)
                .await
                .map_err(storage)
                .map(|current| current.map(CurrentManagementAuthority::ClientScopes))
        }
    }
}

/// The target holds the complete trusted management capability set. Never a
/// role key or built-in group check.
pub(super) async fn target_is_owner(
    txn: &DatabaseTransaction,
    user_oid: UserOid,
) -> Result<bool, UserManagementRepositoryError> {
    let authority = load_user_permission_authority(txn, user_oid)
        .await
        .map_err(|error| UserManagementRepositoryError::Storage(Box::new(error)))?;
    Ok(authority.is_some_and(|authority| authority.has_full_management_permissions()))
}

/// Lock and re-verify the issuing client's live authority before any user/grant
/// evaluation or business write.
pub(super) async fn recheck_issuing_client(
    txn: &DatabaseTransaction,
    authority: &UserManagementAuthority,
) -> Result<(), UserManagementRepositoryError> {
    crate::database::repository::management_authority::lock_and_recheck_issuing_client(
        txn,
        authority.client_oid,
        authority.client_policy_version,
    )
    .await
    .map_err(|error| match error {
        crate::database::repository::management_authority::ManagementAuthorityCheckError::Storage(
            error,
        ) => storage(error),
        crate::database::repository::management_authority::ManagementAuthorityCheckError::Authorization(
            error,
        ) => map_authorization(error),
    })
}

/// Re-verify entry authority with authoritative rows in the write transaction.
pub(super) async fn recheck_authority(
    txn: &DatabaseTransaction,
    authority: &UserManagementAuthority,
    required: ManagementScope,
    target_user: Option<UserOid>,
) -> Result<(), UserManagementRepositoryError> {
    // Global serialization first, then the issuing client/policy, then the
    // actor/target user authority reads.
    lock_owner_lifecycle(txn).await.map_err(storage)?;
    recheck_issuing_client(txn, authority).await?;
    let current = current_authority(txn, authority).await?;
    let policy_version = policy_fingerprint();
    let target = if let Some(user_oid) = target_user {
        ManagementTarget::user(user_oid, target_is_owner(txn, user_oid).await?)
    } else {
        ManagementTarget::instance()
    };
    let recent_aal2_ttl =
        crate::database::repository::management_authority::recent_authentication_ttl(txn).await;
    evaluate_management_authority(&ManagementAuthorizationRequest {
        actor: &authority.actor,
        token_scopes: &authority.token_scopes,
        required,
        target,
        current_authority: current.as_ref(),
        snapshot: authority.snapshot.as_ref(),
        credential_client_boundary: Some(authority.client_policy_version),
        current_policy_version: policy_version,
        now: Utc::now(),
        recent_aal2_ttl,
    })
    .map(|_| ())
    .map_err(map_authorization)
}

pub(super) async fn append_semantic_audit(
    txn: &DatabaseTransaction,
    authority: &UserManagementAuthority,
    record: AuditRecord,
) -> Result<(), UserManagementRepositoryError> {
    audit::record(txn, record.by(&authority.actor))
        .await
        .map_err(|error| UserManagementRepositoryError::AuditFailed(Box::new(error)))
}

pub(super) fn record_from_model(
    model: user::Model,
) -> Result<UserManagementRecord, UserManagementRepositoryError> {
    let user = to_domain(model).map_err(map_domain_user)?;
    Ok(UserManagementRecord::new(user))
}

pub(super) fn cursor_condition(
    cursor: &UserSortKey,
    comparison: CursorComparison,
    order: ManagementUserOrder,
) -> Condition {
    use identity_application::user::management::UserOrder;
    match (cursor, order) {
        (UserSortKey::CreatedAt { created_at, id }, UserOrder::CreatedAtAsc) => {
            created_at_condition(UserColumn::CreatedAt, *created_at, *id, comparison, true)
        }
        (UserSortKey::CreatedAt { created_at, id }, UserOrder::CreatedAtDesc) => {
            created_at_condition(UserColumn::CreatedAt, *created_at, *id, comparison, false)
        }
        (
            UserSortKey::Username {
                name_normalized,
                id,
            },
            UserOrder::UsernameAsc,
        ) => name_condition(
            UserColumn::NameNormalized,
            name_normalized,
            *id,
            comparison,
            true,
        ),
        (
            UserSortKey::Username {
                name_normalized,
                id,
            },
            UserOrder::UsernameDesc,
        ) => name_condition(
            UserColumn::NameNormalized,
            name_normalized,
            *id,
            comparison,
            false,
        ),
        _ => Condition::all().add(UserColumn::Id.eq(-1_i64)),
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum CursorComparison {
    After,
    Before,
}

pub(super) fn created_at_condition(
    column: user::Column,
    created_at: chrono::DateTime<Utc>,
    id: i64,
    comparison: CursorComparison,
    ascending: bool,
) -> Condition {
    let value = created_at.fixed_offset();
    match comparison {
        CursorComparison::After if ascending => Condition::any().add(column.gt(value)).add(
            Condition::all()
                .add(column.eq(value))
                .add(UserColumn::Id.gt(id)),
        ),
        CursorComparison::After => Condition::any().add(column.lt(value)).add(
            Condition::all()
                .add(column.eq(value))
                .add(UserColumn::Id.lt(id)),
        ),
        CursorComparison::Before if ascending => Condition::any().add(column.lt(value)).add(
            Condition::all()
                .add(column.eq(value))
                .add(UserColumn::Id.lt(id)),
        ),
        CursorComparison::Before => Condition::any().add(column.gt(value)).add(
            Condition::all()
                .add(column.eq(value))
                .add(UserColumn::Id.gt(id)),
        ),
    }
}

pub(super) fn name_condition(
    column: user::Column,
    name_normalized: &str,
    id: i64,
    comparison: CursorComparison,
    ascending: bool,
) -> Condition {
    let value = name_normalized.to_owned();
    match comparison {
        CursorComparison::After if ascending => Condition::any().add(column.gt(value.clone())).add(
            Condition::all()
                .add(column.eq(value))
                .add(UserColumn::Id.gt(id)),
        ),
        CursorComparison::After => Condition::any().add(column.lt(value.clone())).add(
            Condition::all()
                .add(column.eq(value))
                .add(UserColumn::Id.lt(id)),
        ),
        CursorComparison::Before if ascending => {
            Condition::any().add(column.lt(value.clone())).add(
                Condition::all()
                    .add(column.eq(value))
                    .add(UserColumn::Id.lt(id)),
            )
        }
        CursorComparison::Before => Condition::any().add(column.gt(value.clone())).add(
            Condition::all()
                .add(column.eq(value))
                .add(UserColumn::Id.gt(id)),
        ),
    }
}

pub(super) async fn invalidate_access_in_txn(
    txn: &DatabaseTransaction,
    user_oid: UserOid,
    user_id: i64,
) -> Result<(), UserManagementRepositoryError> {
    // Lock order: owner lifecycle (held by caller), credential, sessions.
    lock_user_credentials(txn, user_oid)
        .await
        .map_err(storage)?;
    lock_account_sessions(txn, user_id).await.map_err(storage)?;
    // Sessions and pending login flows.
    txn.execute_raw(Statement::from_sql_and_values(
        DbBackend::Postgres,
        "UPDATE session SET status = 'revoked', revoked_at = now(), updated_at = now() \
         WHERE user_id = $1 AND status = 'active' AND revoked_at IS NULL",
        [user_id.into()],
    ))
    .await
    .map_err(storage)?;
    txn.execute_raw(Statement::from_sql_and_values(
        DbBackend::Postgres,
        "UPDATE login SET status = 'failed', updated_at = now() \
         WHERE user_id = $1 AND status IN ('created', 'identifier_verified', 'mfa_required', 'mfa_enrollment_required', 'password_change_required')",
        [user_id.into()],
    ))
    .await
    .map_err(storage)?;
    txn.execute_raw(Statement::from_sql_and_values(
        DbBackend::Postgres,
        // Challenges of the account's logins and sessions; an email
        // verification or invitation followed without either stays.
        "DELETE FROM authentication_challenge WHERE user_id = $1 \
         AND (login_id IS NOT NULL OR session_id IS NOT NULL)",
        [user_id.into()],
    ))
    .await
    .map_err(storage)?;
    // Device requests and selected device authorizations carry the user OID.
    txn.execute_raw(Statement::from_sql_and_values(
        DbBackend::Postgres,
        "UPDATE client_authorization SET revoked_at = now(), updated_at = now() \
         WHERE type = 'device_authorization' AND revoked_at IS NULL AND data->>'user_oid' = $1",
        [Uuid::from(user_oid).to_string().into()],
    ))
    .await
    .map_err(storage)?;
    // Generation + binding versions + code/token/refresh revocation.
    sync_user_authority_in_txn(txn, user_id)
        .await
        .map_err(storage)?;
    Ok(())
}

pub(super) fn filtered_users(filter: &UserFilter) -> sea_orm::Select<UserEntity> {
    let mut select = UserEntity::find();
    if let Some(term) = &filter.query {
        let pattern = format!("%{}%", escape_like(term));
        select = select.filter(
            Condition::any()
                .add(UserColumn::NameNormalized.like(pattern.clone()))
                .add(UserColumn::EmailNormalized.like(pattern)),
        );
    }
    if let Some(username) = &filter.username {
        select = select.filter(UserColumn::NameNormalized.eq(username));
    }
    if let Some(email) = &filter.email {
        select = select.filter(UserColumn::EmailNormalized.eq(email));
    }
    if let Some(enabled) = filter.enabled {
        select = select.filter(UserColumn::Enabled.eq(enabled));
    }
    if let Some(locked) = filter.locked {
        let now = Utc::now().fixed_offset();
        if locked {
            select = select.filter(
                Condition::all().add(UserColumn::Locked.eq(true)).add(
                    Condition::any()
                        .add(UserColumn::LockedUntil.is_null())
                        .add(UserColumn::LockedUntil.gt(now)),
                ),
            );
        } else {
            select = select.filter(
                Condition::any().add(UserColumn::Locked.eq(false)).add(
                    Condition::all()
                        .add(UserColumn::LockedUntil.is_not_null())
                        .add(UserColumn::LockedUntil.lte(now)),
                ),
            );
        }
    }
    if let Some(from) = filter.created_from {
        select = select.filter(UserColumn::CreatedAt.gte(from.fixed_offset()));
    }
    if let Some(before) = filter.created_before {
        select = select.filter(UserColumn::CreatedAt.lt(before.fixed_offset()));
    }
    select
}

pub(super) fn storage_any(
    error: impl std::error::Error + Send + Sync + 'static,
) -> UserManagementRepositoryError {
    UserManagementRepositoryError::Storage(Box::new(error))
}
