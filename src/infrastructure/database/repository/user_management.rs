//! Transactional persistence for P2 instance user management.
//!
//! Every write re-locks the issuing client and policy, derives its current
//! authority fingerprint, and re-loads the actor's authoritative binding/grant
//! with a row lock, the current authorization policy version and the target's
//! owner state inside the same transaction. The write also rotates the core
//! `user.version` UUID, writes the semantic audit fact and commits all of it
//! together.

use async_trait::async_trait;
use chrono::Utc;
use identity_application::user::Password;
use identity_application::{
    authorization::{
        CurrentManagementAuthority, DEFAULT_RECENT_AAL2_TTL, ManagementAuthorizationError,
        ManagementAuthorizationRequest, ManagementTarget, evaluate_management_authority,
    },
    user::management::{
        CreateUserTransaction, UpdateUserTransaction, UserFilter, UserManagementAuthority,
        UserManagementMutationOutcome, UserManagementPageData, UserManagementPageEntry,
        UserManagementQuery, UserManagementRepository, UserManagementRepositoryError,
        UserOrder as ManagementUserOrder, UserPageDirection, UserSortKey, UserStateTransaction,
        repository::RevokeUserSessionsTransaction,
    },
};
use identity_domain::audit::{AuditAction, AuditField, AuditRecord};
use identity_domain::{
    authorization::{ActorPrincipal, ManagementScope, policy_fingerprint},
    user::{UserManagementRecord, UserOid, repository::UserRepositoryError},
};
use sea_orm::{
    ActiveModelTrait, ColumnTrait, Condition, ConnectionTrait, DatabaseConnection,
    DatabaseTransaction, DbBackend, DbErr, EntityTrait, Order, QueryFilter, QueryOrder,
    QuerySelect, Set, Statement, TransactionTrait,
};
use serde_json::{json, to_value};
use uuid::Uuid;

use super::{
    authorization,
    authorization::load_user_permission_authority,
    authorization_lifecycle::{
        ensure_recoverable_authorization_administrator, lock_owner_lifecycle,
        renew_user_version_in_txn, sync_user_authority_in_txn,
    },
    email_verification::discard_for_user_in_txn,
    session_security::lock_account_sessions,
    shared::lock_user_credentials,
    user::{to_domain, update_theme_preference, user_attribute_changes},
    user_credential::prune_password_history,
};
use crate::database::{
    audit, client_authorization_boundary,
    entity::{
        user,
        user::{Column as UserColumn, Entity as UserEntity},
        user_credential,
    },
};

pub struct UserManagementRepositoryImpl {
    db: DatabaseConnection,
}

impl UserManagementRepositoryImpl {
    #[must_use]
    pub fn new(db: DatabaseConnection) -> Self {
        Self { db }
    }
}

fn storage(error: DbErr) -> UserManagementRepositoryError {
    UserManagementRepositoryError::Storage(Box::new(error))
}

fn corrupt() -> UserManagementRepositoryError {
    UserManagementRepositoryError::CorruptRecord
}

async fn user_id_by_oid<C: ConnectionTrait>(
    db: &C,
    oid: UserOid,
) -> Result<Option<i64>, UserManagementRepositoryError> {
    UserEntity::find()
        .select_only()
        .column(UserColumn::Id)
        .filter(UserColumn::Oid.eq(Uuid::from(oid)))
        .into_tuple::<i64>()
        .one(db)
        .await
        .map_err(storage)
}

async fn stored_user_version<C: ConnectionTrait>(
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

fn map_domain_user(error: UserRepositoryError) -> UserManagementRepositoryError {
    match error {
        UserRepositoryError::QueryFailed(source) => UserManagementRepositoryError::Storage(source),
        _ => UserManagementRepositoryError::CorruptRecord,
    }
}

fn map_authorization(error: ManagementAuthorizationError) -> UserManagementRepositoryError {
    UserManagementRepositoryError::Authorization(error)
}

async fn identifier_exists<C: ConnectionTrait>(
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

fn escape_like(value: &str) -> String {
    value
        .replace('\\', "\\\\")
        .replace('%', "\\%")
        .replace('_', "\\_")
}

async fn current_authority(
    txn: &DatabaseTransaction,
    authority: &UserManagementAuthority,
) -> Result<Option<CurrentManagementAuthority>, UserManagementRepositoryError> {
    match &authority.actor.principal {
        ActorPrincipal::User { user_oid, .. } => {
            let Some(user_id) = user_id_by_oid(txn, *user_oid).await? else {
                return Ok(None);
            };
            let _ = txn
                .query_one_raw(Statement::from_sql_and_values(
                    DbBackend::Postgres,
                    "SELECT id FROM \"user\" WHERE id = $1 FOR UPDATE",
                    [user_id.into()],
                ))
                .await
                .map_err(storage)?;
            let authority = load_user_permission_authority(txn, *user_oid)
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
async fn target_is_owner(
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
///
/// The verified credential carries the original semantic client fingerprint.
/// A missing client or changed scope boundary fails closed; the current value
/// is never substituted into the request authority.
async fn recheck_issuing_client(
    txn: &DatabaseTransaction,
    authority: &UserManagementAuthority,
) -> Result<(), UserManagementRepositoryError> {
    let client_row = txn
        .query_one_raw(Statement::from_sql_and_values(
            DbBackend::Postgres,
            "SELECT id FROM client WHERE oid = $1 FOR UPDATE",
            [authority.client_oid.into()],
        ))
        .await
        .map_err(storage)?;
    let Some(client_row) = client_row else {
        return Err(map_authorization(
            ManagementAuthorizationError::NoCurrentGrant,
        ));
    };
    let client_id = client_row.try_get::<i64>("", "id").map_err(storage)?;
    // Compare the exact live client scope boundary; there is no management
    // enable switch or independent machine grant.
    let (_, fingerprint) =
        client_authorization_boundary::client_boundary_fingerprint(txn, client_id)
            .await
            .map_err(storage)?;
    if fingerprint != authority.client_policy_version {
        return Err(map_authorization(
            ManagementAuthorizationError::SnapshotPolicyMismatch,
        ));
    }
    Ok(())
}

/// Re-verify entry authority with authoritative rows in the write transaction.
async fn recheck_authority(
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
        recent_aal2_ttl: DEFAULT_RECENT_AAL2_TTL,
    })
    .map(|_| ())
    .map_err(map_authorization)
}

async fn append_semantic_audit(
    txn: &DatabaseTransaction,
    authority: &UserManagementAuthority,
    record: AuditRecord,
) -> Result<(), UserManagementRepositoryError> {
    audit::record(txn, record.by(&authority.actor))
        .await
        .map_err(|error| UserManagementRepositoryError::AuditFailed(Box::new(error)))
}

fn record_from_model(
    model: user::Model,
) -> Result<UserManagementRecord, UserManagementRepositoryError> {
    let user = to_domain(model).map_err(map_domain_user)?;
    Ok(UserManagementRecord::new(user))
}

fn cursor_condition(
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
enum CursorComparison {
    After,
    Before,
}

fn created_at_condition(
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

fn name_condition(
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

async fn invalidate_access_in_txn(
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
        "DELETE FROM authentication_challenge WHERE user_id = $1",
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

fn filtered_users(filter: &UserFilter) -> sea_orm::Select<UserEntity> {
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
        select = select.filter(UserColumn::Locked.eq(locked));
    }
    if let Some(from) = filter.created_from {
        select = select.filter(UserColumn::CreatedAt.gte(from.fixed_offset()));
    }
    if let Some(before) = filter.created_before {
        select = select.filter(UserColumn::CreatedAt.lt(before.fixed_offset()));
    }
    select
}

fn storage_any(
    error: impl std::error::Error + Send + Sync + 'static,
) -> UserManagementRepositoryError {
    UserManagementRepositoryError::Storage(Box::new(error))
}

impl UserManagementRepositoryImpl {
    /// Open a user write: lifecycle, client, credential and user locks in the
    /// documented order, live authority for the target, and the expected
    /// version. A business outcome ends the write before any change.
    async fn begin_user_write(
        &self,
        command: &UserStateTransaction,
    ) -> Result<
        Result<(DatabaseTransaction, user::Model), UserManagementMutationOutcome>,
        UserManagementRepositoryError,
    > {
        let txn = self.db.begin().await.map_err(storage)?;
        lock_owner_lifecycle(&txn).await.map_err(storage)?;
        recheck_issuing_client(&txn, &command.authority).await?;
        lock_user_credentials(&txn, command.user_oid)
            .await
            .map_err(storage)?;
        let Some(model) = UserEntity::find()
            .filter(UserColumn::Oid.eq(Uuid::from(command.user_oid)))
            .lock_exclusive()
            .one(&txn)
            .await
            .map_err(storage)?
        else {
            return Ok(Err(UserManagementMutationOutcome::UserNotFound));
        };
        recheck_authority(
            &txn,
            &command.authority,
            ManagementScope::UsersWrite,
            Some(command.user_oid),
        )
        .await?;
        if model.version != command.expected_version {
            return Ok(Err(UserManagementMutationOutcome::VersionConflict {
                current_version: model.version,
            }));
        }
        Ok(Ok((txn, model)))
    }
}

async fn finish_user_write(
    txn: DatabaseTransaction,
    updated: user::Model,
) -> Result<UserManagementMutationOutcome, UserManagementRepositoryError> {
    let user = to_domain(updated).map_err(map_domain_user)?;
    let record = UserManagementRecord::new(user);
    txn.commit().await.map_err(storage)?;
    Ok(UserManagementMutationOutcome::Success(Box::new(record)))
}

#[async_trait]
impl UserManagementRepository for UserManagementRepositoryImpl {
    #[tracing::instrument(skip_all, name = "db.query", fields(db.system = "postgresql", db.operation = "user_management.count"))]
    async fn count_users(&self, filter: UserFilter) -> Result<u64, UserManagementRepositoryError> {
        use sea_orm::PaginatorTrait;
        filtered_users(&filter)
            .count(&self.db)
            .await
            .map_err(storage)
    }

    #[tracing::instrument(skip_all, name = "db.query", fields(db.system = "postgresql", db.operation = "user_management.list"))]
    async fn list_users(
        &self,
        query: UserManagementQuery,
    ) -> Result<UserManagementPageData, UserManagementRepositoryError> {
        let mut select = filtered_users(&query.filter);
        if let Some(after) = &query.after {
            select = select.filter(cursor_condition(
                after,
                CursorComparison::After,
                query.order,
            ));
        }
        if let Some(before) = &query.before {
            select = select.filter(cursor_condition(
                before,
                CursorComparison::Before,
                query.order,
            ));
        }

        let descending = match query.direction {
            UserPageDirection::Forward => query.order.is_descending(),
            UserPageDirection::Backward => !query.order.is_descending(),
        };
        let (created_order, id_order, name_order) = if descending {
            (Order::Desc, Order::Desc, Order::Desc)
        } else {
            (Order::Asc, Order::Asc, Order::Asc)
        };
        select = match query.order {
            ManagementUserOrder::CreatedAtAsc | ManagementUserOrder::CreatedAtDesc => select
                .order_by(UserColumn::CreatedAt, created_order)
                .order_by(UserColumn::Id, id_order),
            ManagementUserOrder::UsernameAsc | ManagementUserOrder::UsernameDesc => select
                .order_by(UserColumn::NameNormalized, name_order)
                .order_by(UserColumn::Id, id_order),
        };
        let rows = select
            .limit((query.limit.saturating_add(1)) as u64)
            .all(&self.db)
            .await
            .map_err(storage)?;
        let has_more = rows.len() > query.limit;
        let mut rows = rows;
        rows.truncate(query.limit);
        if query.direction == UserPageDirection::Backward {
            rows.reverse();
        }

        let mut items = Vec::with_capacity(rows.len());
        for model in rows {
            let sort_key = match query.order {
                ManagementUserOrder::CreatedAtAsc | ManagementUserOrder::CreatedAtDesc => {
                    UserSortKey::CreatedAt {
                        created_at: model.created_at.with_timezone(&Utc),
                        id: model.id,
                    }
                }
                ManagementUserOrder::UsernameAsc | ManagementUserOrder::UsernameDesc => {
                    UserSortKey::Username {
                        name_normalized: model.name_normalized.clone(),
                        id: model.id,
                    }
                }
            };
            let user = to_domain(model).map_err(map_domain_user)?;
            let record = UserManagementRecord::new(user);
            items.push(UserManagementPageEntry { sort_key, record });
        }

        let (has_previous_page, has_next_page) = match query.direction {
            UserPageDirection::Forward => (query.after.is_some(), has_more),
            UserPageDirection::Backward => (has_more, query.before.is_some()),
        };
        Ok(UserManagementPageData {
            items,
            has_previous_page,
            has_next_page,
        })
    }

    #[tracing::instrument(skip_all, name = "db.query", fields(db.system = "postgresql", db.operation = "user_management.find"))]
    async fn find_user(
        &self,
        user_oid: UserOid,
    ) -> Result<Option<UserManagementRecord>, UserManagementRepositoryError> {
        let model = UserEntity::find()
            .filter(UserColumn::Oid.eq(Uuid::from(user_oid)))
            .one(&self.db)
            .await
            .map_err(storage)?;
        match model {
            Some(model) => record_from_model(model).map(Some),
            None => Ok(None),
        }
    }

    #[tracing::instrument(skip_all, name = "db.query", fields(db.system = "postgresql", db.operation = "user_management.find_many"))]
    async fn find_users(
        &self,
        user_oids: Vec<UserOid>,
    ) -> Result<Vec<UserManagementRecord>, UserManagementRepositoryError> {
        if user_oids.is_empty() {
            return Ok(Vec::new());
        }
        UserEntity::find()
            .filter(UserColumn::Oid.is_in(user_oids.into_iter().map(Uuid::from)))
            .all(&self.db)
            .await
            .map_err(storage)?
            .into_iter()
            .map(record_from_model)
            .collect()
    }

    #[tracing::instrument(skip_all, name = "db.query", fields(db.system = "postgresql", db.operation = "user_management.create"))]
    async fn create_user(
        &self,
        command: CreateUserTransaction,
    ) -> Result<UserManagementMutationOutcome, UserManagementRepositoryError> {
        let txn = self.db.begin().await.map_err(storage)?;
        recheck_authority(&txn, &command.authority, ManagementScope::UsersWrite, None).await?;
        if identifier_exists(
            &txn,
            UserColumn::NameNormalized,
            &command.username_normalized,
            None,
        )
        .await?
        {
            return Ok(UserManagementMutationOutcome::UsernameExists);
        }
        if identifier_exists(
            &txn,
            UserColumn::EmailNormalized,
            &command.email_normalized,
            None,
        )
        .await?
        {
            return Ok(UserManagementMutationOutcome::EmailExists);
        }

        let now = Utc::now();
        let user_oid = Uuid::new_v4();
        let mut preferences = json!({});
        if let Some(theme) = command.profile.theme {
            update_theme_preference(&mut preferences, theme);
        }
        let mut active = user::ActiveModel {
            oid: Set(user_oid),
            name: Set(command.username.clone()),
            name_normalized: Set(command.username_normalized.clone()),
            email: Set(command.email.clone()),
            email_normalized: Set(command.email_normalized.clone()),
            email_verified: Set(false),
            preferences: Set(preferences),
            failed_attempts: Set(0),
            enabled: Set(true),
            locked: Set(false),
            created_at: Set(now.into()),
            ..Default::default()
        };
        macro_rules! apply_create_profile {
            ($($field:ident),+ $(,)?) => {
                $(
                    if let Some(value) = command.profile.$field.clone() {
                        active.$field = Set(value);
                    }
                )+
            };
        }
        apply_create_profile!(
            given_name,
            family_name,
            middle_name,
            nickname,
            profile,
            picture,
            website,
            gender,
            birthdate,
            zone_info,
            locale,
            address_formatted,
            address_street_address,
            address_locality,
            address_region,
            address_postal_code,
            address_country
        );
        let inserted = active.insert(&txn).await;
        let model = match inserted {
            Ok(model) => model,
            Err(error) => {
                let _ = txn.rollback().await;
                if identifier_exists(
                    &self.db,
                    UserColumn::NameNormalized,
                    &command.username_normalized,
                    None,
                )
                .await?
                {
                    return Ok(UserManagementMutationOutcome::UsernameExists);
                }
                if identifier_exists(
                    &self.db,
                    UserColumn::EmailNormalized,
                    &command.email_normalized,
                    None,
                )
                .await?
                {
                    return Ok(UserManagementMutationOutcome::EmailExists);
                }
                return Err(storage(error));
            }
        };

        let data = to_value(&command.password)
            .map_err(|error| UserManagementRepositoryError::Storage(Box::new(error)))?;
        user_credential::ActiveModel {
            oid: Set(Uuid::new_v4()),
            user_id: Set(model.id),
            r#type: Set("password".to_owned()),
            data: Set(data),
            expires_at: Set(None),
            created_at: Set(now.into()),
            ..Default::default()
        }
        .insert(&txn)
        .await
        .map_err(storage)?;

        append_semantic_audit(
            &txn,
            &command.authority,
            AuditRecord::success(AuditAction::UserCreate, user_oid),
        )
        .await?;
        let user = to_domain(model).map_err(map_domain_user)?;
        let record = UserManagementRecord::new(user);
        txn.commit().await.map_err(storage)?;
        Ok(UserManagementMutationOutcome::Success(Box::new(record)))
    }

    #[tracing::instrument(skip_all, name = "db.query", fields(db.system = "postgresql", db.operation = "user_management.update"))]
    async fn update_user(
        &self,
        command: UpdateUserTransaction,
    ) -> Result<UserManagementMutationOutcome, UserManagementRepositoryError> {
        let txn = self.db.begin().await.map_err(storage)?;
        lock_owner_lifecycle(&txn).await.map_err(storage)?;
        // Reject a client disabled/reconfigured while this write waited for the
        // global lifecycle lock, before any credential/user lock or business
        // write. Lock order: lifecycle -> client -> policy -> user.
        recheck_issuing_client(&txn, &command.authority).await?;
        // Issuance takes the credential lock before the user row lock.
        lock_user_credentials(&txn, command.user_oid)
            .await
            .map_err(storage)?;
        let Some(model) = UserEntity::find()
            .filter(UserColumn::Oid.eq(Uuid::from(command.user_oid)))
            .lock_exclusive()
            .one(&txn)
            .await
            .map_err(storage)?
        else {
            return Ok(UserManagementMutationOutcome::UserNotFound);
        };
        recheck_authority(
            &txn,
            &command.authority,
            ManagementScope::UsersWrite,
            Some(command.user_oid),
        )
        .await?;
        if model.version != command.expected_version {
            return Ok(UserManagementMutationOutcome::VersionConflict {
                current_version: model.version,
            });
        }
        if let Some(username) = &command.username
            && identifier_exists(
                &txn,
                UserColumn::NameNormalized,
                &username.normalized,
                Some(model.id),
            )
            .await?
        {
            return Ok(UserManagementMutationOutcome::UsernameExists);
        }
        if let Some(email) = &command.email
            && identifier_exists(
                &txn,
                UserColumn::EmailNormalized,
                &email.normalized,
                Some(model.id),
            )
            .await?
        {
            return Ok(UserManagementMutationOutcome::EmailExists);
        }

        let mut active: user::ActiveModel = model.clone().into();
        if let Some(username) = &command.username {
            active.name = Set(username.value.clone());
            active.name_normalized = Set(username.normalized.clone());
        }
        if let Some(email) = &command.email {
            let changed = email.normalized != model.email_normalized;
            active.email = Set(email.value.clone());
            active.email_normalized = Set(email.normalized.clone());
            if changed {
                active.email_verified = Set(false);
            }
        }
        if let Some(verified) = command.email_verified {
            active.email_verified = Set(verified);
        }
        if let Some(required) = command.password_change_required {
            active.password_change_required = Set(required);
        }
        let mut preferences = model.preferences.clone();
        let mut preferences_changed = false;
        if let Some(theme) = command.profile.theme {
            update_theme_preference(&mut preferences, theme);
            preferences_changed = true;
        }
        if preferences_changed {
            active.preferences = Set(preferences);
        }
        macro_rules! apply_profile {
            ($($field:ident),+ $(,)?) => {
                $(
                    if let Some(value) = command.profile.$field.clone() {
                        active.$field = Set(value);
                    }
                )+
            };
        }
        apply_profile!(
            given_name,
            family_name,
            middle_name,
            nickname,
            profile,
            picture,
            website,
            gender,
            birthdate,
            zone_info,
            locale,
            address_formatted,
            address_street_address,
            address_locality,
            address_region,
            address_postal_code,
            address_country
        );
        active.updated_at = Set(Some(Utc::now().into()));

        let updated = match active.update(&txn).await {
            Ok(updated) => updated,
            Err(error) => {
                let _ = txn.rollback().await;
                if let Some(username) = &command.username
                    && identifier_exists(
                        &self.db,
                        UserColumn::NameNormalized,
                        &username.normalized,
                        Some(model.id),
                    )
                    .await?
                {
                    return Ok(UserManagementMutationOutcome::UsernameExists);
                }
                if let Some(email) = &command.email
                    && identifier_exists(
                        &self.db,
                        UserColumn::EmailNormalized,
                        &email.normalized,
                        Some(model.id),
                    )
                    .await?
                {
                    return Ok(UserManagementMutationOutcome::EmailExists);
                }
                return Err(storage(error));
            }
        };
        let version = renew_user_version_in_txn(&txn, updated.id)
            .await
            .map_err(storage)?;
        // A changed address voids any verification of the previous one; an
        // address marked verified needs none.
        if updated.email_normalized != model.email_normalized
            || (updated.email_verified && !model.email_verified)
        {
            discard_for_user_in_txn(&txn, updated.id)
                .await
                .map_err(storage)?;
        }
        let mut updated = updated;
        updated.version = version.as_uuid();
        append_semantic_audit(
            &txn,
            &command.authority,
            AuditRecord::success(AuditAction::UserUpdate, Uuid::from(command.user_oid))
                .with_changes(|changes| user_attribute_changes(changes, &model, &updated)),
        )
        .await?;
        let user = to_domain(updated).map_err(map_domain_user)?;
        let record = UserManagementRecord::new(user);
        txn.commit().await.map_err(storage)?;
        Ok(UserManagementMutationOutcome::Success(Box::new(record)))
    }

    #[tracing::instrument(skip_all, name = "db.query", fields(db.system = "postgresql", db.operation = "user_management.state"))]
    async fn set_user_enabled(
        &self,
        command: UserStateTransaction,
        enabled: bool,
    ) -> Result<UserManagementMutationOutcome, UserManagementRepositoryError> {
        let txn = self.db.begin().await.map_err(storage)?;
        lock_owner_lifecycle(&txn).await.map_err(storage)?;
        // Reject a client disabled/reconfigured while this write waited for the
        // global lifecycle lock, before any credential/user lock or business
        // write. Lock order: lifecycle -> client -> policy -> user.
        recheck_issuing_client(&txn, &command.authority).await?;
        lock_user_credentials(&txn, command.user_oid)
            .await
            .map_err(storage)?;
        let Some(model) = UserEntity::find()
            .filter(UserColumn::Oid.eq(Uuid::from(command.user_oid)))
            .lock_exclusive()
            .one(&txn)
            .await
            .map_err(storage)?
        else {
            return Ok(UserManagementMutationOutcome::UserNotFound);
        };
        recheck_authority(
            &txn,
            &command.authority,
            ManagementScope::UsersWrite,
            Some(command.user_oid),
        )
        .await?;
        if model.version != command.expected_version {
            return Ok(UserManagementMutationOutcome::VersionConflict {
                current_version: model.version,
            });
        }

        let action =
            AuditAction::toggle(enabled, AuditAction::UserEnable, AuditAction::UserDisable);
        if model.enabled == enabled {
            // An explicit request that changes nothing still passed authority
            // re-verification and the expected-version CAS above. Preserve the
            // semantic audit fact but leave the user UUID and every issued
            // artifact untouched: there was no authority transition.
            append_semantic_audit(
                &txn,
                &command.authority,
                AuditRecord::success(action, Uuid::from(command.user_oid)),
            )
            .await?;
            let user = to_domain(model).map_err(map_domain_user)?;
            let record = UserManagementRecord::new(user);
            txn.commit().await.map_err(storage)?;
            return Ok(UserManagementMutationOutcome::Success(Box::new(record)));
        }

        let mut active: user::ActiveModel = model.clone().into();
        active.enabled = Set(enabled);
        active.updated_at = Set(Some(Utc::now().into()));
        let mut updated = active.update(&txn).await.map_err(storage)?;
        if enabled {
            updated.version = sync_user_authority_in_txn(&txn, updated.id)
                .await
                .map_err(storage)?
                .as_uuid();
        } else {
            invalidate_access_in_txn(&txn, command.user_oid, updated.id).await?;
            // Capability-based last recoverable authorization administrator:
            // the proposed disablement is already visible in this transaction.
            if let Err(error) = ensure_recoverable_authorization_administrator(&txn).await {
                if matches!(&error, DbErr::Custom(message) if message == "no recoverable authorization administrator remains")
                {
                    return Ok(UserManagementMutationOutcome::LastOwnerProtected);
                }
                return Err(storage(error));
            }
            updated.version = stored_user_version(&txn, updated.id).await?;
        }
        append_semantic_audit(
            &txn,
            &command.authority,
            AuditRecord::success(action, Uuid::from(command.user_oid)),
        )
        .await?;
        let user = to_domain(updated).map_err(map_domain_user)?;
        let record = UserManagementRecord::new(user);
        txn.commit().await.map_err(storage)?;
        Ok(UserManagementMutationOutcome::Success(Box::new(record)))
    }

    #[tracing::instrument(skip_all, name = "db.query", fields(db.system = "postgresql", db.operation = "user_management.unlock"))]
    async fn unlock_user(
        &self,
        command: UserStateTransaction,
    ) -> Result<UserManagementMutationOutcome, UserManagementRepositoryError> {
        let txn = self.db.begin().await.map_err(storage)?;
        lock_owner_lifecycle(&txn).await.map_err(storage)?;
        // Reject a client disabled/reconfigured while this write waited for the
        // global lifecycle lock, before any credential/user lock or business
        // write. Lock order: lifecycle -> client -> policy -> user.
        recheck_issuing_client(&txn, &command.authority).await?;
        lock_user_credentials(&txn, command.user_oid)
            .await
            .map_err(storage)?;
        let Some(model) = UserEntity::find()
            .filter(UserColumn::Oid.eq(Uuid::from(command.user_oid)))
            .lock_exclusive()
            .one(&txn)
            .await
            .map_err(storage)?
        else {
            return Ok(UserManagementMutationOutcome::UserNotFound);
        };
        recheck_authority(
            &txn,
            &command.authority,
            ManagementScope::UsersWrite,
            Some(command.user_oid),
        )
        .await?;
        if model.version != command.expected_version {
            return Ok(UserManagementMutationOutcome::VersionConflict {
                current_version: model.version,
            });
        }

        if !model.locked && model.locked_until.is_none() && model.failed_attempts == 0 {
            // Already fully unlocked. Authority re-verification and the
            // expected-version CAS still ran, but there is no transition to
            // record beyond the explicit request's semantic audit fact. Do not
            // rotate the UUID or withdraw existing artifacts.
            append_semantic_audit(
                &txn,
                &command.authority,
                AuditRecord::success(AuditAction::UserUnlock, Uuid::from(command.user_oid)),
            )
            .await?;
            let user = to_domain(model).map_err(map_domain_user)?;
            let record = UserManagementRecord::new(user);
            txn.commit().await.map_err(storage)?;
            return Ok(UserManagementMutationOutcome::Success(Box::new(record)));
        }

        let mut active: user::ActiveModel = model.clone().into();
        active.locked = Set(false);
        active.locked_until = Set(Option::<chrono::DateTime<chrono::FixedOffset>>::None);
        active.failed_attempts = Set(0);
        active.updated_at = Set(Some(Utc::now().into()));
        let mut updated = active.update(&txn).await.map_err(storage)?;
        updated.version = sync_user_authority_in_txn(&txn, updated.id)
            .await
            .map_err(storage)?
            .as_uuid();
        append_semantic_audit(
            &txn,
            &command.authority,
            AuditRecord::success(AuditAction::UserUnlock, Uuid::from(command.user_oid)),
        )
        .await?;
        let user = to_domain(updated).map_err(map_domain_user)?;
        let record = UserManagementRecord::new(user);
        txn.commit().await.map_err(storage)?;
        Ok(UserManagementMutationOutcome::Success(Box::new(record)))
    }

    #[tracing::instrument(skip_all, name = "db.query", fields(db.system = "postgresql", db.operation = "user_management.reset_password"))]
    async fn reset_user_password(
        &self,
        command: UserStateTransaction,
        password: Password,
        keep_history: u32,
    ) -> Result<UserManagementMutationOutcome, UserManagementRepositoryError> {
        let (txn, model) = match self.begin_user_write(&command).await? {
            Ok(locked) => locked,
            Err(outcome) => return Ok(outcome),
        };
        let data = to_value(&password).map_err(storage_any)?;
        let current = txn
            .query_one_raw(Statement::from_sql_and_values(
                DbBackend::Postgres,
                "SELECT oid FROM user_credential WHERE user_id = $1 AND type = 'password' \
                 AND (expires_at IS NULL OR expires_at > now()) ORDER BY id DESC LIMIT 1",
                [model.id.into()],
            ))
            .await
            .map_err(storage)?;
        match current {
            Some(row) => {
                let oid: Uuid = row.try_get("", "oid").map_err(storage)?;
                if keep_history > 0 {
                    txn.execute_raw(Statement::from_sql_and_values(
                        DbBackend::Postgres,
                        "INSERT INTO user_credential (oid, user_id, type, data, expires_at, created_at, updated_at) \
                         SELECT gen_random_uuid(), user_id, type, data, now(), created_at, updated_at \
                         FROM user_credential WHERE oid = $1",
                        [oid.into()],
                    ))
                    .await
                    .map_err(storage)?;
                }
                // A new credential OID marks a semantic replacement.
                txn.execute_raw(Statement::from_sql_and_values(
                    DbBackend::Postgres,
                    "UPDATE user_credential SET oid = gen_random_uuid(), data = $1, updated_at = now() WHERE oid = $2",
                    [data.into(), oid.into()],
                ))
                .await
                .map_err(storage)?;
            }
            None => {
                txn.execute_raw(Statement::from_sql_and_values(
                    DbBackend::Postgres,
                    "INSERT INTO user_credential (oid, user_id, type, data) VALUES (gen_random_uuid(), $1, 'password', $2)",
                    [model.id.into(), data.into()],
                ))
                .await
                .map_err(storage)?;
            }
        }
        prune_password_history(&txn, model.id, keep_history)
            .await
            .map_err(storage)?;
        let mut active: user::ActiveModel = model.clone().into();
        active.password_change_required = Set(true);
        active.failed_attempts = Set(0);
        if model.locked_until.is_some() {
            active.locked = Set(false);
            active.locked_until = Set(None);
        }
        active.updated_at = Set(Some(Utc::now().into()));
        let mut updated = active.update(&txn).await.map_err(storage)?;
        invalidate_access_in_txn(&txn, command.user_oid, updated.id).await?;
        updated.version = stored_user_version(&txn, updated.id).await?;
        append_semantic_audit(
            &txn,
            &command.authority,
            AuditRecord::success(AuditAction::UserPasswordReset, Uuid::from(command.user_oid))
                .with_changes(|changes| {
                    changes.secret(AuditField::Password).diff(
                        AuditField::PasswordChangeRequired,
                        &model.password_change_required,
                        &true,
                    );
                }),
        )
        .await?;
        finish_user_write(txn, updated).await
    }

    #[tracing::instrument(skip_all, name = "db.query", fields(db.system = "postgresql", db.operation = "user_management.reset_mfa"))]
    async fn reset_user_mfa(
        &self,
        command: UserStateTransaction,
    ) -> Result<UserManagementMutationOutcome, UserManagementRepositoryError> {
        let (txn, model) = match self.begin_user_write(&command).await? {
            Ok(locked) => locked,
            Err(outcome) => return Ok(outcome),
        };
        let has_password = txn
            .query_one_raw(Statement::from_sql_and_values(
                DbBackend::Postgres,
                "SELECT 1 AS present FROM user_credential WHERE user_id = $1 AND type = 'password' \
                 AND (expires_at IS NULL OR expires_at > now()) LIMIT 1",
                [model.id.into()],
            ))
            .await
            .map_err(storage)?
            .is_some();
        if !has_password {
            return Ok(UserManagementMutationOutcome::NoPassword);
        }
        let removed = txn
            .query_all_raw(Statement::from_sql_and_values(
                DbBackend::Postgres,
                "DELETE FROM user_credential WHERE user_id = $1 AND type IN ('otp', 'recovery_code', 'passkey') RETURNING type",
                [model.id.into()],
            ))
            .await
            .map_err(storage)?
            .into_iter()
            .filter_map(|row| row.try_get::<String>("", "type").ok())
            .collect::<Vec<_>>();
        invalidate_access_in_txn(&txn, command.user_oid, model.id).await?;
        if let Err(error) = ensure_recoverable_authorization_administrator(&txn).await {
            if matches!(&error, DbErr::Custom(message) if message == "no recoverable authorization administrator remains")
            {
                return Ok(UserManagementMutationOutcome::LastOwnerProtected);
            }
            return Err(storage(error));
        }
        let mut updated = model.clone();
        updated.version = stored_user_version(&txn, updated.id).await?;
        append_semantic_audit(
            &txn,
            &command.authority,
            AuditRecord::success(AuditAction::UserMfaReset, Uuid::from(command.user_oid))
                .with_changes(|changes| {
                    for (kind, field) in [
                        ("otp", AuditField::Totp),
                        ("recovery_code", AuditField::RecoveryCodes),
                        ("passkey", AuditField::Passkey),
                    ] {
                        if removed.iter().any(|removed| removed == kind) {
                            changes.secret(field);
                        }
                    }
                }),
        )
        .await?;
        finish_user_write(txn, updated).await
    }

    #[tracing::instrument(skip_all, name = "db.query", fields(db.system = "postgresql", db.operation = "user_management.revoke_sessions"))]
    async fn revoke_user_sessions(
        &self,
        command: RevokeUserSessionsTransaction,
    ) -> Result<UserManagementMutationOutcome, UserManagementRepositoryError> {
        let txn = self.db.begin().await.map_err(storage)?;
        lock_owner_lifecycle(&txn).await.map_err(storage)?;
        recheck_issuing_client(&txn, &command.authority).await?;
        lock_user_credentials(&txn, command.user_oid)
            .await
            .map_err(storage)?;
        let Some(model) = UserEntity::find()
            .filter(UserColumn::Oid.eq(Uuid::from(command.user_oid)))
            .lock_exclusive()
            .one(&txn)
            .await
            .map_err(storage)?
        else {
            return Ok(UserManagementMutationOutcome::UserNotFound);
        };
        recheck_authority(
            &txn,
            &command.authority,
            ManagementScope::UsersWrite,
            Some(command.user_oid),
        )
        .await?;
        lock_account_sessions(&txn, model.id)
            .await
            .map_err(storage)?;
        let targets: Vec<Uuid> = match &command.sessions {
            Some(sessions) => {
                let rows = txn
                    .query_all_raw(Statement::from_sql_and_values(
                        DbBackend::Postgres,
                        "SELECT oid FROM session WHERE user_id = $1 AND oid = ANY($2) \
                         AND status = 'active' AND revoked_at IS NULL",
                        [model.id.into(), sessions.clone().into()],
                    ))
                    .await
                    .map_err(storage)?;
                if rows.len() != sessions.len() {
                    return Ok(UserManagementMutationOutcome::SessionNotFound);
                }
                sessions.clone()
            }
            None => txn
                .query_all_raw(Statement::from_sql_and_values(
                    DbBackend::Postgres,
                    "SELECT oid FROM session WHERE user_id = $1 AND status = 'active' AND revoked_at IS NULL",
                    [model.id.into()],
                ))
                .await
                .map_err(storage)?
                .into_iter()
                .map(|row| row.try_get::<Uuid>("", "oid"))
                .collect::<Result<_, _>>()
                .map_err(storage)?,
        };
        if !targets.is_empty() {
            txn.execute_raw(Statement::from_sql_and_values(
                DbBackend::Postgres,
                "UPDATE session SET status = 'revoked', revoked_at = now(), updated_at = now() WHERE oid = ANY($1)",
                [targets.clone().into()],
            ))
            .await
            .map_err(storage)?;
            txn.execute_raw(Statement::from_sql_and_values(
                DbBackend::Postgres,
                "DELETE FROM authentication_challenge WHERE session_id IN (SELECT id FROM session WHERE oid = ANY($1))",
                [targets.clone().into()],
            ))
            .await
            .map_err(storage)?;
            let texts: Vec<String> = targets.iter().map(Uuid::to_string).collect();
            txn.execute_raw(Statement::from_sql_and_values(
                DbBackend::Postgres,
                "UPDATE client_authorization SET revoked_at = now(), updated_at = now() \
                 WHERE revoked_at IS NULL AND type IN ('authorization_code', 'access_token', 'refresh_token') \
                 AND data->>'session_oid' = ANY($1)",
                [texts.into()],
            ))
            .await
            .map_err(storage)?;
        }
        append_semantic_audit(
            &txn,
            &command.authority,
            AuditRecord::success(AuditAction::UserSessionRevoke, Uuid::from(command.user_oid))
                .label(model.name.clone()),
        )
        .await?;
        let user = to_domain(model).map_err(map_domain_user)?;
        txn.commit().await.map_err(storage)?;
        Ok(UserManagementMutationOutcome::Success(Box::new(
            UserManagementRecord::new(user),
        )))
    }

    #[tracing::instrument(skip_all, name = "db.query", fields(db.system = "postgresql", db.operation = "user_management.delete"))]
    async fn delete_user(
        &self,
        command: UserStateTransaction,
    ) -> Result<UserManagementMutationOutcome, UserManagementRepositoryError> {
        let (txn, model) = match self.begin_user_write(&command).await? {
            Ok(locked) => locked,
            Err(outcome) => return Ok(outcome),
        };
        if model.enabled {
            return Ok(UserManagementMutationOutcome::NotDisabled);
        }
        invalidate_access_in_txn(&txn, command.user_oid, model.id).await?;
        // Grants this user made to others stay; only the granter is dropped.
        for table in ["user_role", "group_membership", "group_role"] {
            txn.execute_raw(Statement::from_sql_and_values(
                DbBackend::Postgres,
                format!(
                    "UPDATE {table} SET granted_by_user_id = NULL WHERE granted_by_user_id = $1"
                ),
                [model.id.into()],
            ))
            .await
            .map_err(storage)?;
        }
        for table in ["user_role", "group_membership"] {
            txn.execute_raw(Statement::from_sql_and_values(
                DbBackend::Postgres,
                format!("DELETE FROM {table} WHERE user_id = $1"),
                [model.id.into()],
            ))
            .await
            .map_err(storage)?;
        }
        append_semantic_audit(
            &txn,
            &command.authority,
            AuditRecord::success(AuditAction::UserDelete, Uuid::from(command.user_oid))
                .label(model.name.clone()),
        )
        .await?;
        UserEntity::delete_by_id(model.id)
            .exec(&txn)
            .await
            .map_err(storage)?;
        if let Err(error) = ensure_recoverable_authorization_administrator(&txn).await {
            if matches!(&error, DbErr::Custom(message) if message == "no recoverable authorization administrator remains")
            {
                return Ok(UserManagementMutationOutcome::LastOwnerProtected);
            }
            return Err(storage(error));
        }
        let user = to_domain(model).map_err(map_domain_user)?;
        txn.commit().await.map_err(storage)?;
        Ok(UserManagementMutationOutcome::Success(Box::new(
            UserManagementRecord::new(user),
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::escape_like;

    #[test]
    fn search_terms_treat_sql_wildcards_literally() {
        assert_eq!(escape_like("100%_done"), "100\\%\\_done");
        assert_eq!(escape_like("a\\b"), "a\\\\b");
        assert_eq!(escape_like("ada"), "ada");
    }
}
