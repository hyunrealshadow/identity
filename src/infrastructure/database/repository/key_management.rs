//! Transactional persistence for instance key management.
//!
//! Reads project key rows into metadata and drop the key material right away.
//! Writes re-check live management authority, take the same advisory lock as
//! scheduled rotation, re-check the key's lifecycle state under a row lock and
//! append the semantic audit record before committing.

use std::collections::HashMap;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use identity_application::{
    key::management::{
        CreateKeyTransaction, KeyManagementRepository, KeyManagementRepositoryError,
        KeyRotationResult, ManagedKeyFilter, ManagedKeyPageData, ManagedKeyQuery, ManagedKeyRecord,
        ManagedKeyStatus, ManagedKeyUse, RevokeKeyTransaction, RotateKeyTransaction,
    },
    rbac::{RbacManagementRepositoryError, cursor::RbacPageDirection},
};
use identity_domain::{
    authorization::ManagementScope,
    key::{JwkAlgorithm, Key, KeyData, KeyOid, KeyType, SymmetricKeyAlgorithm},
};
use sea_orm::{
    ColumnTrait, Condition, ConnectionTrait, DatabaseConnection, EntityTrait, PaginatorTrait,
    QueryFilter, QueryOrder, QuerySelect, TransactionTrait, sea_query::Expr,
};
use uuid::Uuid;

use super::{
    key::to_domain,
    key_rotation::{KEY_ROTATION_LOCK, insert_key, insert_successor},
    rbac_management::{audit::append_semantic_audit, authority::recheck_authority},
};
use crate::database::{
    entity::{
        key,
        key::{Column as KeyColumn, Entity as KeyEntity},
        key_jwk::{Column as KeyJwkColumn, Entity as KeyJwkEntity},
    },
    query::advisory_transaction_lock,
};

pub struct KeyManagementRepositoryImpl {
    db: DatabaseConnection,
}

impl KeyManagementRepositoryImpl {
    #[must_use]
    pub fn new(db: DatabaseConnection) -> Self {
        Self { db }
    }
}

fn storage(error: impl std::error::Error + Send + Sync + 'static) -> KeyManagementRepositoryError {
    KeyManagementRepositoryError::Storage(Box::new(error))
}

fn from_management(error: RbacManagementRepositoryError) -> KeyManagementRepositoryError {
    use KeyManagementRepositoryError as Key;
    use RbacManagementRepositoryError as Shared;
    match error {
        Shared::Authorization(source) => Key::Authorization(source),
        Shared::AuditFailed(source) => Key::AuditFailed(source),
        Shared::LastRecoverableAdministrator => Key::LastRecoverableAdministrator,
        other => Key::Storage(Box::new(other)),
    }
}

fn key_use(model: &key::Model) -> Result<ManagedKeyUse, KeyManagementRepositoryError> {
    let key_type = model.r#type.parse::<KeyType>().map_err(storage)?;
    Ok(ManagedKeyUse::from_key_type(&key_type))
}

fn status(model: &key::Model, now: DateTime<Utc>) -> ManagedKeyStatus {
    ManagedKeyStatus::of(
        now,
        Some(model.expires_at.to_utc()),
        model.rotated_at.map(|value| value.to_utc()),
        model.revoked_at.map(|value| value.to_utc()),
    )
}

fn symmetric_algorithm_name(algorithm: SymmetricKeyAlgorithm) -> &'static str {
    match algorithm {
        SymmetricKeyAlgorithm::Aes256Gcm => "AES-256-GCM",
        SymmetricKeyAlgorithm::XChaCha20Poly1305 => "XChaCha20-Poly1305",
    }
}

/// Builds metadata for `models`, loading the JWK bindings of signing keys.
/// Key material is decoded only to read its algorithm and certificate flag.
async fn records<C: ConnectionTrait>(
    db: &C,
    models: Vec<key::Model>,
) -> Result<Vec<ManagedKeyRecord>, KeyManagementRepositoryError> {
    let oids = models.iter().map(|model| model.oid).collect::<Vec<_>>();
    let mut bindings: HashMap<Uuid, Vec<(String, Uuid)>> = HashMap::new();
    if !oids.is_empty() {
        let rows = KeyJwkEntity::find()
            .filter(KeyJwkColumn::KeyOid.is_in(oids))
            .order_by_asc(KeyJwkColumn::Algorithm)
            .order_by_asc(KeyJwkColumn::Oid)
            .all(db)
            .await
            .map_err(storage)?;
        for row in rows {
            bindings
                .entry(row.key_oid)
                .or_default()
                .push((row.algorithm, row.oid));
        }
    }

    models
        .into_iter()
        .map(|model| {
            let key_use = key_use(&model)?;
            let data: KeyData = serde_json::from_value(model.data).map_err(storage)?;
            let (algorithms, key_ids, has_certificate) = match data {
                KeyData::Symmetric(data) => (
                    vec![symmetric_algorithm_name(data.algorithm).to_owned()],
                    Vec::new(),
                    false,
                ),
                KeyData::Asymmetric(data) => {
                    let mut bound = bindings.remove(&model.oid).unwrap_or_default();
                    // Signing bindings first: they identify the key in tokens.
                    bound.sort_by_key(|(algorithm, oid)| {
                        let signing = matches!(
                            algorithm.parse::<JwkAlgorithm>(),
                            Ok(JwkAlgorithm::Signing(_))
                        );
                        (!signing, algorithm.clone(), *oid)
                    });
                    let mut algorithms = Vec::new();
                    for (algorithm, _) in &bound {
                        if !algorithms.contains(algorithm) {
                            algorithms.push(algorithm.clone());
                        }
                    }
                    let key_ids = bound.iter().map(|(_, oid)| oid.to_string()).collect();
                    (algorithms, key_ids, data.certificate.is_some())
                }
            };
            Ok(ManagedKeyRecord {
                oid: KeyOid(model.oid),
                key_use,
                algorithms,
                key_ids,
                has_certificate,
                rotated_from: model.rotated_from_oid.map(KeyOid),
                created_at: model.created_at.to_utc(),
                expires_at: Some(model.expires_at.to_utc()),
                rotated_at: model.rotated_at.map(|value| value.to_utc()),
                revoked_at: model.revoked_at.map(|value| value.to_utc()),
            })
        })
        .collect()
}

async fn find_record<C: ConnectionTrait>(
    db: &C,
    oid: Uuid,
) -> Result<ManagedKeyRecord, KeyManagementRepositoryError> {
    let model = KeyEntity::find()
        .filter(KeyColumn::Oid.eq(oid))
        .one(db)
        .await
        .map_err(storage)?
        .ok_or(KeyManagementRepositoryError::NotFound)?;
    records(db, vec![model])
        .await?
        .pop()
        .ok_or(KeyManagementRepositoryError::NotFound)
}

fn status_condition(status: ManagedKeyStatus, now: DateTime<Utc>) -> Condition {
    let now = now.fixed_offset();
    match status {
        ManagedKeyStatus::Revoked => Condition::all().add(KeyColumn::RevokedAt.is_not_null()),
        ManagedKeyStatus::Expired => Condition::all()
            .add(KeyColumn::RevokedAt.is_null())
            .add(KeyColumn::ExpiresAt.lte(now)),
        ManagedKeyStatus::Retired => Condition::all()
            .add(KeyColumn::RevokedAt.is_null())
            .add(KeyColumn::ExpiresAt.gt(now))
            .add(KeyColumn::RotatedAt.is_not_null()),
        ManagedKeyStatus::Active => Condition::all()
            .add(KeyColumn::RevokedAt.is_null())
            .add(KeyColumn::ExpiresAt.gt(now))
            .add(KeyColumn::RotatedAt.is_null()),
    }
}

/// Keyset predicate for the `(created_at DESC, oid DESC)` order.
fn position_condition(created_at: DateTime<Utc>, oid: Uuid, older: bool) -> Condition {
    let created_at = created_at.fixed_offset();
    if older {
        Condition::any()
            .add(KeyColumn::CreatedAt.lt(created_at))
            .add(
                Condition::all()
                    .add(KeyColumn::CreatedAt.eq(created_at))
                    .add(KeyColumn::Oid.lt(oid)),
            )
    } else {
        Condition::any()
            .add(KeyColumn::CreatedAt.gt(created_at))
            .add(
                Condition::all()
                    .add(KeyColumn::CreatedAt.eq(created_at))
                    .add(KeyColumn::Oid.gt(oid)),
            )
    }
}

/// Locks one key row for a lifecycle change.
async fn lock_key<C: ConnectionTrait>(
    txn: &C,
    oid: KeyOid,
) -> Result<key::Model, KeyManagementRepositoryError> {
    KeyEntity::find()
        .filter(KeyColumn::Oid.eq(Uuid::from(oid)))
        .lock_exclusive()
        .one(txn)
        .await
        .map_err(storage)?
        .ok_or(KeyManagementRepositoryError::NotFound)
}

fn filter_condition(filter: &ManagedKeyFilter, now: DateTime<Utc>) -> Condition {
    let mut condition = Condition::all();
    if let Some(key_use) = filter.key_use {
        condition = condition.add(KeyColumn::Type.eq(key_use.key_type().to_string()));
    }
    if !filter.statuses.is_empty() {
        let mut any = Condition::any();
        for status in &filter.statuses {
            any = any.add(status_condition(*status, now));
        }
        condition = condition.add(any);
    }
    condition
}

#[async_trait]
impl KeyManagementRepository for KeyManagementRepositoryImpl {
    #[tracing::instrument(skip_all, name = "db.query", fields(db.system = "postgresql", db.operation = "count_managed_keys"))]
    async fn count(
        &self,
        filter: ManagedKeyFilter,
        now: DateTime<Utc>,
    ) -> Result<u64, KeyManagementRepositoryError> {
        KeyEntity::find()
            .filter(filter_condition(&filter, now))
            .count(&self.db)
            .await
            .map_err(storage)
    }

    #[tracing::instrument(skip_all, name = "db.query", fields(db.system = "postgresql", db.operation = "list_managed_keys"))]
    async fn list(
        &self,
        query: ManagedKeyQuery,
    ) -> Result<ManagedKeyPageData, KeyManagementRepositoryError> {
        let mut select = KeyEntity::find().filter(filter_condition(&query.filter, query.now));
        let backward = query.direction == RbacPageDirection::Backward;
        if let Some((created_at, oid)) = query.after {
            select = select.filter(position_condition(created_at, oid, true));
        }
        if let Some((created_at, oid)) = query.before {
            select = select.filter(position_condition(created_at, oid, false));
        }
        select = if backward {
            select
                .order_by_asc(KeyColumn::CreatedAt)
                .order_by_asc(KeyColumn::Oid)
        } else {
            select
                .order_by_desc(KeyColumn::CreatedAt)
                .order_by_desc(KeyColumn::Oid)
        };
        let mut models = select
            .limit(query.limit as u64 + 1)
            .all(&self.db)
            .await
            .map_err(storage)?;
        let has_more = models.len() > query.limit;
        models.truncate(query.limit);
        if backward {
            models.reverse();
        }
        let (has_previous_page, has_next_page) = if backward {
            (has_more, query.before.is_some())
        } else {
            (query.after.is_some(), has_more)
        };
        Ok(ManagedKeyPageData {
            items: records(&self.db, models).await?,
            has_previous_page,
            has_next_page,
        })
    }

    #[tracing::instrument(skip_all, name = "db.query", fields(db.system = "postgresql", db.operation = "find_managed_key"))]
    async fn find(
        &self,
        oid: KeyOid,
    ) -> Result<Option<ManagedKeyRecord>, KeyManagementRepositoryError> {
        match find_record(&self.db, Uuid::from(oid)).await {
            Ok(record) => Ok(Some(record)),
            Err(KeyManagementRepositoryError::NotFound) => Ok(None),
            Err(error) => Err(error),
        }
    }

    #[tracing::instrument(skip_all, name = "db.query", fields(db.system = "postgresql", db.operation = "find_key_material"))]
    async fn find_material(
        &self,
        oid: KeyOid,
    ) -> Result<Option<Key>, KeyManagementRepositoryError> {
        KeyEntity::find()
            .filter(KeyColumn::Oid.eq(Uuid::from(oid)))
            .one(&self.db)
            .await
            .map_err(storage)?
            .map(|model| to_domain(model).map_err(storage))
            .transpose()
    }

    #[tracing::instrument(skip_all, name = "db.transaction", fields(db.system = "postgresql", db.operation = "rotate_key"))]
    async fn rotate(
        &self,
        transaction: RotateKeyTransaction,
    ) -> Result<KeyRotationResult, KeyManagementRepositoryError> {
        let RotateKeyTransaction {
            authority,
            key_oid,
            material,
            revoke_previous,
            now,
        } = transaction;
        let txn = self.db.begin().await.map_err(storage)?;
        recheck_authority(&txn, &authority, ManagementScope::KeysRotate, None)
            .await
            .map_err(from_management)?;
        if revoke_previous {
            recheck_authority(&txn, &authority, ManagementScope::KeysRevoke, None)
                .await
                .map_err(from_management)?;
        }
        txn.execute(&advisory_transaction_lock(KEY_ROTATION_LOCK))
            .await
            .map_err(storage)?;
        let previous = lock_key(&txn, key_oid).await?;
        if status(&previous, now) != ManagedKeyStatus::Active {
            return Err(KeyManagementRepositoryError::NotActive);
        }
        let key_type = previous.r#type.parse::<KeyType>().map_err(storage)?;
        let material_matches = material.data.key_type() == key_type
            && (key_type == KeyType::Asymmetric || material.jwks.is_empty());
        if !material_matches {
            return Err(storage(sea_orm::DbErr::Custom(
                "rotation material does not match the key type".to_owned(),
            )));
        }
        let successor_oid = insert_successor(&txn, &previous, material, now)
            .await
            .map_err(storage)?;
        append_semantic_audit(&txn, &authority, "key.rotate", "key", previous.oid, "")
            .await
            .map_err(from_management)?;
        if revoke_previous {
            KeyEntity::update_many()
                .col_expr(KeyColumn::RevokedAt, Expr::value(Some(now.fixed_offset())))
                .col_expr(KeyColumn::UpdatedAt, Expr::value(Some(now.fixed_offset())))
                .filter(KeyColumn::Id.eq(previous.id))
                .exec(&txn)
                .await
                .map_err(storage)?;
            append_semantic_audit(&txn, &authority, "key.revoke", "key", previous.oid, "")
                .await
                .map_err(from_management)?;
        }
        let previous_record = find_record(&txn, previous.oid).await?;
        let successor = find_record(&txn, successor_oid).await?;
        txn.commit().await.map_err(storage)?;
        Ok(KeyRotationResult {
            previous: previous_record,
            successor,
        })
    }

    #[tracing::instrument(skip_all, name = "db.transaction", fields(db.system = "postgresql", db.operation = "create_key"))]
    async fn create(
        &self,
        transaction: CreateKeyTransaction,
    ) -> Result<ManagedKeyRecord, KeyManagementRepositoryError> {
        let CreateKeyTransaction {
            authority,
            data,
            jwks,
            now,
        } = transaction;
        let txn = self.db.begin().await.map_err(storage)?;
        recheck_authority(&txn, &authority, ManagementScope::KeysCreate, None)
            .await
            .map_err(from_management)?;
        txn.execute(&advisory_transaction_lock(KEY_ROTATION_LOCK))
            .await
            .map_err(storage)?;
        let key_type = data.key_type().to_string();
        let oid = insert_key(&txn, &key_type, data, jwks, None, now)
            .await
            .map_err(storage)?;
        append_semantic_audit(&txn, &authority, "key.create", "key", oid, "")
            .await
            .map_err(from_management)?;
        let record = find_record(&txn, oid).await?;
        txn.commit().await.map_err(storage)?;
        Ok(record)
    }

    #[tracing::instrument(skip_all, name = "db.transaction", fields(db.system = "postgresql", db.operation = "revoke_key"))]
    async fn revoke(
        &self,
        transaction: RevokeKeyTransaction,
    ) -> Result<ManagedKeyRecord, KeyManagementRepositoryError> {
        let RevokeKeyTransaction {
            authority,
            key_oid,
            now,
        } = transaction;
        let txn = self.db.begin().await.map_err(storage)?;
        recheck_authority(&txn, &authority, ManagementScope::KeysRevoke, None)
            .await
            .map_err(from_management)?;
        txn.execute(&advisory_transaction_lock(KEY_ROTATION_LOCK))
            .await
            .map_err(storage)?;
        let current = lock_key(&txn, key_oid).await?;
        match status(&current, now) {
            ManagedKeyStatus::Revoked => return Err(KeyManagementRepositoryError::AlreadyRevoked),
            // Every use keeps at least one active key.
            ManagedKeyStatus::Active => {
                let others = KeyEntity::find()
                    .filter(KeyColumn::Type.eq(current.r#type.clone()))
                    .filter(KeyColumn::Id.ne(current.id))
                    .filter(status_condition(ManagedKeyStatus::Active, now))
                    .count(&txn)
                    .await
                    .map_err(storage)?;
                if others == 0 {
                    return Err(KeyManagementRepositoryError::LastActiveKey);
                }
            }
            ManagedKeyStatus::Retired | ManagedKeyStatus::Expired => {}
        }
        KeyEntity::update_many()
            .col_expr(KeyColumn::RevokedAt, Expr::value(Some(now.fixed_offset())))
            .col_expr(KeyColumn::UpdatedAt, Expr::value(Some(now.fixed_offset())))
            .filter(KeyColumn::Id.eq(current.id))
            .exec(&txn)
            .await
            .map_err(storage)?;
        append_semantic_audit(&txn, &authority, "key.revoke", "key", current.oid, "")
            .await
            .map_err(from_management)?;
        let record = find_record(&txn, current.oid).await?;
        txn.commit().await.map_err(storage)?;
        Ok(record)
    }
}
