//! Shared SQL, mapping and keyset helpers for unified RBAC management.

use chrono::{DateTime, FixedOffset, Utc};
use identity_application::rbac::{
    RbacEntityKind, RbacManagementRepositoryError, ScopeDescription,
    cursor::{RbacPageDirection, RbacSortKey, RbacTie},
};
use identity_domain::rbac::{LocalizedMetadata, LocalizedText};
use sea_orm::{ConnectionTrait, DatabaseTransaction, DbBackend, DbErr, Statement, Value};
use serde_json::Value as JsonValue;
use uuid::Uuid;

use super::super::{
    authorization_lifecycle,
    localized::{self, LocalizedJsonError},
};

pub(crate) fn storage(error: DbErr) -> RbacManagementRepositoryError {
    RbacManagementRepositoryError::Storage(Box::new(error))
}

pub(crate) fn corrupt() -> RbacManagementRepositoryError {
    RbacManagementRepositoryError::CorruptRecord
}

pub(crate) fn not_found(kind: RbacEntityKind) -> RbacManagementRepositoryError {
    RbacManagementRepositoryError::NotFound(kind)
}

#[derive(Default)]
pub(crate) struct Binds {
    values: Vec<Value>,
}

impl Binds {
    pub(crate) fn new() -> Self {
        Self::default()
    }

    pub(crate) fn push<T: Into<Value>>(&mut self, value: T) -> String {
        self.values.push(value.into());
        format!("${}", self.values.len())
    }

    pub(crate) fn into_values(self) -> Vec<Value> {
        self.values
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum CursorComparison {
    After,
    Before,
}

#[must_use]
pub(crate) fn order_is_descending(order_descending: bool, direction: RbacPageDirection) -> bool {
    match direction {
        RbacPageDirection::Forward => order_descending,
        RbacPageDirection::Backward => !order_descending,
    }
}

#[must_use]
pub(crate) fn page_flags(
    direction: RbacPageDirection,
    has_more: bool,
    after_present: bool,
    before_present: bool,
) -> (bool, bool) {
    match direction {
        RbacPageDirection::Forward => (after_present, has_more),
        RbacPageDirection::Backward => (has_more, before_present),
    }
}

/// Build the stable `(sort column, unique tie-breaker)` keyset predicate.
///
/// `column` and `tie_expr` are compile-time SQL fragments chosen from a closed
/// whitelist; values are always bound.
pub(crate) fn keyset_condition(
    column: &str,
    tie_expr: &str,
    key: &RbacSortKey,
    comparison: CursorComparison,
    ascending: bool,
    binds: &mut Binds,
) -> String {
    let (value_placeholder, equal_placeholder, tie_placeholder) = match key {
        RbacSortKey::CreatedAt { created_at, tie } => {
            let value = created_at.fixed_offset();
            let first = binds.push(value);
            let second = binds.push(value);
            let tie = push_tie(binds, tie);
            (first, second, tie)
        }
        RbacSortKey::Text { value, tie } => {
            let first = binds.push(value.clone());
            let second = binds.push(value.clone());
            let tie = push_tie(binds, tie);
            (first, second, tie)
        }
    };
    let after = matches!(comparison, CursorComparison::After);
    let (operator, tie_operator) = if after == ascending {
        (">", ">")
    } else {
        ("<", "<")
    };
    format!(
        "({column} {operator} {value_placeholder} OR ({column} = {equal_placeholder} AND {tie_expr} {tie_operator} {tie_placeholder}))"
    )
}

fn push_tie(binds: &mut Binds, tie: &RbacTie) -> String {
    match tie {
        RbacTie::Id(id) => binds.push(*id),
        RbacTie::Oid(oid) => binds.push(*oid),
    }
}

#[must_use]
pub(crate) fn escape_like(value: &str) -> String {
    value
        .replace('\\', "\\\\")
        .replace('%', "\\%")
        .replace('_', "\\_")
}

#[must_use]
pub(crate) fn utc(value: DateTime<FixedOffset>) -> DateTime<Utc> {
    value.with_timezone(&Utc)
}

pub(crate) fn parse_scope_names(
    value: JsonValue,
) -> Result<Vec<String>, RbacManagementRepositoryError> {
    let values = value.as_array().ok_or_else(corrupt)?;
    values
        .iter()
        .map(|value| value.as_str().map(str::to_owned).ok_or_else(corrupt))
        .collect()
}

fn localized_error(_error: LocalizedJsonError) -> RbacManagementRepositoryError {
    corrupt()
}

pub(crate) fn parse_localized_metadata(
    names: JsonValue,
    descriptions: JsonValue,
) -> Result<LocalizedMetadata, RbacManagementRepositoryError> {
    localized::decode_metadata(names, descriptions).map_err(localized_error)
}

/// `(names, descriptions, scalar name, scalar description)`.
pub(crate) fn metadata_json(metadata: &LocalizedMetadata) -> (JsonValue, JsonValue) {
    localized::encode_metadata(metadata)
}

pub(crate) fn scope_descriptions(entries: &[LocalizedText]) -> Vec<ScopeDescription> {
    entries
        .iter()
        .map(|entry| ScopeDescription {
            locale: entry.locale.clone(),
            value: entry.value.clone(),
        })
        .collect()
}

/// Permanently withdraw users whose effective authority includes a scope.
///
/// Scope enable/disable is a real authority change. The row's UUID version and
/// the durable withdrawal marker prevent an enable/disable/enable cycle from
/// reviving an older credential.
pub(crate) async fn withdraw_users_affected_by_scope(
    txn: &DatabaseTransaction,
    scope_id: i64,
) -> Result<(), RbacManagementRepositoryError> {
    let rows = txn
        .query_all_raw(Statement::from_sql_and_values(
            DbBackend::Postgres,
            r#"
SELECT user_id FROM (
    SELECT binding.user_id
    FROM user_role binding
    JOIN role_permission relation ON relation.role_id = binding.role_id
    WHERE binding.enabled = true
      AND binding.revoked_at IS NULL
      AND relation.scope_id = $1
    UNION
    SELECT membership.user_id
    FROM group_membership membership
    JOIN user_group group_row
      ON group_row.id = membership.group_id
     AND group_row.enabled = true
     AND group_row.deleted_at IS NULL
    JOIN group_role group_relation
      ON group_relation.group_id = group_row.id
     AND group_relation.enabled = true
     AND group_relation.revoked_at IS NULL
    JOIN role_permission relation ON relation.role_id = group_relation.role_id
    WHERE membership.enabled = true
      AND membership.revoked_at IS NULL
      AND relation.scope_id = $1
) affected
ORDER BY user_id
"#,
            [scope_id.into()],
        ))
        .await
        .map_err(storage)?;
    for row in rows {
        let user_id = row.try_get::<i64>("", "user_id").map_err(storage)?;
        authorization_lifecycle::withdraw_user_authority_in_txn(txn, user_id)
            .await
            .map_err(storage)?;
    }
    Ok(())
}

/// Permanently withdraw users whose effective authority includes any scope of a
/// resource. Used for resource enable/disable.
pub(crate) async fn withdraw_users_affected_by_resource(
    txn: &DatabaseTransaction,
    resource_oid: Uuid,
) -> Result<(), RbacManagementRepositoryError> {
    let rows = txn
        .query_all_raw(Statement::from_sql_and_values(
            DbBackend::Postgres,
            r#"
SELECT user_id FROM (
    SELECT binding.user_id
    FROM user_role binding
    JOIN role_permission relation ON relation.role_id = binding.role_id
    JOIN scope scope_row ON scope_row.id = relation.scope_id
    WHERE binding.enabled = true
      AND binding.revoked_at IS NULL
      AND scope_row.resource_id = $1
    UNION
    SELECT membership.user_id
    FROM group_membership membership
    JOIN user_group group_row
      ON group_row.id = membership.group_id
     AND group_row.enabled = true
     AND group_row.deleted_at IS NULL
    JOIN group_role group_relation
      ON group_relation.group_id = group_row.id
     AND group_relation.enabled = true
     AND group_relation.revoked_at IS NULL
    JOIN role_permission relation ON relation.role_id = group_relation.role_id
    JOIN scope scope_row ON scope_row.id = relation.scope_id
    WHERE membership.enabled = true
      AND membership.revoked_at IS NULL
      AND scope_row.resource_id = $1
) affected
ORDER BY user_id
"#,
            [resource_oid.into()],
        ))
        .await
        .map_err(storage)?;
    for row in rows {
        let user_id = row.try_get::<i64>("", "user_id").map_err(storage)?;
        authorization_lifecycle::withdraw_user_authority_in_txn(txn, user_id)
            .await
            .map_err(storage)?;
    }
    Ok(())
}
