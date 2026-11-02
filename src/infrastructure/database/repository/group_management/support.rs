//! Shared SQL, mapping and keyset helpers for group management.

use chrono::{DateTime, FixedOffset, Utc};
use identity_application::rbac::{
    GroupEntityKind, GroupManagementRepositoryError,
    cursor::{RbacPageDirection, RbacSortKey, RbacTie},
};
use identity_domain::rbac::LocalizedText;
use sea_orm::{DbErr, Value};
use serde_json::Value as JsonValue;

use super::super::localized::{self, LocalizedJsonError};

pub(crate) fn storage(error: DbErr) -> GroupManagementRepositoryError {
    GroupManagementRepositoryError::Storage(Box::new(error))
}

pub(crate) fn corrupt() -> GroupManagementRepositoryError {
    GroupManagementRepositoryError::CorruptRecord
}

pub(crate) fn not_found(kind: GroupEntityKind) -> GroupManagementRepositoryError {
    GroupManagementRepositoryError::NotFound(kind)
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

fn localized_error(_error: LocalizedJsonError) -> GroupManagementRepositoryError {
    corrupt()
}

pub(crate) fn parse_localized(
    value: JsonValue,
) -> Result<Vec<LocalizedText>, GroupManagementRepositoryError> {
    localized::decode_text(value).map_err(localized_error)
}

pub(crate) fn localized_json(
    entries: &[LocalizedText],
) -> Result<JsonValue, GroupManagementRepositoryError> {
    Ok(localized::encode_text(entries))
}
