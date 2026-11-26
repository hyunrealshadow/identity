//! Shared SQL bind, keyset pagination, and LIKE-escaping helpers for repositories.

use chrono::{DateTime, FixedOffset, Utc};
use identity_application::rbac::cursor::{RbacPageDirection, RbacSortKey, RbacTie};
use sea_orm::Value;

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
    direction.order_is_descending(order_descending)
}

#[must_use]
pub(crate) fn page_flags(
    direction: RbacPageDirection,
    has_more: bool,
    after_present: bool,
    before_present: bool,
) -> (bool, bool) {
    direction.page_flags(has_more, after_present, before_present)
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
