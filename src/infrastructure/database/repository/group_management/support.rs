//! Shared SQL, mapping and keyset helpers for group management.

use identity_application::rbac::{GroupEntityKind, GroupManagementRepositoryError};
use identity_domain::rbac::LocalizedText;
use sea_orm::DbErr;
use serde_json::Value as JsonValue;

use super::super::localized::{self, LocalizedJsonError};
pub(crate) use super::super::sql_support::{
    Binds, CursorComparison, escape_like, keyset_condition, order_is_descending, page_flags, utc,
};

pub(crate) fn storage(error: DbErr) -> GroupManagementRepositoryError {
    GroupManagementRepositoryError::Storage(Box::new(error))
}

pub(crate) fn corrupt() -> GroupManagementRepositoryError {
    GroupManagementRepositoryError::CorruptRecord
}

pub(crate) fn not_found(kind: GroupEntityKind) -> GroupManagementRepositoryError {
    GroupManagementRepositoryError::NotFound(kind)
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
