//! Persistence codec for localized display text.
//!
//! The database stores localized names and descriptions as locale-to-string
//! JSON objects (for example `{"en-US":"Users","zh-CN":"用户"}`). The domain
//! owns canonicalization and ordering; scalar defaults are stored separately. This module
//! only translates between that canonical value and the persisted object shape.
//!
//! Objects are always rebuilt in canonical locale order. No default locale is
//! stored and no request locale is consulted here.

use std::collections::BTreeMap;

use identity_domain::rbac::{
    LocalizedMetadata, LocalizedText, LocalizedTextError, canonicalize_locale,
};
use serde_json::{Map, Value};

#[derive(Debug, thiserror::Error)]
pub(crate) enum LocalizedJsonError {
    #[error("localized JSON must be a locale-to-string object")]
    NotObject,
    #[error(transparent)]
    Metadata(#[from] LocalizedTextError),
}

fn parse_entries(value: Value) -> Result<Vec<LocalizedText>, LocalizedJsonError> {
    let object = value.as_object().ok_or(LocalizedJsonError::NotObject)?;
    let mut entries = Vec::with_capacity(object.len());
    for (locale, value) in object {
        let value = value.as_str().ok_or(LocalizedJsonError::NotObject)?;
        entries.push(LocalizedText::new(locale.clone(), value.to_owned()));
    }
    Ok(entries)
}

/// Decode one localized collection, canonicalizing locale aliases and order.
pub(crate) fn decode_text(value: Value) -> Result<Vec<LocalizedText>, LocalizedJsonError> {
    let entries = parse_entries(value)?;
    let mut canonical = BTreeMap::new();
    for entry in entries {
        let locale = canonicalize_locale(&entry.locale)?;
        if canonical.insert(locale.clone(), entry.value).is_some() {
            return Err(LocalizedTextError::DuplicateLocale { locale }.into());
        }
    }
    Ok(canonical
        .into_iter()
        .map(|(locale, value)| LocalizedText { locale, value })
        .collect())
}

/// Decode and validate a complete metadata value.
pub(crate) fn decode_metadata(
    names: Value,
    descriptions: Value,
) -> Result<LocalizedMetadata, LocalizedJsonError> {
    LocalizedMetadata::canonicalize(parse_entries(names)?, parse_entries(descriptions)?)
        .map_err(Into::into)
}

/// Encode one localized collection as a deterministic JSON object.
pub(crate) fn encode_text(entries: &[LocalizedText]) -> Value {
    let mut object = Map::new();
    let mut ordered = entries.iter().collect::<Vec<_>>();
    ordered.sort_by(|left, right| left.locale.cmp(&right.locale));
    for entry in ordered {
        object.insert(entry.locale.clone(), Value::String(entry.value.clone()));
    }
    Value::Object(object)
}

/// Encode canonical metadata as deterministic `(names, descriptions)` objects.
pub(crate) fn encode_metadata(metadata: &LocalizedMetadata) -> (Value, Value) {
    (
        encode_text(&metadata.names),
        encode_text(&metadata.descriptions),
    )
}
