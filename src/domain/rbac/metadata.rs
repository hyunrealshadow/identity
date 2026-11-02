//! Canonical localized display metadata for groups, roles, permissions and
//! scopes.
//!
//! Display text is resource data: it is persisted as a locale-to-string object
//! map, validated on the server and projected deterministically. It never
//! participates in permission identity, built-in classification or
//! authorization versions.
//!
//! There is no stored default locale and no server-side request-locale
//! selection. Clients choose which translation to present. The scalar
//! `name`/`description` defaults are independent text, never projections of
//! these optional translations.
//!
//! Language tags are canonicalized to a conservative BCP 47 subset without
//! depending on a locale database. The same canonical form is used for storage,
//! duplicate detection and projection so two spellings cannot create two
//! translations of the same language.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

pub const LANGUAGES: [&str; 2] = ["en-US", "zh-CN"];

pub const MAX_LOCALE_LENGTH: usize = 35;
pub const MAX_LOCALIZED_ENTRIES: usize = 20;
pub const MAX_LOCALIZED_NAME_LENGTH: usize = 256;
pub const MAX_LOCALIZED_DESCRIPTION_LENGTH: usize = 1_024;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LocalizedText {
    pub locale: String,
    pub value: String,
}

impl LocalizedText {
    #[must_use]
    pub fn new(locale: impl Into<String>, value: impl Into<String>) -> Self {
        Self {
            locale: locale.into(),
            value: value.into(),
        }
    }
}

/// Optional translated names/descriptions. Missing translations resolve to no
/// value rather than to a fabricated translation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct LocalizedMetadata {
    pub names: Vec<LocalizedText>,
    pub descriptions: Vec<LocalizedText>,
}

impl LocalizedMetadata {
    /// Build a translated name/description pair in an explicitly supplied
    /// language. This does not define independent fallback text.
    #[must_use]
    pub fn single(
        locale: impl Into<String>,
        name: impl Into<String>,
        description: impl Into<String>,
    ) -> Self {
        let locale = canonicalize_locale(&locale.into()).unwrap_or_else(|_| "en-US".to_owned());
        let name = name.into();
        let description = description.into();
        let descriptions = if description.trim().is_empty() {
            Vec::new()
        } else {
            vec![LocalizedText::new(locale.clone(), description)]
        };
        Self {
            names: vec![LocalizedText::new(locale, name)],
            descriptions,
        }
    }

    /// Validate and canonicalize metadata supplied by an application command.
    ///
    /// Entries are sorted by canonical locale, duplicate locales are rejected
    /// and every supplied name must be non-empty. Empty
    /// description entries are dropped because they carry no display text.
    pub fn canonicalize(
        names: Vec<LocalizedText>,
        descriptions: Vec<LocalizedText>,
    ) -> Result<Self, LocalizedTextError> {
        Ok(Self {
            names: Self::canonicalize_names(names)?,
            descriptions: Self::canonicalize_descriptions(descriptions)?,
        })
    }

    /// Validate a supplied names replacement independently of descriptions.
    pub fn canonicalize_names(
        names: Vec<LocalizedText>,
    ) -> Result<Vec<LocalizedText>, LocalizedTextError> {
        if names.len() > MAX_LOCALIZED_ENTRIES {
            return Err(LocalizedTextError::TooManyEntries {
                field: "names",
                max: MAX_LOCALIZED_ENTRIES,
            });
        }
        let names = canonicalize_entries(names, MAX_LOCALIZED_NAME_LENGTH, true)?;
        Ok(names)
    }

    /// Validate a supplied descriptions replacement; an empty list clears it.
    pub fn canonicalize_descriptions(
        descriptions: Vec<LocalizedText>,
    ) -> Result<Vec<LocalizedText>, LocalizedTextError> {
        if descriptions.len() > MAX_LOCALIZED_ENTRIES {
            return Err(LocalizedTextError::TooManyEntries {
                field: "descriptions",
                max: MAX_LOCALIZED_ENTRIES,
            });
        }
        canonicalize_entries(descriptions, MAX_LOCALIZED_DESCRIPTION_LENGTH, false)
    }

    /// Replace all display text, preserving the previous metadata if the new
    /// value is invalid.
    pub fn update(
        &mut self,
        names: Vec<LocalizedText>,
        descriptions: Vec<LocalizedText>,
    ) -> Result<(), LocalizedTextError> {
        let next = Self::canonicalize(names, descriptions)?;
        *self = next;
        Ok(())
    }

    /// Deterministic projection for trusted preset initialization.
    ///
    /// English is preferred; otherwise the first canonical locale is used. This
    /// is not per-request localization and never accepts a locale argument.
    #[must_use]
    pub fn base_name(&self) -> Option<&str> {
        base_projection(&self.names)
    }

    /// Deterministic scalar description projection.
    #[must_use]
    pub fn base_description(&self) -> Option<&str> {
        base_projection(&self.descriptions)
    }
}

fn base_projection(entries: &[LocalizedText]) -> Option<&str> {
    if let Some(english) = entries
        .iter()
        .find(|entry| entry.locale == "en" || entry.locale.starts_with("en-"))
    {
        return Some(english.value.as_str());
    }
    entries
        .iter()
        .find(|entry| !entry.value.is_empty())
        .map(|entry| entry.value.as_str())
}

fn canonicalize_entries(
    entries: Vec<LocalizedText>,
    max_length: usize,
    name_required: bool,
) -> Result<Vec<LocalizedText>, LocalizedTextError> {
    let mut canonical: BTreeMap<String, LocalizedText> = BTreeMap::new();
    for entry in entries {
        let locale =
            canonicalize_locale(&entry.locale).map_err(|_| LocalizedTextError::InvalidLocale {
                locale: entry.locale.clone(),
            })?;
        let value = entry.value.trim();
        if name_required && value.is_empty() {
            return Err(LocalizedTextError::EmptyName {
                locale: locale.clone(),
            });
        }
        if value.chars().count() > max_length {
            return Err(LocalizedTextError::TextTooLong {
                locale,
                max: max_length,
            });
        }
        if !name_required && value.is_empty() {
            // An empty description is the absence of a translation, not a
            // stored blank value.
            continue;
        }
        if canonical.contains_key(&locale) {
            return Err(LocalizedTextError::DuplicateLocale { locale });
        }
        canonical.insert(
            locale.clone(),
            LocalizedText {
                locale,
                value: value.to_owned(),
            },
        );
    }
    Ok(canonical.into_values().collect())
}

/// Canonicalize a BCP 47 language tag to a deterministic conservative subset.
///
/// Accepted shape: language (`2..=8` ASCII letters), optional script
/// (`4` ASCII letters) and optional region (`2` letters or `3` digits),
/// optionally followed by dot-less alphanumeric extension subtags. The output
/// is `language[-Script][-REGION][-variant...]` with language/variant lower
/// case, script title case and region upper case. Underscores are accepted only
/// as separators and normalized to hyphens.
pub fn canonicalize_locale(value: &str) -> Result<String, LocalizedTextError> {
    let trimmed = value.trim().replace('_', "-");
    if trimmed.is_empty() || trimmed.len() > MAX_LOCALE_LENGTH {
        return Err(LocalizedTextError::InvalidLocale {
            locale: value.to_owned(),
        });
    }
    if trimmed.starts_with('-') || trimmed.ends_with('-') || trimmed.contains("--") {
        return Err(LocalizedTextError::InvalidLocale {
            locale: value.to_owned(),
        });
    }
    let mut subtags = trimmed.split('-');
    let language = subtags.next().unwrap_or_default();
    if !(2..=8).contains(&language.len())
        || !language.bytes().all(|byte| byte.is_ascii_alphabetic())
    {
        return Err(LocalizedTextError::InvalidLocale {
            locale: value.to_owned(),
        });
    }
    let mut parts = Vec::new();
    parts.push(language.to_ascii_lowercase());

    let mut index = 0;
    let rest: Vec<&str> = subtags.collect();
    if rest.is_empty() {
        return Ok(parts.join("-"));
    }
    if index < rest.len()
        && rest[index].len() == 4
        && rest[index].bytes().all(|byte| byte.is_ascii_alphabetic())
    {
        let script = rest[index];
        parts.push(format!(
            "{}{}",
            script[..1].to_ascii_uppercase(),
            script[1..].to_ascii_lowercase()
        ));
        index += 1;
    }
    if index < rest.len() {
        let region = rest[index];
        if (region.len() == 2 && region.bytes().all(|byte| byte.is_ascii_alphabetic()))
            || (region.len() == 3 && region.bytes().all(|byte| byte.is_ascii_digit()))
        {
            parts.push(region.to_ascii_uppercase());
            index += 1;
        }
    }
    for variant in &rest[index..] {
        if variant.is_empty()
            || variant.len() > 8
            || !variant.bytes().all(|byte| byte.is_ascii_alphanumeric())
        {
            return Err(LocalizedTextError::InvalidLocale {
                locale: value.to_owned(),
            });
        }
        parts.push(variant.to_ascii_lowercase());
    }
    Ok(parts.join("-"))
}

/// Validate a canonical or user-supplied language tag without storing it.
pub fn validate_locale(value: &str) -> Result<String, LocalizedTextError> {
    canonicalize_locale(value)
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum LocalizedTextError {
    #[error("the language tag is invalid: {locale}")]
    InvalidLocale { locale: String },
    #[error("the language tag appears more than once: {locale}")]
    DuplicateLocale { locale: String },
    #[error("the name is empty: {locale}")]
    EmptyName { locale: String },
    #[error("localized text exceeds {max} characters: {locale}")]
    TextTooLong { locale: String, max: usize },
    #[error("{field} exceeds {max} entries")]
    TooManyEntries { field: &'static str, max: usize },
}

#[cfg(test)]
mod tests {
    use super::{LocalizedMetadata, LocalizedText, LocalizedTextError, canonicalize_locale};

    #[test]
    fn locale_canonicalization_is_stable() {
        assert_eq!(canonicalize_locale("zh_cn").unwrap(), "zh-CN");
        assert_eq!(canonicalize_locale("EN-us").unwrap(), "en-US");
        assert_eq!(canonicalize_locale("zh-hant-tw").unwrap(), "zh-Hant-TW");
        assert!(canonicalize_locale("zh").is_ok());
        for invalid in ["", "-", "en--US", "e", "en US", "zh-CN-"] {
            assert!(canonicalize_locale(invalid).is_err(), "{invalid}");
        }
    }

    #[test]
    fn canonicalization_rejects_duplicates_and_allows_no_translations() {
        let duplicate = LocalizedMetadata::canonicalize(
            vec![
                LocalizedText::new("en-US", "Owner"),
                LocalizedText::new("en_us", "Owner again"),
            ],
            Vec::new(),
        );
        assert!(matches!(
            duplicate,
            Err(LocalizedTextError::DuplicateLocale { .. })
        ));

        let missing = LocalizedMetadata::canonicalize(Vec::new(), Vec::new());
        assert!(missing.unwrap().names.is_empty());

        let non_english = LocalizedMetadata::canonicalize(
            vec![LocalizedText::new("zh-CN", "所有者")],
            Vec::new(),
        )
        .unwrap();
        assert_eq!(non_english.base_name(), Some("所有者"));
    }

    #[test]
    fn base_projection_prefers_english_then_first_locale() {
        let metadata = LocalizedMetadata::canonicalize(
            vec![
                LocalizedText::new("zh-CN", "所有者"),
                LocalizedText::new("en-US", "Owner"),
            ],
            vec![LocalizedText::new("zh-CN", "完整管理权限")],
        )
        .unwrap();

        assert_eq!(metadata.base_name(), Some("Owner"));
        assert_eq!(metadata.base_description(), Some("完整管理权限"));
        assert_eq!(metadata.names[0].locale, "en-US");
    }
}
