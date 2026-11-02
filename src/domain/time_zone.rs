//! IANA time-zone value used by profile preferences and zoned aggregates.
//!
//! The wrapper accepts only names known to the bundled IANA database. It does
//! not accept numeric UTC offsets or free-form labels, because those cannot
//! describe daylight-saving transitions for historical and future dates.

use std::fmt;

use chrono_tz::Tz;
use thiserror::Error;

/// Rejected time-zone input.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum TimeZoneError {
    /// The caller supplied an empty or whitespace-only value.
    #[error("time zone is empty")]
    Empty,

    /// The caller supplied a value that is not an IANA identifier.
    #[error("time zone is not a valid IANA identifier")]
    Invalid,
}

/// A validated IANA time zone.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct TimeZone(Tz);

impl TimeZone {
    /// Parse a trimmed IANA identifier. Parsing is case-insensitive; aliases
    /// keep the canonical name returned by [`Tz::name`].
    pub fn parse(value: &str) -> Result<Self, TimeZoneError> {
        let value = value.trim();
        if value.is_empty() {
            return Err(TimeZoneError::Empty);
        }
        Tz::from_str_insensitive(value)
            .map(Self)
            .map_err(|_| TimeZoneError::Invalid)
    }

    /// UTC, used when no preference or explicit dashboard zone is supplied.
    #[must_use]
    pub const fn utc() -> Self {
        Self(Tz::UTC)
    }

    /// The underlying `chrono-tz` zone.
    #[must_use]
    pub const fn as_tz(self) -> Tz {
        self.0
    }

    /// The canonical IANA name.
    #[must_use]
    pub fn name(self) -> &'static str {
        self.0.name()
    }

    /// Normalize a present profile value. An empty or whitespace-only string
    /// clears the preference, and a valid identifier becomes its canonical IANA
    /// name.
    pub fn profile_patch_value(value: &str) -> Result<Option<String>, TimeZoneError> {
        let value = value.trim();
        if value.is_empty() {
            return Ok(None);
        }
        Self::parse(value).map(|zone| Some(zone.name().to_owned()))
    }
}

impl Default for TimeZone {
    fn default() -> Self {
        Self::utc()
    }
}

impl fmt::Display for TimeZone {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.name())
    }
}

#[cfg(test)]
mod tests {
    use super::{TimeZone, TimeZoneError};

    #[test]
    fn parses_valid_iana_identifiers() {
        let zone = TimeZone::parse("Europe/Paris").unwrap();
        assert_eq!(zone.name(), "Europe/Paris");
        assert_eq!(zone.as_tz(), chrono_tz::Tz::Europe__Paris);
    }

    #[test]
    fn trims_whitespace_and_accepts_case_insensitive_names() {
        let zone = TimeZone::parse("  asia/tokyo \t").unwrap();
        assert_eq!(zone.name(), "Asia/Tokyo");
        assert_eq!(TimeZone::parse("utc").unwrap(), TimeZone::utc());
    }

    #[test]
    fn rejects_empty_offsets_and_garbage() {
        assert_eq!(TimeZone::parse("   "), Err(TimeZoneError::Empty));
        assert_eq!(TimeZone::parse(""), Err(TimeZoneError::Empty));
        assert_eq!(TimeZone::parse("+02:00"), Err(TimeZoneError::Invalid));
        assert_eq!(TimeZone::parse("UTC+2"), Err(TimeZoneError::Invalid));
        assert_eq!(
            TimeZone::parse("Not/A_Real_Zone"),
            Err(TimeZoneError::Invalid)
        );
    }

    #[test]
    fn profile_patch_normalizes_without_persisting_empty_strings() {
        assert_eq!(
            TimeZone::profile_patch_value(" Europe/Paris ").unwrap(),
            Some("Europe/Paris".to_owned())
        );
        assert_eq!(TimeZone::profile_patch_value("").unwrap(), None);
        assert_eq!(TimeZone::profile_patch_value("  \t").unwrap(), None);
        assert_eq!(
            TimeZone::profile_patch_value("-07:00"),
            Err(TimeZoneError::Invalid)
        );
    }
}
