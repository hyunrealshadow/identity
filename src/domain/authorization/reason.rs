//! Optional operator reason annotations recorded with authorization audits.

use std::fmt;

use serde::{Deserialize, Serialize};

/// Optional operator reason annotation. Reasons are audit annotations, not an
/// approval precondition: an absent or blank value is represented by an empty
/// string. Voluntarily supplied text is trimmed and bounded.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct GrantReason(String);

/// Maximum length of a voluntarily supplied grant reason annotation.
pub const MAX_GRANT_REASON_LENGTH: usize = 1_000;

impl GrantReason {
    pub fn new(value: impl Into<String>) -> Result<Self, GrantReasonError> {
        let value = value.into();
        let trimmed = value.trim();
        if trimmed.chars().count() > MAX_GRANT_REASON_LENGTH {
            return Err(GrantReasonError::TooLong);
        }
        Ok(Self(trimmed.to_owned()))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for GrantReason {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum GrantReasonError {
    #[error("grant reason is too long")]
    TooLong,
}

#[cfg(test)]
mod tests {
    use super::{GrantReason, GrantReasonError};

    #[test]
    fn grant_reason_accepts_blank_as_empty_and_round_trips() {
        let reason = GrantReason::new("   ").expect("blank reason is optional");
        assert_eq!(reason.as_str(), "");
        let encoded = serde_json::to_string(&reason).unwrap();
        assert_eq!(encoded, "\"\"");
        let decoded: GrantReason = serde_json::from_str(&encoded).unwrap();
        assert_eq!(decoded, reason);

        assert_eq!(
            GrantReason::new("  supplied annotation  ")
                .unwrap()
                .as_str(),
            "supplied annotation"
        );
        assert_eq!(
            GrantReason::new("x".repeat(1_001)),
            Err(GrantReasonError::TooLong)
        );
    }
}
