use chrono::{
    DateTime, Datelike, Days, Duration, LocalResult, Months, NaiveDate, NaiveDateTime, NaiveTime,
    TimeZone as _, Timelike, Utc,
};
use chrono_tz::Tz;
use std::str::FromStr;

use strum::{AsRefStr, EnumIter, EnumString, IntoStaticStr};
use thiserror::Error;
use uuid::Uuid;

use super::event::{
    AuditAction, AuditActorKind, AuditAuthMethod, AuditCategory, AuditFailureReason, AuditOutcome,
    AuditTargetKind,
};
use crate::{global_id::DecodedGlobalId, time_zone::TimeZone};

pub const MAX_AUDIT_QUERY_LENGTH: usize = 2048;
pub const MAX_AUDIT_QUERY_DEPTH: usize = 16;
pub const MAX_AUDIT_QUERY_CLAUSES: usize = 64;

/// Searchable structured fields exposed by the native audit Lucene query DSL.
/// Names match the GraphQL `AuditEvent` fields they filter.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Hash, AsRefStr, IntoStaticStr, EnumString, EnumIter,
)]
#[strum(serialize_all = "camelCase")]
pub enum AuditQueryField {
    Category,
    Action,
    Outcome,
    FailureReason,
    ActorKind,
    Actor,
    ActorLabel,
    TargetKind,
    Target,
    TargetLabel,
    Client,
    AuthMethod,
    IpAddress,
    UserAgent,
    RequestId,
    TraceId,
    OccurredAt,
}

impl AuditQueryField {
    #[must_use]
    pub fn parse(name: &str) -> Option<Self> {
        name.parse().ok()
    }

    #[must_use]
    pub fn as_str(self) -> &'static str {
        self.into()
    }

    #[must_use]
    pub const fn is_identifier(self) -> bool {
        matches!(self, Self::Actor | Self::Target | Self::Client)
    }

    #[must_use]
    pub const fn is_date(self) -> bool {
        matches!(self, Self::OccurredAt)
    }

    /// The stored form of an enumerated field's value, accepting any letter
    /// case. `None` means the value is unknown; non-enumerated fields keep
    /// their value as typed.
    #[must_use]
    pub fn canonical_value(self, value: &str) -> Option<String> {
        fn stored<E: FromStr + Into<&'static str>>(value: &str) -> Option<String> {
            E::from_str(value).ok().map(|known| known.into().to_owned())
        }
        match self {
            Self::Category => stored::<AuditCategory>(value),
            Self::Action => stored::<AuditAction>(value),
            Self::Outcome => stored::<AuditOutcome>(value),
            Self::FailureReason => stored::<AuditFailureReason>(value),
            Self::ActorKind => stored::<AuditActorKind>(value),
            Self::TargetKind => stored::<AuditTargetKind>(value),
            Self::AuthMethod => stored::<AuditAuthMethod>(value),
            Self::Actor
            | Self::ActorLabel
            | Self::Target
            | Self::TargetLabel
            | Self::Client
            | Self::IpAddress
            | Self::UserAgent
            | Self::RequestId
            | Self::TraceId
            | Self::OccurredAt => Some(value.to_owned()),
        }
    }
}

/// Text predicate matcher compiled from a Lucene term, phrase, or wildcard.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuditTextMatcher {
    Exact(String),
    Prefix(String),
    /// `*` matches any run of characters and `?` one character; a backslash
    /// makes the next character literal.
    Wildcard(String),
    Contains(String),
    Exists,
}

/// Identifier predicate matcher resolved from a raw UUID or Relay Global ID.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuditIdentifierMatch {
    Exact(Uuid),
    Exists,
}

/// Inclusive or exclusive UTC bound on `audit.occurred_at`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AuditTimeBound {
    pub instant: DateTime<Utc>,
    pub inclusive: bool,
}

/// Validated, normalized AST of a security audit Lucene query.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuditQueryExpr {
    MatchAll,
    And(Vec<AuditQueryExpr>),
    Or(Vec<AuditQueryExpr>),
    Not(Box<AuditQueryExpr>),
    Text {
        field: AuditQueryField,
        matcher: AuditTextMatcher,
    },
    Identifier {
        field: AuditQueryField,
        value: AuditIdentifierMatch,
    },
    OccurredAtRange {
        min: Option<AuditTimeBound>,
        max: Option<AuditTimeBound>,
    },
    FreeText(String),
}

/// Typed validation errors produced while parsing an audit Lucene query.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum AuditQueryError {
    #[error("query exceeds maximum length of {max} characters")]
    QueryTooLong { max: usize, actual: usize },
    #[error("query exceeds maximum of {max} filter clauses")]
    TooManyClauses { max: usize },
    #[error("query nesting depth exceeds maximum of {max}")]
    TooDeeplyNested { max: usize },
    #[error("invalid query syntax: {detail}")]
    SyntaxError { detail: &'static str },
    #[error("unknown audit query field: {field}")]
    UnknownField { field: String },
    #[error("unknown value for {field}: {value}")]
    UnknownValue { field: &'static str, value: String },
    #[error("invalid date or date math value for occurredAt: {value}")]
    InvalidDateValue { value: String },
    #[error("invalid UUID or global identifier for {field}: {value}")]
    InvalidIdentifier { field: &'static str, value: String },
    #[error("comparison operator is not supported on field {field}")]
    UnsupportedOperator { field: &'static str },
    #[error("range queries are not supported on field {field}")]
    UnsupportedRangeField { field: &'static str },
    #[error("regular expression queries are not supported")]
    UnsupportedRegex,
    #[error("fuzzy matching is not supported")]
    UnsupportedFuzzy,
    #[error("term boosting is not supported")]
    UnsupportedBoost,
}

/// Parse and validate a native Lucene query string for security audit events.
///
/// The grammar is the one the query input in `packages/lucene-input` builds
/// its syntax tree with (`syntax-tree.ts`), read strictly: where that tree
/// marks a missing or unparsed part, this parser rejects the query.
///
/// ```text
/// query      := implicit?
/// implicit   := or (WS or)*                  (juxtaposition, lowest precedence)
/// or         := and (("OR" | "||") and)*
/// and        := primary (("AND" | "&&") primary)*
/// primary    := ("NOT" | "!") primary | "(" implicit ")" | field ":" fieldTerm | term
/// fieldGroup := ("NOT" | "!") fieldGroup | "(" fieldGroup ")" | field ":" fieldTerm
///             | cmp term | "[" term "TO" term "]" | term
/// fieldTerm  := ("NOT" | "!") fieldTerm | "(" fieldGroup ")" | cmp term
///             | "[" term "TO" term "]" | term
/// ```
///
/// Keywords match in any letter case; `TO` is a keyword only inside a range.
/// Adjacent implicit clauses require at least one separating whitespace character.
pub fn parse_audit_query(
    raw: &str,
    reference_now: DateTime<Utc>,
    time_zone: TimeZone,
) -> Result<AuditQueryExpr, AuditQueryError> {
    let char_len = raw.chars().count();
    if char_len > MAX_AUDIT_QUERY_LENGTH {
        return Err(AuditQueryError::QueryTooLong {
            max: MAX_AUDIT_QUERY_LENGTH,
            actual: char_len,
        });
    }

    let tokens = tokenize(raw)?;
    if tokens.is_empty() {
        return Ok(AuditQueryExpr::MatchAll);
    }

    let mut parser = Parser {
        tokens,
        pos: 0,
        clauses: 0,
        reference_now,
        tz: time_zone.as_tz(),
    };
    let expr = parser.parse_implicit(None, 0)?;
    if let Some(token) = parser.peek() {
        return Err(unexpected_token(token));
    }
    Ok(expr)
}

mod lexer;
use lexer::*;
mod parser;
use parser::*;
mod predicate;
use predicate::*;
mod time;
use time::*;
#[cfg(test)]
mod tests;
