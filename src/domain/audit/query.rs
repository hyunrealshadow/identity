use chrono::{
    DateTime, Datelike, Days, Duration, LocalResult, Months, NaiveDate, NaiveDateTime, NaiveTime,
    TimeZone as _, Timelike, Utc,
};
use chrono_tz::Tz;
use thiserror::Error;
use uuid::Uuid;

use crate::{global_id::DecodedGlobalId, time_zone::TimeZone};

pub const MAX_AUDIT_QUERY_LENGTH: usize = 2048;
pub const MAX_AUDIT_QUERY_DEPTH: usize = 16;
pub const MAX_AUDIT_QUERY_CLAUSES: usize = 64;

/// Searchable structured fields exposed by the native audit Lucene query DSL.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AuditQueryField {
    Action,
    ActorType,
    Actor,
    TargetType,
    Target,
    ResourceType,
    Resource,
    Subject,
    Operation,
    Status,
    PreviousStatus,
    CredentialType,
    EventKind,
    RequestId,
    TraceId,
    Reason,
    OccurredAt,
}

impl AuditQueryField {
    #[must_use]
    pub fn parse(name: &str) -> Option<Self> {
        match name {
            "action" => Some(Self::Action),
            "actorType" => Some(Self::ActorType),
            "actor" => Some(Self::Actor),
            "targetType" => Some(Self::TargetType),
            "target" => Some(Self::Target),
            "resourceType" => Some(Self::ResourceType),
            "resource" => Some(Self::Resource),
            "subject" => Some(Self::Subject),
            "operation" => Some(Self::Operation),
            "status" => Some(Self::Status),
            "previousStatus" => Some(Self::PreviousStatus),
            "credentialType" => Some(Self::CredentialType),
            "eventKind" => Some(Self::EventKind),
            "requestId" => Some(Self::RequestId),
            "traceId" => Some(Self::TraceId),
            "reason" => Some(Self::Reason),
            "occurredAt" => Some(Self::OccurredAt),
            _ => None,
        }
    }

    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Action => "action",
            Self::ActorType => "actorType",
            Self::Actor => "actor",
            Self::TargetType => "targetType",
            Self::Target => "target",
            Self::ResourceType => "resourceType",
            Self::Resource => "resource",
            Self::Subject => "subject",
            Self::Operation => "operation",
            Self::Status => "status",
            Self::PreviousStatus => "previousStatus",
            Self::CredentialType => "credentialType",
            Self::EventKind => "eventKind",
            Self::RequestId => "requestId",
            Self::TraceId => "traceId",
            Self::Reason => "reason",
            Self::OccurredAt => "occurredAt",
        }
    }

    #[must_use]
    pub const fn is_identifier(self) -> bool {
        matches!(
            self,
            Self::Actor | Self::Target | Self::Resource | Self::Subject
        )
    }

    #[must_use]
    pub const fn is_date(self) -> bool {
        matches!(self, Self::OccurredAt)
    }
}

/// Text predicate matcher compiled from a Lucene term, phrase, or wildcard.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuditTextMatcher {
    Exact(String),
    Prefix(String),
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

/// Inclusive or exclusive UTC bound on `security_audit.occurred_at`.
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

    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Ok(AuditQueryExpr::MatchAll);
    }

    let mut parser = Parser {
        src: trimmed,
        pos: 0,
        clauses: 0,
        reference_now,
        tz: time_zone.as_tz(),
    };
    let expr = parser.parse_or_expr(None, 0)?;
    parser.skip_ws();
    if !parser.is_eof() {
        return Err(parser.unexpected_tail_error());
    }
    Ok(expr)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CmpOp {
    Gt,
    Gte,
    Lt,
    Lte,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum UnaryOp {
    Not,
    Plus,
}

#[derive(Debug, Clone)]
enum Atom {
    Word { text: String, had_colon: bool },
    Quoted(String),
}

struct Parser<'a> {
    src: &'a str,
    pos: usize,
    clauses: usize,
    reference_now: DateTime<Utc>,
    tz: Tz,
}

impl<'a> Parser<'a> {
    fn rest(&self) -> &'a str {
        &self.src[self.pos..]
    }

    fn is_eof(&self) -> bool {
        self.pos >= self.src.len()
    }

    fn peek_char(&self) -> Option<char> {
        self.rest().chars().next()
    }

    fn skip_ws(&mut self) {
        while let Some(ch) = self.peek_char() {
            if ch.is_whitespace() {
                self.pos += ch.len_utf8();
            } else {
                break;
            }
        }
    }

    fn record_clause(&mut self) -> Result<(), AuditQueryError> {
        self.clauses += 1;
        if self.clauses > MAX_AUDIT_QUERY_CLAUSES {
            return Err(AuditQueryError::TooManyClauses {
                max: MAX_AUDIT_QUERY_CLAUSES,
            });
        }
        Ok(())
    }

    fn check_depth(depth: usize) -> Result<(), AuditQueryError> {
        if depth > MAX_AUDIT_QUERY_DEPTH {
            return Err(AuditQueryError::TooDeeplyNested {
                max: MAX_AUDIT_QUERY_DEPTH,
            });
        }
        Ok(())
    }

    fn unexpected_tail_error(&self) -> AuditQueryError {
        match self.peek_char() {
            Some(')') => AuditQueryError::SyntaxError {
                detail: "unmatched closing parenthesis",
            },
            Some(']') | Some('}') => AuditQueryError::SyntaxError {
                detail: "unexpected range closing bracket",
            },
            Some('~') => AuditQueryError::UnsupportedFuzzy,
            Some('^') => AuditQueryError::UnsupportedBoost,
            _ => AuditQueryError::SyntaxError {
                detail: "unexpected trailing tokens",
            },
        }
    }

    fn starts_with_keyword(&self, kw: &str) -> bool {
        let rest = self.rest();
        if !rest.starts_with(kw) {
            return false;
        }
        match rest[kw.len()..].chars().next() {
            None => true,
            Some(ch) => ch.is_whitespace() || matches!(ch, '(' | ')' | '[' | '{' | ']' | '}' | '"'),
        }
    }

    fn try_consume_or(&mut self) -> bool {
        self.skip_ws();
        if self.rest().starts_with("||") {
            self.pos += 2;
            return true;
        }
        if self.starts_with_keyword("OR") {
            self.pos += 2;
            return true;
        }
        false
    }

    fn try_consume_and(&mut self) -> bool {
        self.skip_ws();
        if self.rest().starts_with("&&") {
            self.pos += 2;
            return true;
        }
        if self.starts_with_keyword("AND") {
            self.pos += 3;
            return true;
        }
        false
    }

    fn peek_at_stop_delimiter(&self) -> bool {
        let rest = self.rest();
        if rest.is_empty() {
            return true;
        }
        matches!(rest.chars().next(), Some(')') | Some(']') | Some('}'))
    }

    fn peek_starts_or(&self) -> bool {
        let rest = self.rest();
        rest.starts_with("||") || self.starts_with_keyword("OR")
    }

    fn parse_or_expr(
        &mut self,
        active_field: Option<AuditQueryField>,
        depth: usize,
    ) -> Result<AuditQueryExpr, AuditQueryError> {
        let first = self.parse_and_expr(active_field, depth)?;
        let mut items = vec![first];
        while self.try_consume_or() {
            items.push(self.parse_and_expr(active_field, depth)?);
        }
        Ok(if items.len() == 1 {
            items.into_iter().next().expect("checked len == 1")
        } else {
            AuditQueryExpr::Or(items)
        })
    }

    fn parse_and_expr(
        &mut self,
        active_field: Option<AuditQueryField>,
        depth: usize,
    ) -> Result<AuditQueryExpr, AuditQueryError> {
        let first = self.parse_unary_expr(active_field, depth)?;
        let mut items = vec![first];
        loop {
            self.skip_ws();
            if self.peek_at_stop_delimiter() || self.peek_starts_or() {
                break;
            }
            if self.try_consume_and() {
                items.push(self.parse_unary_expr(active_field, depth)?);
            } else {
                // Implicit whitespace AND
                items.push(self.parse_unary_expr(active_field, depth)?);
            }
        }
        Ok(if items.len() == 1 {
            items.into_iter().next().expect("checked len == 1")
        } else {
            AuditQueryExpr::And(items)
        })
    }

    fn parse_unary_expr(
        &mut self,
        active_field: Option<AuditQueryField>,
        depth: usize,
    ) -> Result<AuditQueryExpr, AuditQueryError> {
        self.skip_ws();
        if self.is_eof() || self.peek_at_stop_delimiter() {
            return Err(AuditQueryError::SyntaxError {
                detail: "expected query clause",
            });
        }

        let unary = if self.starts_with_keyword("NOT") {
            self.pos += 3;
            Some(UnaryOp::Not)
        } else if self.rest().starts_with('!') {
            self.pos += 1;
            Some(UnaryOp::Not)
        } else if self.rest().starts_with('-') {
            self.pos += 1;
            Some(UnaryOp::Not)
        } else if self.rest().starts_with('+') {
            self.pos += 1;
            Some(UnaryOp::Plus)
        } else {
            None
        };

        if let Some(op) = unary {
            self.skip_ws();
            if self.is_eof()
                || self.peek_at_stop_delimiter()
                || self.peek_starts_or()
                || self.starts_with_keyword("AND")
                || self.rest().starts_with("&&")
            {
                return Err(AuditQueryError::SyntaxError {
                    detail: "missing operand after unary operator",
                });
            }
            let inner = self.parse_unary_expr(active_field, depth)?;
            return Ok(match op {
                UnaryOp::Not => AuditQueryExpr::Not(Box::new(inner)),
                UnaryOp::Plus => inner,
            });
        }

        if self.starts_with_keyword("AND")
            || self.starts_with_keyword("OR")
            || self.rest().starts_with("&&")
            || self.rest().starts_with("||")
        {
            return Err(AuditQueryError::SyntaxError {
                detail: "unexpected binary boolean operator",
            });
        }

        self.parse_primary(active_field, depth)
    }

    fn parse_primary(
        &mut self,
        active_field: Option<AuditQueryField>,
        depth: usize,
    ) -> Result<AuditQueryExpr, AuditQueryError> {
        self.skip_ws();
        match self.peek_char() {
            None => Err(AuditQueryError::SyntaxError {
                detail: "expected query clause",
            }),
            Some('(') => {
                self.pos += 1;
                let next_depth = depth + 1;
                Self::check_depth(next_depth)?;
                self.skip_ws();
                if self.peek_char() == Some(')') {
                    return Err(AuditQueryError::SyntaxError {
                        detail: "empty parenthesized group",
                    });
                }
                let inner = self.parse_or_expr(active_field, next_depth)?;
                self.skip_ws();
                if self.peek_char() != Some(')') {
                    return Err(AuditQueryError::SyntaxError {
                        detail: "unclosed parenthesis",
                    });
                }
                self.pos += 1;
                self.check_unsupported_suffix()?;
                Ok(inner)
            }
            Some('[') | Some('{') => {
                if let Some(field) = active_field {
                    self.parse_range_for_field(field)
                } else {
                    Err(AuditQueryError::SyntaxError {
                        detail: "range query must follow a field name",
                    })
                }
            }
            Some(':') => Err(AuditQueryError::SyntaxError {
                detail: "missing field name before colon",
            }),
            Some('/') => {
                if self.scan_regex_literal() {
                    Err(AuditQueryError::UnsupportedRegex)
                } else if let Some(field) = active_field {
                    self.parse_field_value(field)
                } else {
                    self.record_clause()?;
                    let atom = self.read_clause_atom(false)?;
                    let value = match atom {
                        Atom::Quoted(s) | Atom::Word { text: s, .. } => s,
                    };
                    self.check_unsupported_suffix()?;
                    Ok(AuditQueryExpr::FreeText(value))
                }
            }
            Some('~') => Err(AuditQueryError::UnsupportedFuzzy),
            Some('^') => Err(AuditQueryError::UnsupportedBoost),
            _ => {
                if let Some(field) = active_field {
                    return self.parse_field_value(field);
                }

                // If active_field is None, we might have `field:value` or bare term.
                if self.starts_with_cmp_op().is_some() {
                    return Err(AuditQueryError::SyntaxError {
                        detail: "comparison operator must follow a field name",
                    });
                }

                let atom = self.read_clause_atom(true)?;
                match atom {
                    Atom::Quoted(text) => {
                        self.check_unsupported_suffix()?;
                        if self.peek_char() == Some(':') {
                            return Err(AuditQueryError::SyntaxError {
                                detail: "field name cannot be quoted",
                            });
                        }
                        self.record_clause()?;
                        Ok(AuditQueryExpr::FreeText(text))
                    }
                    Atom::Word { text, .. } => {
                        if self.peek_char() == Some(':') {
                            self.pos += 1;
                            let field = AuditQueryField::parse(&text).ok_or_else(|| {
                                AuditQueryError::UnknownField {
                                    field: text.clone(),
                                }
                            })?;
                            return self.parse_after_field_colon(field, depth);
                        }
                        self.check_unsupported_suffix()?;
                        self.record_clause()?;
                        Ok(AuditQueryExpr::FreeText(text))
                    }
                }
            }
        }
    }

    fn parse_after_field_colon(
        &mut self,
        field: AuditQueryField,
        depth: usize,
    ) -> Result<AuditQueryExpr, AuditQueryError> {
        self.skip_ws();
        match self.peek_char() {
            None => Err(AuditQueryError::SyntaxError {
                detail: "missing value after field colon",
            }),
            Some(')') | Some(']') | Some('}') => Err(AuditQueryError::SyntaxError {
                detail: "missing value after field colon",
            }),
            Some('(') => {
                self.pos += 1;
                let next_depth = depth + 1;
                Self::check_depth(next_depth)?;
                self.skip_ws();
                if self.peek_char() == Some(')') {
                    return Err(AuditQueryError::SyntaxError {
                        detail: "empty field group",
                    });
                }
                let inner = self.parse_or_expr(Some(field), next_depth)?;
                self.skip_ws();
                if self.peek_char() != Some(')') {
                    return Err(AuditQueryError::SyntaxError {
                        detail: "unclosed field group parenthesis",
                    });
                }
                self.pos += 1;
                self.check_unsupported_suffix()?;
                Ok(inner)
            }
            _ => self.parse_field_value(field),
        }
    }

    fn starts_with_cmp_op(&self) -> Option<(CmpOp, usize)> {
        let rest = self.rest();
        if rest.starts_with(">=") {
            Some((CmpOp::Gte, 2))
        } else if rest.starts_with("<=") {
            Some((CmpOp::Lte, 2))
        } else if rest.starts_with('>') {
            Some((CmpOp::Gt, 1))
        } else if rest.starts_with('<') {
            Some((CmpOp::Lt, 1))
        } else {
            None
        }
    }

    fn parse_field_value(
        &mut self,
        field: AuditQueryField,
    ) -> Result<AuditQueryExpr, AuditQueryError> {
        self.skip_ws();
        if matches!(self.peek_char(), Some('[') | Some('{')) {
            return self.parse_range_for_field(field);
        }
        if let Some((op, len)) = self.starts_with_cmp_op() {
            self.pos += len;
            self.skip_ws();
            if self.is_eof() || self.peek_at_stop_delimiter() {
                return Err(AuditQueryError::SyntaxError {
                    detail: "missing value after comparison operator",
                });
            }
            if !field.is_date() {
                return Err(AuditQueryError::UnsupportedOperator {
                    field: field.as_str(),
                });
            }
            if matches!(self.peek_char(), Some('[') | Some('{')) {
                return Err(AuditQueryError::SyntaxError {
                    detail: "unexpected bracket after comparison operator",
                });
            }
            let atom = self.read_value_atom()?;
            self.check_unsupported_suffix()?;
            let raw_val = match atom {
                Atom::Quoted(s) | Atom::Word { text: s, .. } => s,
            };
            if raw_val.is_empty() {
                return Err(AuditQueryError::InvalidDateValue { value: raw_val });
            }
            self.record_clause()?;
            return build_occurred_at_cmp(op, &raw_val, self.reference_now, self.tz);
        }

        if self.scan_regex_literal() {
            return Err(AuditQueryError::UnsupportedRegex);
        }

        let atom = self.read_value_atom()?;
        if self.peek_char() == Some(':') {
            // Unquoted secondary colons can only remain inside value_atom directly;
            // if read_value_atom stopped at ':' (it doesn't!), fail safely.
        }
        self.check_unsupported_suffix()?;

        match atom {
            Atom::Quoted(value) => {
                if self.peek_char() == Some(':') {
                    return Err(AuditQueryError::SyntaxError {
                        detail: "unexpected colon after quoted value",
                    });
                }
                self.record_clause()?;
                build_field_predicate(field, &value, true, self.reference_now, self.tz)
            }
            Atom::Word { text, had_colon } => {
                if matches!(text.as_str(), "AND" | "OR" | "NOT") {
                    return Err(AuditQueryError::SyntaxError {
                        detail: "boolean keyword cannot be used as an unquoted field value",
                    });
                }
                if had_colon
                    && !field.is_date()
                    && !field.is_identifier()
                    && !matches!(
                        field,
                        AuditQueryField::RequestId
                            | AuditQueryField::TraceId
                            | AuditQueryField::Reason
                            | AuditQueryField::Action
                            | AuditQueryField::Operation
                            | AuditQueryField::ResourceType
                            | AuditQueryField::TargetType
                            | AuditQueryField::ActorType
                            | AuditQueryField::Status
                            | AuditQueryField::PreviousStatus
                            | AuditQueryField::CredentialType
                            | AuditQueryField::EventKind
                    )
                {
                    return Err(AuditQueryError::SyntaxError {
                        detail: "unexpected colon in field value",
                    });
                }
                self.record_clause()?;
                build_field_predicate(field, &text, false, self.reference_now, self.tz)
            }
        }
    }

    fn parse_range_for_field(
        &mut self,
        field: AuditQueryField,
    ) -> Result<AuditQueryExpr, AuditQueryError> {
        let open_ch = self.peek_char().expect("checked open bracket");
        let min_inclusive = match open_ch {
            '[' => true,
            '{' => false,
            _ => unreachable!(),
        };
        self.pos += 1;

        if !field.is_date() {
            return Err(AuditQueryError::UnsupportedRangeField {
                field: field.as_str(),
            });
        }

        self.skip_ws();
        let min_atom = self.read_value_atom()?;
        let min_raw = match min_atom {
            Atom::Quoted(s) | Atom::Word { text: s, .. } => s,
        };
        if min_raw.is_empty() {
            return Err(AuditQueryError::SyntaxError {
                detail: "missing lower bound in range",
            });
        }

        self.skip_ws();
        if !self.starts_with_keyword("TO") {
            return Err(AuditQueryError::SyntaxError {
                detail: "expected TO inside range query",
            });
        }
        self.pos += 2;

        self.skip_ws();
        if self.is_eof() || matches!(self.peek_char(), Some(']') | Some('}')) {
            return Err(AuditQueryError::SyntaxError {
                detail: "missing upper bound in range",
            });
        }
        let max_atom = self.read_value_atom()?;
        let max_raw = match max_atom {
            Atom::Quoted(s) | Atom::Word { text: s, .. } => s,
        };

        self.skip_ws();
        let max_inclusive = match self.peek_char() {
            Some(']') => true,
            Some('}') => false,
            _ => {
                return Err(AuditQueryError::SyntaxError {
                    detail: "unclosed range bracket",
                });
            }
        };
        self.pos += 1;
        self.check_unsupported_suffix()?;
        self.record_clause()?;

        build_occurred_at_range(
            &min_raw,
            min_inclusive,
            &max_raw,
            max_inclusive,
            self.reference_now,
            self.tz,
        )
    }

    fn check_unsupported_suffix(&self) -> Result<(), AuditQueryError> {
        match self.peek_char() {
            Some('~') => Err(AuditQueryError::UnsupportedFuzzy),
            Some('^') => Err(AuditQueryError::UnsupportedBoost),
            _ => Ok(()),
        }
    }

    fn scan_regex_literal(&self) -> bool {
        let rest = self.rest();
        if !rest.starts_with('/') {
            return false;
        }
        let mut chars = rest[1..].chars();
        let mut escaped = false;
        while let Some(ch) = chars.next() {
            if escaped {
                escaped = false;
                continue;
            }
            if ch == '\\' {
                escaped = true;
                continue;
            }
            if ch == '/' {
                return true;
            }
        }
        false
    }

    fn read_clause_atom(&mut self, stop_at_colon: bool) -> Result<Atom, AuditQueryError> {
        self.skip_ws();
        if self.peek_char() == Some('"') {
            return Ok(Atom::Quoted(self.read_quoted_string()?));
        }
        self.read_unquoted_word(stop_at_colon)
    }

    fn read_value_atom(&mut self) -> Result<Atom, AuditQueryError> {
        self.skip_ws();
        if self.peek_char() == Some('"') {
            return Ok(Atom::Quoted(self.read_quoted_string()?));
        }
        self.read_unquoted_word(false)
    }

    fn read_quoted_string(&mut self) -> Result<String, AuditQueryError> {
        debug_assert_eq!(self.peek_char(), Some('"'));
        self.pos += 1;
        let mut out = String::new();
        let mut escaped = false;
        while let Some(ch) = self.peek_char() {
            self.pos += ch.len_utf8();
            if escaped {
                match ch {
                    '"' | '\\' | '/' => out.push(ch),
                    'n' => out.push('\n'),
                    'r' => out.push('\r'),
                    't' => out.push('\t'),
                    other => {
                        out.push('\\');
                        out.push(other);
                    }
                }
                escaped = false;
            } else if ch == '\\' {
                escaped = true;
            } else if ch == '"' {
                return Ok(out);
            } else {
                out.push(ch);
            }
        }
        Err(AuditQueryError::SyntaxError {
            detail: "unclosed quoted string",
        })
    }

    fn read_unquoted_word(&mut self, stop_at_colon: bool) -> Result<Atom, AuditQueryError> {
        let start = self.pos;
        let mut had_colon = false;
        while let Some(ch) = self.peek_char() {
            if ch.is_whitespace() {
                break;
            }
            if matches!(ch, '(' | ')' | '[' | '{' | ']' | '}' | '"' | '~' | '^') {
                break;
            }
            if self.rest().starts_with("&&") || self.rest().starts_with("||") {
                break;
            }
            if ch == ':' {
                if stop_at_colon {
                    break;
                }
                had_colon = true;
            }
            self.pos += ch.len_utf8();
        }
        if self.pos == start {
            return match self.peek_char() {
                Some('~') => Err(AuditQueryError::UnsupportedFuzzy),
                Some('^') => Err(AuditQueryError::UnsupportedBoost),
                _ => Err(AuditQueryError::SyntaxError {
                    detail: "unexpected token",
                }),
            };
        }
        Ok(Atom::Word {
            text: self.src[start..self.pos].to_owned(),
            had_colon,
        })
    }
}

fn build_field_predicate(
    field: AuditQueryField,
    value: &str,
    quoted: bool,
    reference_now: DateTime<Utc>,
    tz: Tz,
) -> Result<AuditQueryExpr, AuditQueryError> {
    if field.is_date() {
        return match parse_time_value(value, reference_now, tz)? {
            ParsedTimeValue::Exact(instant) => Ok(AuditQueryExpr::OccurredAtRange {
                min: Some(AuditTimeBound {
                    instant,
                    inclusive: true,
                }),
                max: Some(AuditTimeBound {
                    instant,
                    inclusive: true,
                }),
            }),
            ParsedTimeValue::CalendarDay {
                start,
                next_day_start,
            } => Ok(AuditQueryExpr::OccurredAtRange {
                min: Some(AuditTimeBound {
                    instant: start,
                    inclusive: true,
                }),
                max: Some(AuditTimeBound {
                    instant: next_day_start,
                    inclusive: false,
                }),
            }),
            ParsedTimeValue::Unbounded => Ok(AuditQueryExpr::OccurredAtRange {
                min: None,
                max: None,
            }),
        };
    }

    if field.is_identifier() {
        if !quoted && value == "*" {
            return Ok(AuditQueryExpr::Identifier {
                field,
                value: AuditIdentifierMatch::Exists,
            });
        }
        let oid = resolve_identifier(field, value)?;
        return Ok(AuditQueryExpr::Identifier {
            field,
            value: AuditIdentifierMatch::Exact(oid),
        });
    }

    let matcher = build_text_matcher(value, quoted);
    Ok(AuditQueryExpr::Text { field, matcher })
}

fn build_text_matcher(value: &str, quoted: bool) -> AuditTextMatcher {
    if quoted {
        return AuditTextMatcher::Exact(value.to_owned());
    }
    if value == "*" {
        return AuditTextMatcher::Exists;
    }
    if let Some(prefix) = value.strip_suffix('*')
        && !prefix.is_empty()
        && !prefix.contains('*')
        && !prefix.contains('?')
    {
        return AuditTextMatcher::Prefix(prefix.to_owned());
    }
    if let Some(middle) = value
        .strip_prefix('*')
        .and_then(|rest| rest.strip_suffix('*'))
        && !middle.is_empty()
        && !middle.contains('*')
        && !middle.contains('?')
    {
        return AuditTextMatcher::Contains(middle.to_owned());
    }
    if value.contains('*') || value.contains('?') {
        return AuditTextMatcher::Wildcard(value.to_owned());
    }
    AuditTextMatcher::Exact(value.to_owned())
}

fn resolve_identifier(field: AuditQueryField, value: &str) -> Result<Uuid, AuditQueryError> {
    if let Ok(uuid) = Uuid::parse_str(value) {
        return Ok(uuid);
    }
    if let Ok(decoded) = DecodedGlobalId::decode(value) {
        return Ok(decoded.oid());
    }
    Err(AuditQueryError::InvalidIdentifier {
        field: field.as_str(),
        value: value.to_owned(),
    })
}

fn build_occurred_at_cmp(
    op: CmpOp,
    raw: &str,
    reference_now: DateTime<Utc>,
    tz: Tz,
) -> Result<AuditQueryExpr, AuditQueryError> {
    let parsed = parse_time_value(raw, reference_now, tz)?;
    if matches!(parsed, ParsedTimeValue::Unbounded) {
        return Err(AuditQueryError::InvalidDateValue {
            value: raw.to_owned(),
        });
    }
    let (min, max) = match (op, parsed) {
        (CmpOp::Gte, ParsedTimeValue::Exact(t)) => (
            Some(AuditTimeBound {
                instant: t,
                inclusive: true,
            }),
            None,
        ),
        (CmpOp::Gt, ParsedTimeValue::Exact(t)) => (
            Some(AuditTimeBound {
                instant: t,
                inclusive: false,
            }),
            None,
        ),
        (CmpOp::Lte, ParsedTimeValue::Exact(t)) => (
            None,
            Some(AuditTimeBound {
                instant: t,
                inclusive: true,
            }),
        ),
        (CmpOp::Lt, ParsedTimeValue::Exact(t)) => (
            None,
            Some(AuditTimeBound {
                instant: t,
                inclusive: false,
            }),
        ),
        (CmpOp::Gte, ParsedTimeValue::CalendarDay { start, .. }) => (
            Some(AuditTimeBound {
                instant: start,
                inclusive: true,
            }),
            None,
        ),
        (CmpOp::Gt, ParsedTimeValue::CalendarDay { next_day_start, .. }) => (
            Some(AuditTimeBound {
                instant: next_day_start,
                inclusive: true,
            }),
            None,
        ),
        (CmpOp::Lte, ParsedTimeValue::CalendarDay { next_day_start, .. }) => (
            None,
            Some(AuditTimeBound {
                instant: next_day_start,
                inclusive: false,
            }),
        ),
        (CmpOp::Lt, ParsedTimeValue::CalendarDay { start, .. }) => (
            None,
            Some(AuditTimeBound {
                instant: start,
                inclusive: false,
            }),
        ),
        (_, ParsedTimeValue::Unbounded) => unreachable!(),
    };
    Ok(AuditQueryExpr::OccurredAtRange { min, max })
}

fn build_occurred_at_range(
    min_raw: &str,
    min_inclusive: bool,
    max_raw: &str,
    max_inclusive: bool,
    reference_now: DateTime<Utc>,
    tz: Tz,
) -> Result<AuditQueryExpr, AuditQueryError> {
    let min_val = parse_time_value(min_raw, reference_now, tz)?;
    let max_val = parse_time_value(max_raw, reference_now, tz)?;

    let min = match min_val {
        ParsedTimeValue::Unbounded => None,
        ParsedTimeValue::Exact(t) => Some(AuditTimeBound {
            instant: t,
            inclusive: min_inclusive,
        }),
        ParsedTimeValue::CalendarDay {
            start,
            next_day_start,
        } => Some(AuditTimeBound {
            instant: if min_inclusive { start } else { next_day_start },
            inclusive: true,
        }),
    };

    let max = match max_val {
        ParsedTimeValue::Unbounded => None,
        ParsedTimeValue::Exact(t) => Some(AuditTimeBound {
            instant: t,
            inclusive: max_inclusive,
        }),
        ParsedTimeValue::CalendarDay {
            start,
            next_day_start,
        } => Some(AuditTimeBound {
            instant: if max_inclusive { next_day_start } else { start },
            inclusive: false,
        }),
    };

    if let (Some(lower), Some(upper)) = (min, max)
        && (lower.instant > upper.instant
            || (lower.instant == upper.instant && (!lower.inclusive || !upper.inclusive)))
    {
        return Err(AuditQueryError::InvalidDateValue {
            value: format!("{min_raw} TO {max_raw}"),
        });
    }

    Ok(AuditQueryExpr::OccurredAtRange { min, max })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ParsedTimeValue {
    Unbounded,
    Exact(DateTime<Utc>),
    CalendarDay {
        start: DateTime<Utc>,
        next_day_start: DateTime<Utc>,
    },
}

fn parse_time_value(
    raw: &str,
    reference_now: DateTime<Utc>,
    tz: Tz,
) -> Result<ParsedTimeValue, AuditQueryError> {
    if raw == "*" {
        return Ok(ParsedTimeValue::Unbounded);
    }

    if raw == "now" || raw.starts_with("now+") || raw.starts_with("now-") || raw.starts_with("now/")
    {
        return parse_date_math(raw, reference_now, tz).map(ParsedTimeValue::Exact);
    }

    if raw.len() == 10
        && raw.as_bytes().get(4) == Some(&b'-')
        && raw.as_bytes().get(7) == Some(&b'-')
        && let Ok(date) = NaiveDate::parse_from_str(raw, "%Y-%m-%d")
    {
        let start = resolve_local_midnight(tz, date)?;
        let next_day = date
            .succ_opt()
            .ok_or_else(|| AuditQueryError::InvalidDateValue {
                value: raw.to_owned(),
            })?;
        let next_day_start = resolve_local_midnight(tz, next_day)?;
        return Ok(ParsedTimeValue::CalendarDay {
            start,
            next_day_start,
        });
    }

    if let Ok(dt) = DateTime::parse_from_rfc3339(raw) {
        return Ok(ParsedTimeValue::Exact(dt.with_timezone(&Utc)));
    }

    for fmt in [
        "%Y-%m-%dT%H:%M:%S%.f",
        "%Y-%m-%dT%H:%M:%S",
        "%Y-%m-%dT%H:%M",
        "%Y-%m-%d %H:%M:%S%.f",
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%d %H:%M",
    ] {
        if let Ok(naive) = NaiveDateTime::parse_from_str(raw, fmt) {
            return Ok(ParsedTimeValue::Exact(resolve_local_datetime(tz, naive)));
        }
    }

    Err(AuditQueryError::InvalidDateValue {
        value: raw.to_owned(),
    })
}

fn parse_date_math(
    raw: &str,
    reference_now: DateTime<Utc>,
    tz: Tz,
) -> Result<DateTime<Utc>, AuditQueryError> {
    let mut rest = raw
        .strip_prefix("now")
        .ok_or_else(|| AuditQueryError::InvalidDateValue {
            value: raw.to_owned(),
        })?;
    let mut current = reference_now;

    while let Some(sign) = rest.chars().next().filter(|c| *c == '+' || *c == '-') {
        rest = &rest[1..];
        let digits_len = rest.bytes().take_while(|b| b.is_ascii_digit()).count();
        if digits_len == 0 {
            return Err(AuditQueryError::InvalidDateValue {
                value: raw.to_owned(),
            });
        }
        let amount: u32 =
            rest[..digits_len]
                .parse()
                .map_err(|_| AuditQueryError::InvalidDateValue {
                    value: raw.to_owned(),
                })?;
        rest = &rest[digits_len..];
        let unit = rest
            .chars()
            .next()
            .ok_or_else(|| AuditQueryError::InvalidDateValue {
                value: raw.to_owned(),
            })?;
        rest = &rest[unit.len_utf8()..];
        current = apply_date_math_offset(current, tz, sign == '+', amount, unit, raw)?;
    }

    if let Some(after_slash) = rest.strip_prefix('/') {
        let mut chars = after_slash.chars();
        let unit = chars
            .next()
            .ok_or_else(|| AuditQueryError::InvalidDateValue {
                value: raw.to_owned(),
            })?;
        if chars.next().is_some() {
            return Err(AuditQueryError::InvalidDateValue {
                value: raw.to_owned(),
            });
        }
        current = floor_date_unit(current, tz, unit, raw)?;
        rest = "";
    }

    if !rest.is_empty() {
        return Err(AuditQueryError::InvalidDateValue {
            value: raw.to_owned(),
        });
    }

    Ok(current)
}

fn apply_date_math_offset(
    instant: DateTime<Utc>,
    tz: Tz,
    add: bool,
    amount: u32,
    unit: char,
    raw: &str,
) -> Result<DateTime<Utc>, AuditQueryError> {
    let amount_i64 = i64::from(amount);
    let delta_i64 = if add { amount_i64 } else { -amount_i64 };
    match unit {
        's' => instant
            .checked_add_signed(Duration::seconds(delta_i64))
            .ok_or_else(|| AuditQueryError::InvalidDateValue {
                value: raw.to_owned(),
            }),
        'm' => instant
            .checked_add_signed(Duration::minutes(delta_i64))
            .ok_or_else(|| AuditQueryError::InvalidDateValue {
                value: raw.to_owned(),
            }),
        'h' => instant
            .checked_add_signed(Duration::hours(delta_i64))
            .ok_or_else(|| AuditQueryError::InvalidDateValue {
                value: raw.to_owned(),
            }),
        'd' | 'w' => {
            let days = if unit == 'w' {
                amount.checked_mul(7)
            } else {
                Some(amount)
            }
            .ok_or_else(|| AuditQueryError::InvalidDateValue {
                value: raw.to_owned(),
            })?;
            let local = instant.with_timezone(&tz).naive_local();
            let date = if add {
                local.date().checked_add_days(Days::new(u64::from(days)))
            } else {
                local.date().checked_sub_days(Days::new(u64::from(days)))
            }
            .ok_or_else(|| AuditQueryError::InvalidDateValue {
                value: raw.to_owned(),
            })?;
            Ok(resolve_local_datetime(
                tz,
                NaiveDateTime::new(date, local.time()),
            ))
        }
        'M' => {
            let local = instant.with_timezone(&tz).naive_local();
            let date = if add {
                local.date().checked_add_months(Months::new(amount))
            } else {
                local.date().checked_sub_months(Months::new(amount))
            }
            .ok_or_else(|| AuditQueryError::InvalidDateValue {
                value: raw.to_owned(),
            })?;
            Ok(resolve_local_datetime(
                tz,
                NaiveDateTime::new(date, local.time()),
            ))
        }
        'y' => {
            let months =
                amount
                    .checked_mul(12)
                    .ok_or_else(|| AuditQueryError::InvalidDateValue {
                        value: raw.to_owned(),
                    })?;
            let local = instant.with_timezone(&tz).naive_local();
            let date = if add {
                local.date().checked_add_months(Months::new(months))
            } else {
                local.date().checked_sub_months(Months::new(months))
            }
            .ok_or_else(|| AuditQueryError::InvalidDateValue {
                value: raw.to_owned(),
            })?;
            Ok(resolve_local_datetime(
                tz,
                NaiveDateTime::new(date, local.time()),
            ))
        }
        _ => Err(AuditQueryError::InvalidDateValue {
            value: raw.to_owned(),
        }),
    }
}

fn floor_date_unit(
    instant: DateTime<Utc>,
    tz: Tz,
    unit: char,
    raw: &str,
) -> Result<DateTime<Utc>, AuditQueryError> {
    let local = instant.with_timezone(&tz).naive_local();
    match unit {
        's' => {
            let naive = local
                .date()
                .and_hms_opt(local.hour(), local.minute(), local.second())
                .ok_or_else(|| AuditQueryError::InvalidDateValue {
                    value: raw.to_owned(),
                })?;
            Ok(resolve_local_datetime(tz, naive))
        }
        'm' => {
            let naive = local
                .date()
                .and_hms_opt(local.hour(), local.minute(), 0)
                .ok_or_else(|| AuditQueryError::InvalidDateValue {
                    value: raw.to_owned(),
                })?;
            Ok(resolve_local_datetime(tz, naive))
        }
        'h' => {
            let naive = local
                .date()
                .and_hms_opt(local.hour(), 0, 0)
                .ok_or_else(|| AuditQueryError::InvalidDateValue {
                    value: raw.to_owned(),
                })?;
            Ok(resolve_local_datetime(tz, naive))
        }
        'd' => resolve_local_midnight(tz, local.date()),
        'w' => {
            let offset_from_monday = u64::from(local.date().weekday().num_days_from_monday());
            let monday = local
                .date()
                .checked_sub_days(Days::new(offset_from_monday))
                .ok_or_else(|| AuditQueryError::InvalidDateValue {
                    value: raw.to_owned(),
                })?;
            resolve_local_midnight(tz, monday)
        }
        'M' => {
            let first =
                local
                    .date()
                    .with_day(1)
                    .ok_or_else(|| AuditQueryError::InvalidDateValue {
                        value: raw.to_owned(),
                    })?;
            resolve_local_midnight(tz, first)
        }
        'y' => {
            let jan1 = NaiveDate::from_ymd_opt(local.year(), 1, 1).ok_or_else(|| {
                AuditQueryError::InvalidDateValue {
                    value: raw.to_owned(),
                }
            })?;
            resolve_local_midnight(tz, jan1)
        }
        _ => Err(AuditQueryError::InvalidDateValue {
            value: raw.to_owned(),
        }),
    }
}

fn resolve_local_midnight(tz: Tz, date: NaiveDate) -> Result<DateTime<Utc>, AuditQueryError> {
    let midnight = NaiveTime::from_hms_opt(0, 0, 0).expect("valid midnight");
    Ok(resolve_local_datetime(
        tz,
        NaiveDateTime::new(date, midnight),
    ))
}

fn resolve_local_datetime(tz: Tz, naive: NaiveDateTime) -> DateTime<Utc> {
    match tz.from_local_datetime(&naive) {
        LocalResult::Single(dt) | LocalResult::Ambiguous(dt, _) => dt.with_timezone(&Utc),
        LocalResult::None => {
            // Spring-forward DST gap: advance minute-by-minute to first valid instant.
            for step in 1..=180_i64 {
                let shifted = naive + Duration::minutes(step);
                if let Some(dt) = tz.from_local_datetime(&shifted).earliest() {
                    return dt.with_timezone(&Utc);
                }
            }
            DateTime::from_naive_utc_and_offset(naive, Utc)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::global_id::{encode, kind};

    fn ref_now() -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 11, 20, 10, 30, 45).unwrap()
    }

    fn utc() -> TimeZone {
        TimeZone::parse("UTC").unwrap()
    }

    fn shanghai() -> TimeZone {
        TimeZone::parse("Asia/Shanghai").unwrap()
    }

    #[test]
    fn empty_and_whitespace_produce_match_all() {
        assert_eq!(
            parse_audit_query("", ref_now(), utc()).unwrap(),
            AuditQueryExpr::MatchAll
        );
        assert_eq!(
            parse_audit_query("   \t\n  ", ref_now(), utc()).unwrap(),
            AuditQueryExpr::MatchAll
        );
    }

    #[test]
    fn boolean_precedence_implicit_and_and_field_grouping() {
        let parsed = parse_audit_query(
            "action:(user.create OR user.delete) -status:failed && actorType:user OR traceId:*",
            ref_now(),
            utc(),
        )
        .unwrap();

        assert_eq!(
            parsed,
            AuditQueryExpr::Or(vec![
                AuditQueryExpr::And(vec![
                    AuditQueryExpr::Or(vec![
                        AuditQueryExpr::Text {
                            field: AuditQueryField::Action,
                            matcher: AuditTextMatcher::Exact("user.create".to_owned()),
                        },
                        AuditQueryExpr::Text {
                            field: AuditQueryField::Action,
                            matcher: AuditTextMatcher::Exact("user.delete".to_owned()),
                        },
                    ]),
                    AuditQueryExpr::Not(Box::new(AuditQueryExpr::Text {
                        field: AuditQueryField::Status,
                        matcher: AuditTextMatcher::Exact("failed".to_owned()),
                    })),
                    AuditQueryExpr::Text {
                        field: AuditQueryField::ActorType,
                        matcher: AuditTextMatcher::Exact("user".to_owned()),
                    },
                ]),
                AuditQueryExpr::Text {
                    field: AuditQueryField::TraceId,
                    matcher: AuditTextMatcher::Exists,
                },
            ])
        );
    }

    #[test]
    fn wildcards_and_quoted_strings_map_expected_matchers() {
        let parsed = parse_audit_query(
            r#"action:user.* reason:"a:b \"c\"" targetType:*client* operation:up?ate "hello world""#,
            ref_now(),
            utc(),
        )
        .unwrap();

        assert_eq!(
            parsed,
            AuditQueryExpr::And(vec![
                AuditQueryExpr::Text {
                    field: AuditQueryField::Action,
                    matcher: AuditTextMatcher::Prefix("user.".to_owned()),
                },
                AuditQueryExpr::Text {
                    field: AuditQueryField::Reason,
                    matcher: AuditTextMatcher::Exact("a:b \"c\"".to_owned()),
                },
                AuditQueryExpr::Text {
                    field: AuditQueryField::TargetType,
                    matcher: AuditTextMatcher::Contains("client".to_owned()),
                },
                AuditQueryExpr::Text {
                    field: AuditQueryField::Operation,
                    matcher: AuditTextMatcher::Wildcard("up?ate".to_owned()),
                },
                AuditQueryExpr::FreeText("hello world".to_owned()),
            ])
        );
    }

    #[test]
    fn identifiers_accept_raw_uuid_global_id_and_exists() {
        let oid = Uuid::new_v4();
        let gid = encode::<kind::User>(oid);
        let query = format!("actor:{oid} target:{gid} subject:*");

        let parsed = parse_audit_query(&query, ref_now(), utc()).unwrap();
        assert_eq!(
            parsed,
            AuditQueryExpr::And(vec![
                AuditQueryExpr::Identifier {
                    field: AuditQueryField::Actor,
                    value: AuditIdentifierMatch::Exact(oid),
                },
                AuditQueryExpr::Identifier {
                    field: AuditQueryField::Target,
                    value: AuditIdentifierMatch::Exact(oid),
                },
                AuditQueryExpr::Identifier {
                    field: AuditQueryField::Subject,
                    value: AuditIdentifierMatch::Exists,
                },
            ])
        );

        let err = parse_audit_query("actor:not-a-uuid", ref_now(), utc()).unwrap_err();
        assert_eq!(
            err,
            AuditQueryError::InvalidIdentifier {
                field: "actor",
                value: "not-a-uuid".to_owned()
            }
        );
    }

    #[test]
    fn occurred_at_resolves_bare_dates_in_user_time_zone() {
        // 2026-11-20 in Asia/Shanghai (+08:00) spans [2026-11-19T16:00Z, 2026-11-20T16:00Z)
        let parsed = parse_audit_query("occurredAt:2026-11-20", ref_now(), shanghai()).unwrap();
        assert_eq!(
            parsed,
            AuditQueryExpr::OccurredAtRange {
                min: Some(AuditTimeBound {
                    instant: Utc.with_ymd_and_hms(2026, 11, 19, 16, 0, 0).unwrap(),
                    inclusive: true,
                }),
                max: Some(AuditTimeBound {
                    instant: Utc.with_ymd_and_hms(2026, 11, 20, 16, 0, 0).unwrap(),
                    inclusive: false,
                }),
            }
        );
    }

    #[test]
    fn occurred_at_supports_date_math_comparisons_and_ranges() {
        let now = Utc.with_ymd_and_hms(2026, 11, 20, 17, 15, 0).unwrap();
        // In Asia/Shanghai, 17:15Z is 2026-11-21 01:15+08:00 -> /d rounds to 2026-11-20T16:00Z
        let expr = parse_audit_query(
            "occurredAt:[now-1d/d TO now] AND occurredAt:>=2026-11-19T00:00:00Z",
            now,
            shanghai(),
        )
        .unwrap();

        assert_eq!(
            expr,
            AuditQueryExpr::And(vec![
                AuditQueryExpr::OccurredAtRange {
                    min: Some(AuditTimeBound {
                        instant: Utc.with_ymd_and_hms(2026, 11, 19, 16, 0, 0).unwrap(),
                        inclusive: true,
                    }),
                    max: Some(AuditTimeBound {
                        instant: now,
                        inclusive: true,
                    }),
                },
                AuditQueryExpr::OccurredAtRange {
                    min: Some(AuditTimeBound {
                        instant: Utc.with_ymd_and_hms(2026, 11, 19, 0, 0, 0).unwrap(),
                        inclusive: true,
                    }),
                    max: None,
                },
            ])
        );
    }

    #[test]
    fn occurred_at_handles_spring_forward_dst_gap() {
        let ny = TimeZone::parse("America/New_York").unwrap();
        // 2026-03-08 02:30 does not exist in America/New_York; resolves forward cleanly
        let expr = parse_audit_query(r#"occurredAt:"2026-03-08 02:30""#, ref_now(), ny).unwrap();
        match expr {
            AuditQueryExpr::OccurredAtRange {
                min: Some(bound), ..
            } => {
                assert_eq!(
                    bound.instant,
                    Utc.with_ymd_and_hms(2026, 3, 8, 7, 0, 0).unwrap()
                );
            }
            other => panic!("unexpected expr: {other:?}"),
        }
    }

    #[test]
    fn parser_rejects_unsupported_and_invalid_queries() {
        assert_eq!(
            parse_audit_query(&"a".repeat(MAX_AUDIT_QUERY_LENGTH + 1), ref_now(), utc())
                .unwrap_err(),
            AuditQueryError::QueryTooLong {
                max: MAX_AUDIT_QUERY_LENGTH,
                actual: MAX_AUDIT_QUERY_LENGTH + 1,
            }
        );

        let many = (0..=MAX_AUDIT_QUERY_CLAUSES)
            .map(|i| format!("status:s{i}"))
            .collect::<Vec<_>>()
            .join(" ");
        assert_eq!(
            parse_audit_query(&many, ref_now(), utc()).unwrap_err(),
            AuditQueryError::TooManyClauses {
                max: MAX_AUDIT_QUERY_CLAUSES
            }
        );

        let deep = format!(
            "{}status:ok{}",
            "(".repeat(MAX_AUDIT_QUERY_DEPTH + 1),
            ")".repeat(MAX_AUDIT_QUERY_DEPTH + 1)
        );
        assert_eq!(
            parse_audit_query(&deep, ref_now(), utc()).unwrap_err(),
            AuditQueryError::TooDeeplyNested {
                max: MAX_AUDIT_QUERY_DEPTH
            }
        );

        assert_eq!(
            parse_audit_query("unknownField:foo", ref_now(), utc()).unwrap_err(),
            AuditQueryError::UnknownField {
                field: "unknownField".to_owned()
            }
        );
        assert_eq!(
            parse_audit_query("action:/user.*/", ref_now(), utc()).unwrap_err(),
            AuditQueryError::UnsupportedRegex
        );
        assert_eq!(
            parse_audit_query("action:create~1", ref_now(), utc()).unwrap_err(),
            AuditQueryError::UnsupportedFuzzy
        );
        assert_eq!(
            parse_audit_query("action:create^2", ref_now(), utc()).unwrap_err(),
            AuditQueryError::UnsupportedBoost
        );
        assert_eq!(
            parse_audit_query("action:>=a", ref_now(), utc()).unwrap_err(),
            AuditQueryError::UnsupportedOperator { field: "action" }
        );
        assert_eq!(
            parse_audit_query("action:[a TO b]", ref_now(), utc()).unwrap_err(),
            AuditQueryError::UnsupportedRangeField { field: "action" }
        );
        assert!(matches!(
            parse_audit_query("occurredAt:[2026-11-21 TO 2026-11-20]", ref_now(), utc())
                .unwrap_err(),
            AuditQueryError::InvalidDateValue { .. }
        ));
        assert!(matches!(
            parse_audit_query("action:\"unterminated", ref_now(), utc()).unwrap_err(),
            AuditQueryError::SyntaxError { .. }
        ));
    }
}
