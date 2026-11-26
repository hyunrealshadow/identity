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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CmpOp {
    Gt,
    Gte,
    Lt,
    Lte,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Token {
    /// A name directly followed by `:`.
    Field(String),
    /// The `:` after a field name.
    Colon,
    /// A `:` with no field name before it.
    StrayColon,
    And,
    Or,
    Not,
    /// `TO` between the brackets of a range.
    To,
    Cmp(CmpOp),
    Open,
    Close,
    RangeOpen,
    RangeClose,
    /// A quoted phrase, unescaped.
    Quoted(String),
    /// An unquoted term as written, backslash escapes included.
    Word(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct SpannedToken {
    token: Token,
    separated: bool,
}

fn syntax(detail: &'static str) -> AuditQueryError {
    AuditQueryError::SyntaxError { detail }
}

/// Split a query into tokens the way the query input's tokenizer does.
fn tokenize(src: &str) -> Result<Vec<SpannedToken>, AuditQueryError> {
    let mut tokens: Vec<SpannedToken> = Vec::new();
    let mut index = 0;
    let mut range_depth = 0usize;
    let mut separated = false;

    while let Some(ch) = src[index..].chars().next() {
        let rest = &src[index..];
        if ch.is_whitespace() {
            separated = true;
            index += ch.len_utf8();
            continue;
        }

        // The input recognizes these; the audit query bar turns them off.
        if matches!(ch, '+' | '-')
            && is_prefix_position(src, index, tokens.last().map(|item| &item.token))
        {
            return Err(syntax("prefix operators are not supported"));
        }
        match ch {
            '{' | '}' => return Err(syntax("exclusive ranges are not supported")),
            '~' => return Err(AuditQueryError::UnsupportedFuzzy),
            '^' => return Err(AuditQueryError::UnsupportedBoost),
            _ => {}
        }

        if ch == '"' || ch == '\'' {
            let (value, end) = read_quoted(src, index, ch)?;
            tokens.push(SpannedToken {
                token: Token::Quoted(value),
                separated,
            });
            separated = false;
            index = end;
            continue;
        }

        if ch == '/' {
            return Err(AuditQueryError::UnsupportedRegex);
        }

        let symbol = [
            ("&&", Token::And),
            ("||", Token::Or),
            (">=", Token::Cmp(CmpOp::Gte)),
            ("<=", Token::Cmp(CmpOp::Lte)),
            (">", Token::Cmp(CmpOp::Gt)),
            ("<", Token::Cmp(CmpOp::Lt)),
            ("!", Token::Not),
            ("(", Token::Open),
            (")", Token::Close),
            ("[", Token::RangeOpen),
            ("]", Token::RangeClose),
        ]
        .into_iter()
        .find(|(text, _)| rest.starts_with(text));
        if let Some((text, token)) = symbol {
            match token {
                Token::RangeOpen => range_depth += 1,
                Token::RangeClose => range_depth = range_depth.saturating_sub(1),
                _ => {}
            }
            tokens.push(SpannedToken { token, separated });
            separated = false;
            index += text.len();
            continue;
        }

        if ch == ':' {
            let token = if matches!(tokens.last().map(|item| &item.token), Some(Token::Field(_))) {
                Token::Colon
            } else {
                Token::StrayColon
            };
            tokens.push(SpannedToken { token, separated });
            separated = false;
            index += 1;
            continue;
        }

        // A value may contain colons, as in `ipAddress:fe80::1`.
        let allow_colon = matches!(
            tokens.last().map(|item| &item.token),
            Some(Token::Colon | Token::RangeOpen | Token::Cmp(_) | Token::To)
        );
        let end = read_date_time(rest)
            .or_else(|| read_time(rest))
            .map_or_else(|| read_word(src, index, allow_colon), |len| index + len);
        let text = &src[index..end];
        let token = if src[end..].trim_start().starts_with(':') && is_field_name(text) {
            Token::Field(text.to_owned())
        } else if text.eq_ignore_ascii_case("AND") {
            Token::And
        } else if text.eq_ignore_ascii_case("OR") {
            Token::Or
        } else if text.eq_ignore_ascii_case("NOT") {
            Token::Not
        } else if range_depth > 0 && text.eq_ignore_ascii_case("TO") {
            Token::To
        } else {
            Token::Word(text.to_owned())
        };
        tokens.push(SpannedToken { token, separated });
        separated = false;
        index = end;
    }

    Ok(tokens)
}

/// A quoted phrase in `"` or `'`; a backslash makes the next character literal.
fn read_quoted(src: &str, from: usize, quote: char) -> Result<(String, usize), AuditQueryError> {
    let body = from + quote.len_utf8();
    let mut out = String::new();
    let mut chars = src[body..].char_indices();
    while let Some((offset, ch)) = chars.next() {
        if ch == '\\' {
            if let Some((_, escaped)) = chars.next() {
                out.push(escaped);
            }
            continue;
        }
        if ch == quote {
            return Ok((out, body + offset + ch.len_utf8()));
        }
        out.push(ch);
    }
    Err(syntax("unclosed quoted string"))
}

/// An unquoted term. It ends at whitespace or a character with a meaning of
/// its own; a backslash keeps the next character in the term.
fn read_word(src: &str, from: usize, allow_colon: bool) -> usize {
    let mut index = from;
    let mut chars = src[from..].chars();
    while let Some(ch) = chars.next() {
        let stops = ch.is_whitespace()
            || matches!(
                ch,
                '(' | ')'
                    | '['
                    | ']'
                    | '{'
                    | '}'
                    | '!'
                    | '&'
                    | '|'
                    | '<'
                    | '>'
                    | '~'
                    | '^'
                    | '"'
                    | '\''
            )
            || (ch == ':' && !allow_colon);
        if stops {
            break;
        }
        index += ch.len_utf8();
        if ch == '\\'
            && let Some(escaped) = chars.next()
        {
            index += escaped.len_utf8();
        }
    }
    if index == from {
        // A lone `&` or `|` is a term of its own.
        index + src[from..].chars().next().map_or(0, char::len_utf8)
    } else {
        index
    }
}

/// Whether a `+` or `-` starts a clause: it begins a word, something follows
/// it, and no field, comparison, or range waits for a value.
fn is_prefix_position(src: &str, index: usize, previous: Option<&Token>) -> bool {
    let followed = src[index + 1..]
        .chars()
        .next()
        .is_some_and(|ch| !ch.is_whitespace());
    let starts_word = src[..index]
        .chars()
        .next_back()
        .is_none_or(|ch| ch.is_whitespace() || ch == '(');
    followed
        && starts_word
        && !matches!(
            previous,
            Some(Token::Colon | Token::Cmp(_) | Token::RangeOpen | Token::To)
        )
}

fn digits(bytes: &[u8], from: usize, count: usize) -> bool {
    bytes.len() >= from + count && bytes[from..from + count].iter().all(u8::is_ascii_digit)
}

fn is_term_boundary(rest: &str, len: usize) -> bool {
    rest[len..].chars().next().is_none_or(|ch| {
        ch.is_whitespace()
            || matches!(
                ch,
                '(' | ')'
                    | '['
                    | ']'
                    | '{'
                    | '}'
                    | '!'
                    | '&'
                    | '|'
                    | '<'
                    | '>'
                    | '~'
                    | '^'
                    | '"'
                    | '\''
            )
    })
}

/// `HH:MM:SS` with up to three fractional digits.
fn read_time_prefix(rest: &str) -> Option<usize> {
    let bytes = rest.as_bytes();
    let shape = digits(bytes, 0, 2)
        && bytes.get(2) == Some(&b':')
        && digits(bytes, 3, 2)
        && bytes.get(5) == Some(&b':')
        && digits(bytes, 6, 2);
    if !shape {
        return None;
    }
    let mut len = 8;
    if bytes.get(len) == Some(&b'.') {
        let fraction = bytes[len + 1..]
            .iter()
            .take(9)
            .take_while(|byte| byte.is_ascii_digit())
            .count();
        if fraction > 0 {
            len += 1 + fraction;
        }
    }
    Some(len)
}

fn read_time(rest: &str) -> Option<usize> {
    read_time_prefix(rest).filter(|&len| is_term_boundary(rest, len))
}

/// An ISO 8601 date and time with a zone, such as `2026-11-19T00:00:00Z`.
fn read_date_time(rest: &str) -> Option<usize> {
    let bytes = rest.as_bytes();
    let date = digits(bytes, 0, 4)
        && bytes.get(4) == Some(&b'-')
        && digits(bytes, 5, 2)
        && bytes.get(7) == Some(&b'-')
        && digits(bytes, 8, 2)
        && bytes.get(10) == Some(&b'T');
    if !date {
        return None;
    }
    let mut len = 11 + read_time_prefix(&rest[11..])?;
    match bytes.get(len) {
        Some(b'Z') => len += 1,
        Some(b'+' | b'-') if digits(bytes, len + 1, 2) => {
            len += 3;
            if bytes.get(len) == Some(&b':') {
                len += 1;
            }
            if !digits(bytes, len, 2) {
                return None;
            }
            len += 2;
        }
        _ => return None,
    }
    is_term_boundary(rest, len).then_some(len)
}

fn is_field_name(text: &str) -> bool {
    let mut chars = text.chars();
    chars
        .next()
        .is_some_and(|ch| ch.is_ascii_alphabetic() || ch == '_')
        && chars.all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '_' | '.' | '-'))
}

fn unexpected_token(token: &Token) -> AuditQueryError {
    syntax(match token {
        Token::Close => "unmatched closing parenthesis",
        Token::RangeClose => "unexpected range closing bracket",
        Token::StrayColon => "missing field name before colon",
        Token::And | Token::Or => "unexpected binary boolean operator",
        Token::Cmp(_) => "comparison operator must follow a field name",
        Token::RangeOpen => "range query must follow a field name",
        _ => "unexpected trailing tokens",
    })
}

/// A term's value as the query states it.
enum TermValue {
    Quoted(String),
    Word(String),
}

impl TermValue {
    /// The value with escapes resolved.
    fn text(&self) -> String {
        match self {
            Self::Quoted(value) => value.clone(),
            Self::Word(raw) => {
                let mut out = String::with_capacity(raw.len());
                let mut chars = raw.chars();
                while let Some(ch) = chars.next() {
                    if ch == '\\'
                        && let Some(escaped) = chars.next()
                    {
                        out.push(escaped);
                    } else {
                        out.push(ch);
                    }
                }
                out
            }
        }
    }

    fn is_bare_star(&self) -> bool {
        matches!(self, Self::Word(raw) if raw == "*")
    }

    /// Reject fuzzy (`~`) and boost (`^`) suffixes, which are not supported.
    fn check_supported(&self) -> Result<(), AuditQueryError> {
        let Self::Word(raw) = self else {
            return Ok(());
        };
        for piece in wildcard_pieces(raw) {
            match piece {
                Piece::Char('~') => return Err(AuditQueryError::UnsupportedFuzzy),
                Piece::Char('^') => return Err(AuditQueryError::UnsupportedBoost),
                _ => {}
            }
        }
        Ok(())
    }
}

/// A character of an unquoted term: literal, or an unescaped wildcard.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Piece {
    Char(char),
    Escaped(char),
    Any,
    One,
}

fn wildcard_pieces(raw: &str) -> Vec<Piece> {
    let mut pieces = Vec::with_capacity(raw.len());
    let mut chars = raw.chars();
    while let Some(ch) = chars.next() {
        pieces.push(match ch {
            '\\' => match chars.next() {
                Some(escaped) => Piece::Escaped(escaped),
                None => Piece::Char('\\'),
            },
            '*' => Piece::Any,
            '?' => Piece::One,
            other => Piece::Char(other),
        });
    }
    pieces
}

struct Parser {
    tokens: Vec<SpannedToken>,
    pos: usize,
    clauses: usize,
    reference_now: DateTime<Utc>,
    tz: Tz,
}

impl Parser {
    fn peek(&self) -> Option<&Token> {
        self.tokens.get(self.pos).map(|item| &item.token)
    }

    fn peek_separated(&self) -> bool {
        self.tokens.get(self.pos).is_some_and(|item| item.separated)
    }

    fn advance(&mut self) -> Option<Token> {
        let token = self.tokens.get(self.pos).map(|item| item.token.clone());
        self.pos += 1;
        token
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

    fn starts_primary(&self, in_field_group: bool) -> bool {
        matches!(
            self.peek(),
            Some(Token::Not | Token::Open | Token::Field(_) | Token::Quoted(_) | Token::Word(_))
        ) || (in_field_group && matches!(self.peek(), Some(Token::Cmp(_) | Token::RangeOpen)))
    }

    fn starts_field_term(&self) -> bool {
        matches!(
            self.peek(),
            Some(
                Token::Not
                    | Token::Open
                    | Token::Cmp(_)
                    | Token::RangeOpen
                    | Token::Quoted(_)
                    | Token::Word(_)
            )
        )
    }

    /// Clauses side by side: every one must match. This binds more loosely
    /// than `OR`, so `a b OR c` means `a AND (b OR c)`.
    fn parse_implicit(
        &mut self,
        field: Option<AuditQueryField>,
        depth: usize,
    ) -> Result<AuditQueryExpr, AuditQueryError> {
        let mut items = vec![self.parse_or(field, depth)?];
        while self.peek_separated() && self.starts_primary(field.is_some()) {
            items.push(self.parse_or(field, depth)?);
        }
        Ok(join(items, false))
    }

    fn parse_or(
        &mut self,
        field: Option<AuditQueryField>,
        depth: usize,
    ) -> Result<AuditQueryExpr, AuditQueryError> {
        let mut items = vec![self.parse_and(field, depth)?];
        while self.peek() == Some(&Token::Or) {
            self.advance();
            items.push(self.parse_and(field, depth)?);
        }
        Ok(join(items, true))
    }

    fn parse_and(
        &mut self,
        field: Option<AuditQueryField>,
        depth: usize,
    ) -> Result<AuditQueryExpr, AuditQueryError> {
        let mut items = vec![self.parse_primary(field, depth)?];
        while self.peek() == Some(&Token::And) {
            self.advance();
            items.push(self.parse_primary(field, depth)?);
        }
        Ok(join(items, false))
    }

    /// A clause. Inside a field group, `field` is the field bare terms apply to.
    fn parse_primary(
        &mut self,
        field: Option<AuditQueryField>,
        depth: usize,
    ) -> Result<AuditQueryExpr, AuditQueryError> {
        match self.peek() {
            None => Err(syntax("expected query clause")),
            Some(Token::Not) => {
                self.advance();
                if !self.starts_primary(field.is_some()) {
                    return Err(syntax("missing operand after unary operator"));
                }
                let inner = self.parse_primary(field, depth)?;
                Ok(AuditQueryExpr::Not(Box::new(inner)))
            }
            Some(Token::Open) => self.parse_group(field, depth),
            Some(&Token::Cmp(op)) if field.is_some() => {
                self.advance();
                self.parse_comparison(field.expect("checked"), op)
            }
            Some(Token::RangeOpen) if field.is_some() => self.parse_range(field.expect("checked")),
            Some(Token::Field(name)) => {
                let name = name.clone();
                self.advance();
                self.advance(); // the colon
                let field = AuditQueryField::parse(&name)
                    .ok_or(AuditQueryError::UnknownField { field: name })?;
                self.parse_field_term(field, depth)
            }
            Some(Token::Quoted(_) | Token::Word(_)) => {
                let value = self.take_value().expect("checked term token");
                self.leaf(field, &value)
            }
            Some(Token::Close) => Err(syntax("expected query clause")),
            Some(token) => Err(unexpected_token(token)),
        }
    }

    fn parse_group(
        &mut self,
        field: Option<AuditQueryField>,
        depth: usize,
    ) -> Result<AuditQueryExpr, AuditQueryError> {
        self.advance();
        let depth = depth + 1;
        if depth > MAX_AUDIT_QUERY_DEPTH {
            return Err(AuditQueryError::TooDeeplyNested {
                max: MAX_AUDIT_QUERY_DEPTH,
            });
        }
        if self.peek() == Some(&Token::Close) {
            return Err(syntax(if field.is_some() {
                "empty field group"
            } else {
                "empty parenthesized group"
            }));
        }
        let inner = self.parse_implicit(field, depth)?;
        match self.advance() {
            Some(Token::Close) => Ok(inner),
            None => Err(syntax("unclosed parenthesis")),
            Some(token) => Err(unexpected_token(&token)),
        }
    }

    fn parse_field_term(
        &mut self,
        field: AuditQueryField,
        depth: usize,
    ) -> Result<AuditQueryExpr, AuditQueryError> {
        match self.peek() {
            Some(Token::Not) => {
                self.advance();
                if !self.starts_field_term() {
                    return Err(syntax("missing operand after unary operator"));
                }
                let inner = self.parse_field_term(field, depth)?;
                Ok(AuditQueryExpr::Not(Box::new(inner)))
            }
            Some(Token::Open) => self.parse_group(Some(field), depth),
            Some(&Token::Cmp(op)) => {
                self.advance();
                self.parse_comparison(field, op)
            }
            Some(Token::RangeOpen) => self.parse_range(field),
            Some(Token::Quoted(_) | Token::Word(_)) => {
                let value = self.take_value().expect("checked term token");
                self.leaf(Some(field), &value)
            }
            Some(Token::And | Token::Or) => Err(syntax(
                "boolean keyword cannot be used as an unquoted field value",
            )),
            _ => Err(syntax("missing value after field colon")),
        }
    }

    fn parse_comparison(
        &mut self,
        field: AuditQueryField,
        op: CmpOp,
    ) -> Result<AuditQueryExpr, AuditQueryError> {
        let Some(value) = self.take_value() else {
            return Err(syntax(if self.peek() == Some(&Token::RangeOpen) {
                "unexpected bracket after comparison operator"
            } else {
                "missing value after comparison operator"
            }));
        };
        if !field.is_date() {
            return Err(AuditQueryError::UnsupportedOperator {
                field: field.as_str(),
            });
        }
        value.check_supported()?;
        let text = value.text();
        if text.is_empty() {
            return Err(AuditQueryError::InvalidDateValue { value: text });
        }
        self.record_clause()?;
        build_occurred_at_cmp(op, &text, self.reference_now, self.tz)
    }

    /// `[start TO end]`, both ends inclusive.
    fn parse_range(&mut self, field: AuditQueryField) -> Result<AuditQueryExpr, AuditQueryError> {
        self.advance();
        if !field.is_date() {
            return Err(AuditQueryError::UnsupportedRangeField {
                field: field.as_str(),
            });
        }
        let start = self
            .take_bound()?
            .ok_or(syntax("missing lower bound in range"))?;
        if self.advance() != Some(Token::To) {
            return Err(syntax("expected TO inside range query"));
        }
        let end = self
            .take_bound()?
            .ok_or(syntax("missing upper bound in range"))?;
        if self.advance() != Some(Token::RangeClose) {
            return Err(syntax("unclosed range bracket"));
        }
        self.record_clause()?;
        build_occurred_at_range(&start, true, &end, true, self.reference_now, self.tz)
    }

    fn take_value(&mut self) -> Option<TermValue> {
        let value = match self.peek()? {
            Token::Quoted(value) => TermValue::Quoted(value.clone()),
            Token::Word(raw) => TermValue::Word(raw.clone()),
            _ => return None,
        };
        self.advance();
        Some(value)
    }

    fn take_bound(&mut self) -> Result<Option<TermValue>, AuditQueryError> {
        let Some(value) = self.take_value() else {
            return Ok(None);
        };
        value.check_supported()?;
        Ok((!value.text().is_empty()).then_some(value))
    }

    fn leaf(
        &mut self,
        field: Option<AuditQueryField>,
        value: &TermValue,
    ) -> Result<AuditQueryExpr, AuditQueryError> {
        value.check_supported()?;
        self.record_clause()?;
        match field {
            Some(field) => build_field_predicate(field, value, self.reference_now, self.tz),
            None => Ok(AuditQueryExpr::FreeText(value.text())),
        }
    }
}

/// Combine clauses, flattening nested lists of the same kind.
fn join(items: Vec<AuditQueryExpr>, or: bool) -> AuditQueryExpr {
    if items.len() == 1 {
        return items.into_iter().next().expect("checked len == 1");
    }
    let mut flat = Vec::with_capacity(items.len());
    for item in items {
        match (or, item) {
            (false, AuditQueryExpr::And(children)) | (true, AuditQueryExpr::Or(children)) => {
                flat.extend(children);
            }
            (_, other) => flat.push(other),
        }
    }
    if or {
        AuditQueryExpr::Or(flat)
    } else {
        AuditQueryExpr::And(flat)
    }
}

fn build_field_predicate(
    field: AuditQueryField,
    value: &TermValue,
    reference_now: DateTime<Utc>,
    tz: Tz,
) -> Result<AuditQueryExpr, AuditQueryError> {
    if field.is_date() {
        if value.is_bare_star() {
            return Ok(AuditQueryExpr::OccurredAtRange {
                min: None,
                max: None,
            });
        }
        return match parse_time_value(&value.text(), reference_now, tz)? {
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
        };
    }

    if field.is_identifier() {
        if value.is_bare_star() {
            return Ok(AuditQueryExpr::Identifier {
                field,
                value: AuditIdentifierMatch::Exists,
            });
        }
        let oid = resolve_identifier(field, &value.text())?;
        return Ok(AuditQueryExpr::Identifier {
            field,
            value: AuditIdentifierMatch::Exact(oid),
        });
    }

    let matcher = match build_text_matcher(value) {
        AuditTextMatcher::Exact(exact) => {
            AuditTextMatcher::Exact(field.canonical_value(&exact).ok_or_else(|| {
                AuditQueryError::UnknownValue {
                    field: field.as_str(),
                    value: exact,
                }
            })?)
        }
        other => other,
    };
    Ok(AuditQueryExpr::Text { field, matcher })
}

/// A quoted phrase matches exactly. In an unquoted term, `*` and `?` are
/// wildcards unless escaped with a backslash.
fn build_text_matcher(value: &TermValue) -> AuditTextMatcher {
    let TermValue::Word(raw) = value else {
        return AuditTextMatcher::Exact(value.text());
    };
    let pieces = wildcard_pieces(raw);
    let literal = |pieces: &[Piece]| -> Option<String> {
        pieces
            .iter()
            .map(|piece| match piece {
                Piece::Char(ch) | Piece::Escaped(ch) => Some(*ch),
                Piece::Any | Piece::One => None,
            })
            .collect()
    };

    if let Some(text) = literal(&pieces) {
        return AuditTextMatcher::Exact(text);
    }
    if pieces == [Piece::Any] {
        return AuditTextMatcher::Exists;
    }
    if let [rest @ .., Piece::Any] = pieces.as_slice()
        && let Some(prefix) = literal(rest)
        && !prefix.is_empty()
    {
        return AuditTextMatcher::Prefix(prefix);
    }
    if let [Piece::Any, middle @ .., Piece::Any] = pieces.as_slice()
        && let Some(middle) = literal(middle)
        && !middle.is_empty()
    {
        return AuditTextMatcher::Contains(middle);
    }

    // The pattern keeps `*` and `?` as wildcards and escapes literal ones.
    let mut pattern = String::with_capacity(raw.len());
    for piece in pieces {
        match piece {
            Piece::Any => pattern.push('*'),
            Piece::One => pattern.push('?'),
            Piece::Char(ch) | Piece::Escaped(ch) => {
                if matches!(ch, '*' | '?' | '\\') {
                    pattern.push('\\');
                }
                pattern.push(ch);
            }
        }
    }
    AuditTextMatcher::Wildcard(pattern)
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
    };
    Ok(AuditQueryExpr::OccurredAtRange { min, max })
}

fn build_occurred_at_range(
    min_term: &TermValue,
    min_inclusive: bool,
    max_term: &TermValue,
    max_inclusive: bool,
    reference_now: DateTime<Utc>,
    tz: Tz,
) -> Result<AuditQueryExpr, AuditQueryError> {
    let min_val = if min_term.is_bare_star() {
        None
    } else {
        Some(parse_time_value(&min_term.text(), reference_now, tz)?)
    };
    let max_val = if max_term.is_bare_star() {
        None
    } else {
        Some(parse_time_value(&max_term.text(), reference_now, tz)?)
    };

    let min = match min_val {
        None => None,
        Some(ParsedTimeValue::Exact(t)) => Some(AuditTimeBound {
            instant: t,
            inclusive: min_inclusive,
        }),
        Some(ParsedTimeValue::CalendarDay {
            start,
            next_day_start,
        }) => Some(AuditTimeBound {
            instant: if min_inclusive { start } else { next_day_start },
            inclusive: true,
        }),
    };

    let max = match max_val {
        None => None,
        Some(ParsedTimeValue::Exact(t)) => Some(AuditTimeBound {
            instant: t,
            inclusive: max_inclusive,
        }),
        Some(ParsedTimeValue::CalendarDay {
            start,
            next_day_start,
        }) => Some(AuditTimeBound {
            instant: if max_inclusive { next_day_start } else { start },
            inclusive: false,
        }),
    };

    if let (Some(lower), Some(upper)) = (min, max)
        && (lower.instant > upper.instant
            || (lower.instant == upper.instant && (!lower.inclusive || !upper.inclusive)))
    {
        return Err(AuditQueryError::InvalidDateValue {
            value: format!("{} TO {}", min_term.text(), max_term.text()),
        });
    }

    Ok(AuditQueryExpr::OccurredAtRange { min, max })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ParsedTimeValue {
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

    for fmt in ["%Y-%m-%dT%H:%M:%S%.f%z", "%Y-%m-%dT%H:%M:%S%z"] {
        if let Ok(dt) = DateTime::parse_from_str(raw, fmt) {
            return Ok(ParsedTimeValue::Exact(dt.with_timezone(&Utc)));
        }
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
        let (unit, unit_len) = if rest.starts_with("ms") {
            ("ms", 2)
        } else if let Some(ch) = rest.chars().next() {
            (&rest[..ch.len_utf8()], ch.len_utf8())
        } else {
            return Err(AuditQueryError::InvalidDateValue {
                value: raw.to_owned(),
            });
        };
        rest = &rest[unit_len..];
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
    unit: &str,
    raw: &str,
) -> Result<DateTime<Utc>, AuditQueryError> {
    let amount_i64 = i64::from(amount);
    let delta_i64 = if add { amount_i64 } else { -amount_i64 };
    match unit {
        "ms" => instant
            .checked_add_signed(Duration::milliseconds(delta_i64))
            .ok_or_else(|| AuditQueryError::InvalidDateValue {
                value: raw.to_owned(),
            }),
        "s" => instant
            .checked_add_signed(Duration::seconds(delta_i64))
            .ok_or_else(|| AuditQueryError::InvalidDateValue {
                value: raw.to_owned(),
            }),
        "m" => instant
            .checked_add_signed(Duration::minutes(delta_i64))
            .ok_or_else(|| AuditQueryError::InvalidDateValue {
                value: raw.to_owned(),
            }),
        "h" => instant
            .checked_add_signed(Duration::hours(delta_i64))
            .ok_or_else(|| AuditQueryError::InvalidDateValue {
                value: raw.to_owned(),
            }),
        "d" | "w" => {
            let days = if unit == "w" {
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
        "M" => {
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
        "y" => {
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

    /// The query input's tree shape for a parsed query: see `grammar-cases.json`.
    fn shape(expr: &AuditQueryExpr) -> serde_json::Value {
        use serde_json::json;
        match expr {
            AuditQueryExpr::And(items) => {
                json!({ "and": items.iter().map(shape).collect::<Vec<_>>() })
            }
            AuditQueryExpr::Or(items) => {
                json!({ "or": items.iter().map(shape).collect::<Vec<_>>() })
            }
            AuditQueryExpr::Not(inner) => json!({ "not": shape(inner) }),
            AuditQueryExpr::Text { field, matcher } => {
                let value = match matcher {
                    AuditTextMatcher::Exact(value) | AuditTextMatcher::Wildcard(value) => {
                        value.clone()
                    }
                    AuditTextMatcher::Prefix(prefix) => format!("{prefix}*"),
                    AuditTextMatcher::Contains(middle) => format!("*{middle}*"),
                    AuditTextMatcher::Exists => "*".to_owned(),
                };
                json!({ "field": field.as_str(), "value": value })
            }
            AuditQueryExpr::FreeText(text) => json!({ "text": text }),
            other => json!({ "unsupported": format!("{other:?}") }),
        }
    }

    #[test]
    fn follows_the_query_input_grammar_cases() {
        let cases: serde_json::Value = serde_json::from_str(include_str!(
            "../../../packages/lucene-input/src/lib/grammar-cases.json"
        ))
        .unwrap();

        for case in cases["valid"].as_array().unwrap() {
            let query = case["query"].as_str().unwrap();
            let parsed = parse_audit_query(query, ref_now(), utc())
                .unwrap_or_else(|error| panic!("{query:?} should parse: {error}"));
            if let Some(tree) = case.get("tree") {
                assert_eq!(&shape(&parsed), tree, "tree of {query:?}");
            }
        }
        for query in cases["invalid"].as_array().unwrap() {
            let query = query.as_str().unwrap();
            assert!(
                parse_audit_query(query, ref_now(), utc()).is_err(),
                "{query:?} should be rejected"
            );
        }
    }

    #[test]
    fn side_by_side_clauses_bind_more_loosely_than_or() {
        let parsed = parse_audit_query(
            "action:(user_create OR GROUP_DELETE) NOT outcome:failure && actorKind:USER OR traceId:*",
            ref_now(),
            utc(),
        )
        .unwrap();

        let text = |field, value: &str| AuditQueryExpr::Text {
            field,
            matcher: AuditTextMatcher::Exact(value.to_owned()),
        };
        assert_eq!(
            parsed,
            AuditQueryExpr::And(vec![
                AuditQueryExpr::Or(vec![
                    text(AuditQueryField::Action, "user_create"),
                    text(AuditQueryField::Action, "group_delete"),
                ]),
                AuditQueryExpr::Or(vec![
                    AuditQueryExpr::And(vec![
                        AuditQueryExpr::Not(Box::new(text(AuditQueryField::Outcome, "failure"))),
                        text(AuditQueryField::ActorKind, "user"),
                    ]),
                    AuditQueryExpr::Text {
                        field: AuditQueryField::TraceId,
                        matcher: AuditTextMatcher::Exists,
                    },
                ]),
            ])
        );
    }

    #[test]
    fn escaped_wildcards_match_literally() {
        let matcher = |query: &str| match parse_audit_query(query, ref_now(), utc()).unwrap() {
            AuditQueryExpr::Text { matcher, .. } => matcher,
            other => panic!("unexpected expr: {other:?}"),
        };

        assert_eq!(
            matcher(r"actorLabel:a\*b"),
            AuditTextMatcher::Exact("a*b".to_owned())
        );
        assert_eq!(
            matcher(r"actorLabel:a\*b*"),
            AuditTextMatcher::Prefix("a*b".to_owned())
        );
        assert_eq!(
            matcher(r"actorLabel:a\?*b"),
            AuditTextMatcher::Wildcard(r"a\?*b".to_owned())
        );
    }

    #[test]
    fn wildcards_and_quoted_strings_map_expected_matchers() {
        let parsed = parse_audit_query(
            r#"action:user_* userAgent:"a:b \"c\"" targetLabel:*client* ipAddress:10.0.0.? "hello world""#,
            ref_now(),
            utc(),
        )
        .unwrap();

        assert_eq!(
            parsed,
            AuditQueryExpr::And(vec![
                AuditQueryExpr::Text {
                    field: AuditQueryField::Action,
                    matcher: AuditTextMatcher::Prefix("user_".to_owned()),
                },
                AuditQueryExpr::Text {
                    field: AuditQueryField::UserAgent,
                    matcher: AuditTextMatcher::Exact("a:b \"c\"".to_owned()),
                },
                AuditQueryExpr::Text {
                    field: AuditQueryField::TargetLabel,
                    matcher: AuditTextMatcher::Contains("client".to_owned()),
                },
                AuditQueryExpr::Text {
                    field: AuditQueryField::IpAddress,
                    matcher: AuditTextMatcher::Wildcard("10.0.0.?".to_owned()),
                },
                AuditQueryExpr::FreeText("hello world".to_owned()),
            ])
        );
    }

    #[test]
    fn identifiers_accept_raw_uuid_global_id_and_exists() {
        let oid = Uuid::new_v4();
        let gid = encode::<kind::User>(oid);
        let query = format!("actor:{oid} target:{gid} client:*");

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
                    field: AuditQueryField::Client,
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
            .map(|i| format!("requestId:s{i}"))
            .collect::<Vec<_>>()
            .join(" ");
        assert_eq!(
            parse_audit_query(&many, ref_now(), utc()).unwrap_err(),
            AuditQueryError::TooManyClauses {
                max: MAX_AUDIT_QUERY_CLAUSES
            }
        );

        let deep = format!(
            "{}outcome:success{}",
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
        assert_eq!(
            parse_audit_query("outcome:denied", ref_now(), utc()).unwrap_err(),
            AuditQueryError::UnknownValue {
                field: "outcome",
                value: "denied".to_owned()
            }
        );
        assert!(parse_audit_query(r#"action:"role.update""#, ref_now(), utc()).is_err());
        assert!(matches!(
            parse_audit_query("action:\"unterminated", ref_now(), utc()).unwrap_err(),
            AuditQueryError::SyntaxError { .. }
        ));
    }

    #[test]
    fn field_groups_support_comparisons_ranges_and_multi_step_date_math() {
        let now = Utc.with_ymd_and_hms(2026, 11, 20, 10, 30, 45).unwrap();
        let grouped = parse_audit_query("occurredAt:(>=now-7d AND <now)", now, utc()).unwrap();
        assert_eq!(
            grouped,
            AuditQueryExpr::And(vec![
                AuditQueryExpr::OccurredAtRange {
                    min: Some(AuditTimeBound {
                        instant: now - Duration::days(7),
                        inclusive: true,
                    }),
                    max: None,
                },
                AuditQueryExpr::OccurredAtRange {
                    min: None,
                    max: Some(AuditTimeBound {
                        instant: now,
                        inclusive: false,
                    }),
                },
            ])
        );

        let grouped_or_range =
            parse_audit_query("occurredAt:([now-7d TO now-1d] OR >=now-1h)", now, utc()).unwrap();
        assert_eq!(
            grouped_or_range,
            AuditQueryExpr::Or(vec![
                AuditQueryExpr::OccurredAtRange {
                    min: Some(AuditTimeBound {
                        instant: now - Duration::days(7),
                        inclusive: true,
                    }),
                    max: Some(AuditTimeBound {
                        instant: now - Duration::days(1),
                        inclusive: true,
                    }),
                },
                AuditQueryExpr::OccurredAtRange {
                    min: Some(AuditTimeBound {
                        instant: now - Duration::hours(1),
                        inclusive: true,
                    }),
                    max: None,
                },
            ])
        );

        let multi_math = parse_audit_query("occurredAt:now-1d+2h-500ms/s", now, utc()).unwrap();
        let expected_instant = Utc.with_ymd_and_hms(2026, 11, 19, 12, 30, 44).unwrap();
        assert_eq!(
            multi_math,
            AuditQueryExpr::OccurredAtRange {
                min: Some(AuditTimeBound {
                    instant: expected_instant,
                    inclusive: true,
                }),
                max: Some(AuditTimeBound {
                    instant: expected_instant,
                    inclusive: true,
                }),
            }
        );

        assert!(matches!(
            parse_audit_query("occurredAt:2026-11-25T10:30:00Zfoo", now, utc()).unwrap_err(),
            AuditQueryError::InvalidDateValue { .. }
        ));
    }

    #[test]
    fn implicit_clauses_require_separating_whitespace() {
        let now = Utc.with_ymd_and_hms(2026, 11, 20, 10, 30, 45).unwrap();
        let valid = parse_audit_query("occurredAt:(>=now-7d <now)", now, utc()).unwrap();
        assert_eq!(
            valid,
            AuditQueryExpr::And(vec![
                AuditQueryExpr::OccurredAtRange {
                    min: Some(AuditTimeBound {
                        instant: now - Duration::days(7),
                        inclusive: true,
                    }),
                    max: None,
                },
                AuditQueryExpr::OccurredAtRange {
                    min: None,
                    max: Some(AuditTimeBound {
                        instant: now,
                        inclusive: false,
                    }),
                },
            ])
        );

        for invalid in [
            "occurredAt:(>=now-7d<now)",
            r#"foo"bar""#,
            "(actorLabel:a)(targetLabel:b)",
            "actorLabel:a!targetLabel:b",
        ] {
            assert!(
                parse_audit_query(invalid, now, utc()).is_err(),
                "{invalid:?} should be rejected"
            );
        }
    }

    #[test]
    fn supports_nanosecond_and_colonless_offset_timestamps_and_rejects_quoted_stars() {
        let now = Utc.with_ymd_and_hms(2026, 11, 20, 10, 30, 45).unwrap();

        let sub_ms =
            parse_audit_query("occurredAt:2026-11-20T10:30:45.123456789Z", now, utc()).unwrap();
        let expected_ns = Utc
            .with_ymd_and_hms(2026, 11, 20, 10, 30, 45)
            .unwrap()
            .with_nanosecond(123_456_789)
            .unwrap();
        assert_eq!(
            sub_ms,
            AuditQueryExpr::OccurredAtRange {
                min: Some(AuditTimeBound {
                    instant: expected_ns,
                    inclusive: true,
                }),
                max: Some(AuditTimeBound {
                    instant: expected_ns,
                    inclusive: true,
                }),
            }
        );

        let local_sub_ms =
            parse_audit_query(r#"occurredAt:"2026-11-20 10:30:45.123456""#, now, utc()).unwrap();
        assert!(matches!(
            local_sub_ms,
            AuditQueryExpr::OccurredAtRange { .. }
        ));

        let colonless_offset =
            parse_audit_query("occurredAt:2026-11-20T18:30:45+0800", now, utc()).unwrap();
        assert_eq!(
            colonless_offset,
            AuditQueryExpr::OccurredAtRange {
                min: Some(AuditTimeBound {
                    instant: now,
                    inclusive: true,
                }),
                max: Some(AuditTimeBound {
                    instant: now,
                    inclusive: true,
                }),
            }
        );

        assert!(matches!(
            parse_audit_query("occurredAt:*", now, utc()).unwrap(),
            AuditQueryExpr::OccurredAtRange {
                min: None,
                max: None
            }
        ));
        assert!(matches!(
            parse_audit_query("occurredAt:[* TO now]", now, utc()).unwrap(),
            AuditQueryExpr::OccurredAtRange {
                min: None,
                max: Some(_),
            }
        ));

        for invalid in [
            r#"occurredAt:"*""#,
            r"occurredAt:\*",
            r#"occurredAt:["*" TO now]"#,
            r"occurredAt:[\* TO now]",
        ] {
            assert!(
                parse_audit_query(invalid, now, utc()).is_err(),
                "{invalid:?} should be rejected"
            );
        }
    }
}
