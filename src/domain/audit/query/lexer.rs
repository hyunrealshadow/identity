//! Tokenizing the Lucene-style audit query text.

use super::*;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum CmpOp {
    Gt,
    Gte,
    Lt,
    Lte,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum Token {
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
pub(super) struct SpannedToken {
    pub(super) token: Token,
    pub(super) separated: bool,
}

pub(super) fn syntax(detail: &'static str) -> AuditQueryError {
    AuditQueryError::SyntaxError { detail }
}

/// Split a query into tokens the way the query input's tokenizer does.
pub(super) fn tokenize(src: &str) -> Result<Vec<SpannedToken>, AuditQueryError> {
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
pub(super) fn read_quoted(
    src: &str,
    from: usize,
    quote: char,
) -> Result<(String, usize), AuditQueryError> {
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
pub(super) fn read_word(src: &str, from: usize, allow_colon: bool) -> usize {
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
pub(super) fn is_prefix_position(src: &str, index: usize, previous: Option<&Token>) -> bool {
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

pub(super) fn digits(bytes: &[u8], from: usize, count: usize) -> bool {
    bytes.len() >= from + count && bytes[from..from + count].iter().all(u8::is_ascii_digit)
}

pub(super) fn is_term_boundary(rest: &str, len: usize) -> bool {
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
pub(super) fn read_time_prefix(rest: &str) -> Option<usize> {
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

pub(super) fn read_time(rest: &str) -> Option<usize> {
    read_time_prefix(rest).filter(|&len| is_term_boundary(rest, len))
}

/// An ISO 8601 date and time with a zone, such as `2026-11-19T00:00:00Z`.
pub(super) fn read_date_time(rest: &str) -> Option<usize> {
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

pub(super) fn is_field_name(text: &str) -> bool {
    let mut chars = text.chars();
    chars
        .next()
        .is_some_and(|ch| ch.is_ascii_alphabetic() || ch == '_')
        && chars.all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '_' | '.' | '-'))
}

pub(super) fn unexpected_token(token: &Token) -> AuditQueryError {
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
