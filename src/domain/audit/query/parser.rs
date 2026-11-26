//! Recursive-descent parsing of query tokens into expressions.

use super::*;

/// A term's value as the query states it.
pub(super) enum TermValue {
    Quoted(String),
    Word(String),
}

impl TermValue {
    /// The value with escapes resolved.
    pub(super) fn text(&self) -> String {
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

    pub(super) fn is_bare_star(&self) -> bool {
        matches!(self, Self::Word(raw) if raw == "*")
    }

    /// Reject fuzzy (`~`) and boost (`^`) suffixes, which are not supported.
    pub(super) fn check_supported(&self) -> Result<(), AuditQueryError> {
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
pub(super) enum Piece {
    Char(char),
    Escaped(char),
    Any,
    One,
}

pub(super) fn wildcard_pieces(raw: &str) -> Vec<Piece> {
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

pub(super) struct Parser {
    pub(super) tokens: Vec<SpannedToken>,
    pub(super) pos: usize,
    pub(super) clauses: usize,
    pub(super) reference_now: DateTime<Utc>,
    pub(super) tz: Tz,
}

impl Parser {
    pub(super) fn peek(&self) -> Option<&Token> {
        self.tokens.get(self.pos).map(|item| &item.token)
    }

    pub(super) fn peek_separated(&self) -> bool {
        self.tokens.get(self.pos).is_some_and(|item| item.separated)
    }

    pub(super) fn advance(&mut self) -> Option<Token> {
        let token = self.tokens.get(self.pos).map(|item| item.token.clone());
        self.pos += 1;
        token
    }

    pub(super) fn record_clause(&mut self) -> Result<(), AuditQueryError> {
        self.clauses += 1;
        if self.clauses > MAX_AUDIT_QUERY_CLAUSES {
            return Err(AuditQueryError::TooManyClauses {
                max: MAX_AUDIT_QUERY_CLAUSES,
            });
        }
        Ok(())
    }

    pub(super) fn starts_primary(&self, in_field_group: bool) -> bool {
        matches!(
            self.peek(),
            Some(Token::Not | Token::Open | Token::Field(_) | Token::Quoted(_) | Token::Word(_))
        ) || (in_field_group && matches!(self.peek(), Some(Token::Cmp(_) | Token::RangeOpen)))
    }

    pub(super) fn starts_field_term(&self) -> bool {
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
    pub(super) fn parse_implicit(
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

    pub(super) fn parse_or(
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

    pub(super) fn parse_and(
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
    pub(super) fn parse_primary(
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

    pub(super) fn parse_group(
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

    pub(super) fn parse_field_term(
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

    pub(super) fn parse_comparison(
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
    pub(super) fn parse_range(
        &mut self,
        field: AuditQueryField,
    ) -> Result<AuditQueryExpr, AuditQueryError> {
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

    pub(super) fn take_value(&mut self) -> Option<TermValue> {
        let value = match self.peek()? {
            Token::Quoted(value) => TermValue::Quoted(value.clone()),
            Token::Word(raw) => TermValue::Word(raw.clone()),
            _ => return None,
        };
        self.advance();
        Some(value)
    }

    pub(super) fn take_bound(&mut self) -> Result<Option<TermValue>, AuditQueryError> {
        let Some(value) = self.take_value() else {
            return Ok(None);
        };
        value.check_supported()?;
        Ok((!value.text().is_empty()).then_some(value))
    }

    pub(super) fn leaf(
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
pub(super) fn join(items: Vec<AuditQueryExpr>, or: bool) -> AuditQueryExpr {
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
