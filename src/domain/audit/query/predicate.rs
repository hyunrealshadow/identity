//! Building field predicates and text matchers from parsed terms.

use super::*;

pub(super) fn build_field_predicate(
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
pub(super) fn build_text_matcher(value: &TermValue) -> AuditTextMatcher {
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

pub(super) fn resolve_identifier(
    field: AuditQueryField,
    value: &str,
) -> Result<Uuid, AuditQueryError> {
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
