//! Resolving occurred_at comparisons, ranges and date math in the viewer's time zone.

use super::*;

pub(super) fn build_occurred_at_cmp(
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

pub(super) fn build_occurred_at_range(
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
pub(super) enum ParsedTimeValue {
    Exact(DateTime<Utc>),
    CalendarDay {
        start: DateTime<Utc>,
        next_day_start: DateTime<Utc>,
    },
}

pub(super) fn parse_time_value(
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

pub(super) fn parse_date_math(
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

pub(super) fn apply_date_math_offset(
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

pub(super) fn floor_date_unit(
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

pub(super) fn resolve_local_midnight(
    tz: Tz,
    date: NaiveDate,
) -> Result<DateTime<Utc>, AuditQueryError> {
    let midnight = NaiveTime::from_hms_opt(0, 0, 0).expect("valid midnight");
    Ok(resolve_local_datetime(
        tz,
        NaiveDateTime::new(date, midnight),
    ))
}

pub(super) fn resolve_local_datetime(tz: Tz, naive: NaiveDateTime) -> DateTime<Utc> {
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
