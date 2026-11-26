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
                AuditTextMatcher::Exact(value) | AuditTextMatcher::Wildcard(value) => value.clone(),
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
        "../../../../packages/lucene-input/src/lib/grammar-cases.json"
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
        parse_audit_query(&"a".repeat(MAX_AUDIT_QUERY_LENGTH + 1), ref_now(), utc()).unwrap_err(),
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
        parse_audit_query("occurredAt:[2026-11-21 TO 2026-11-20]", ref_now(), utc()).unwrap_err(),
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
