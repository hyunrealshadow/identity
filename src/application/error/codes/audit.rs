//! Audit log query error catalog. Reserved range: 30000-30099.

use crate::error::{code::AppErrorCode, kind::ErrorKind};

#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, strum::EnumIter)]
pub enum AuditErrorCode {
    InvalidCursor = 30000,
    InvalidPageSize = 30001,
    InvalidTimeZone = 30002,
    QueryTooLong = 30003,
    QueryTooManyClauses = 30004,
    QueryTooDeep = 30005,
    QuerySyntaxError = 30006,
    QueryUnknownField = 30007,
    QueryInvalidDate = 30008,
    QueryInvalidIdentifier = 30009,
    QueryUnsupportedOperator = 30010,
    QueryUnsupportedRangeField = 30011,
    QueryUnsupportedRegex = 30012,
    QueryUnsupportedSyntax = 30013,
    QueryUnknownValue = 30014,
}

impl AuditErrorCode {
    #[must_use]
    pub const fn kind(self) -> ErrorKind {
        match self {
            Self::InvalidCursor
            | Self::InvalidPageSize
            | Self::InvalidTimeZone
            | Self::QueryTooLong
            | Self::QueryTooManyClauses
            | Self::QueryTooDeep
            | Self::QuerySyntaxError
            | Self::QueryUnknownField
            | Self::QueryInvalidDate
            | Self::QueryInvalidIdentifier
            | Self::QueryUnsupportedOperator
            | Self::QueryUnsupportedRangeField
            | Self::QueryUnsupportedRegex
            | Self::QueryUnsupportedSyntax
            | Self::QueryUnknownValue => ErrorKind::Validation,
        }
    }
}

impl AppErrorCode for AuditErrorCode {
    fn kind(self) -> ErrorKind {
        Self::kind(self)
    }

    fn code(self) -> u32 {
        self as u32
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AuditErrorCodeDefinition {
    pub code: AuditErrorCode,
    pub numeric_code: u32,
    pub kind: ErrorKind,
    pub fluent_key: &'static str,
    pub required_params: &'static [&'static str],
    pub optional_params: &'static [&'static str],
    pub usage_module: &'static str,
}

pub const AUDIT_ERROR_INVENTORY: &[AuditErrorCodeDefinition] = &[
    entry(AuditErrorCode::InvalidCursor, "E30000", &[], &[], "audit"),
    entry(
        AuditErrorCode::InvalidPageSize,
        "E30001",
        &["max"],
        &[],
        "audit",
    ),
    entry(
        AuditErrorCode::InvalidTimeZone,
        "E30002",
        &["value"],
        &[],
        "audit",
    ),
    entry(
        AuditErrorCode::QueryTooLong,
        "E30003",
        &["max"],
        &["actual"],
        "audit",
    ),
    entry(
        AuditErrorCode::QueryTooManyClauses,
        "E30004",
        &["max"],
        &[],
        "audit",
    ),
    entry(
        AuditErrorCode::QueryTooDeep,
        "E30005",
        &["max"],
        &[],
        "audit",
    ),
    entry(
        AuditErrorCode::QuerySyntaxError,
        "E30006",
        &[],
        &[],
        "audit",
    ),
    entry(
        AuditErrorCode::QueryUnknownField,
        "E30007",
        &["field"],
        &[],
        "audit",
    ),
    entry(
        AuditErrorCode::QueryInvalidDate,
        "E30008",
        &["value"],
        &[],
        "audit",
    ),
    entry(
        AuditErrorCode::QueryInvalidIdentifier,
        "E30009",
        &["field", "value"],
        &[],
        "audit",
    ),
    entry(
        AuditErrorCode::QueryUnsupportedOperator,
        "E30010",
        &["field"],
        &[],
        "audit",
    ),
    entry(
        AuditErrorCode::QueryUnsupportedRangeField,
        "E30011",
        &["field"],
        &[],
        "audit",
    ),
    entry(
        AuditErrorCode::QueryUnsupportedRegex,
        "E30012",
        &[],
        &[],
        "audit",
    ),
    entry(
        AuditErrorCode::QueryUnsupportedSyntax,
        "E30013",
        &[],
        &[],
        "audit",
    ),
    entry(
        AuditErrorCode::QueryUnknownValue,
        "E30014",
        &["field", "value"],
        &[],
        "audit",
    ),
];

const fn entry(
    code: AuditErrorCode,
    fluent_key: &'static str,
    required_params: &'static [&'static str],
    optional_params: &'static [&'static str],
    usage_module: &'static str,
) -> AuditErrorCodeDefinition {
    AuditErrorCodeDefinition {
        code,
        numeric_code: code as u32,
        kind: code.kind(),
        fluent_key,
        required_params,
        optional_params,
        usage_module,
    }
}

#[must_use]
pub fn inventory() -> &'static [AuditErrorCodeDefinition] {
    AUDIT_ERROR_INVENTORY
}

#[must_use]
pub fn definition(code: AuditErrorCode) -> Option<&'static AuditErrorCodeDefinition> {
    AUDIT_ERROR_INVENTORY
        .iter()
        .find(|definition| definition.code == code)
}
