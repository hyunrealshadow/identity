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

impl AppErrorCode for AuditErrorCode {
    fn kind(self) -> ErrorKind {
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

    fn code(self) -> u32 {
        self as u32
    }

    fn required_params(self) -> &'static [&'static str] {
        match self {
            Self::InvalidPageSize
            | Self::QueryTooLong
            | Self::QueryTooManyClauses
            | Self::QueryTooDeep => &["max"],
            Self::InvalidTimeZone | Self::QueryInvalidDate => &["value"],
            Self::QueryUnknownField
            | Self::QueryUnsupportedOperator
            | Self::QueryUnsupportedRangeField => &["field"],
            Self::QueryInvalidIdentifier | Self::QueryUnknownValue => &["field", "value"],
            _ => &[],
        }
    }

    fn optional_params(self) -> &'static [&'static str] {
        match self {
            Self::QueryTooLong => &["actual"],
            _ => &[],
        }
    }
}
