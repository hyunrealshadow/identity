use crate::error::{code::AppErrorCode, kind::ErrorKind};

/// Stable HTTP/GraphQL envelope errors. Range: 28100-28199.
#[derive(Debug, Clone, Copy, PartialEq, Eq, strum::EnumIter)]
pub enum GraphqlTransportErrorCode {
    InvalidRequest,
    UnsupportedMediaType,
    PayloadTooLarge,
    UriTooLong,
    MethodNotAllowed,
    OriginDenied,
    TimedOut,
    Unauthenticated,
    Internal,
    InvalidToken,
    /// The document exceeds the configured selection depth.
    QueryTooDeep,
    /// The document exceeds the configured operation complexity.
    QueryTooComplex,
}

impl AppErrorCode for GraphqlTransportErrorCode {
    fn kind(self) -> ErrorKind {
        match self {
            Self::Unauthenticated | Self::InvalidToken => ErrorKind::Unauthorized,
            Self::OriginDenied => ErrorKind::Forbidden,
            Self::TimedOut | Self::Internal => ErrorKind::Internal,
            _ => ErrorKind::Validation,
        }
    }

    fn code(self) -> u32 {
        match self {
            Self::InvalidRequest => 28100,
            Self::UnsupportedMediaType => 28101,
            Self::PayloadTooLarge => 28102,
            Self::UriTooLong => 28103,
            Self::MethodNotAllowed => 28104,
            Self::OriginDenied => 28105,
            Self::TimedOut => 28106,
            Self::Unauthenticated => 28107,
            Self::Internal => 28108,
            Self::InvalidToken => 28109,
            Self::QueryTooDeep => 28110,
            Self::QueryTooComplex => 28111,
        }
    }
}
