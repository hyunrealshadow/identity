use std::fmt::{Debug, Display, Formatter, Result as FmtResult};

use async_graphql::connection::CursorType;

const MAX_PROTECTED_CURSOR_LENGTH: usize = 512;

/// Validate opaque URL-safe cursor token syntax before passing it to an application service.
pub fn validate_cursor_token(value: &str) -> Result<(), InvalidCursor> {
    if value.is_empty()
        || value.len() > MAX_PROTECTED_CURSOR_LENGTH
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    {
        return Err(InvalidCursor);
    }
    Ok(())
}

/// Opaque, application-protected GraphQL connection cursor.
///
/// The application service owns cryptographic protection and binds the token
/// to its normalized filter and order; this adapter validates opaque token syntax
/// without exposing raw contents in debug output.
#[derive(Clone, PartialEq, Eq)]
pub struct OpaqueCursor(String);

impl OpaqueCursor {
    #[must_use]
    pub fn from_backend(token: String) -> Self {
        Self(token)
    }
}

impl Debug for OpaqueCursor {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> FmtResult {
        formatter
            .debug_tuple("OpaqueCursor")
            .field(&"[redacted]")
            .finish()
    }
}

impl CursorType for OpaqueCursor {
    type Error = InvalidCursor;

    fn decode_cursor(value: &str) -> Result<Self, Self::Error> {
        validate_cursor_token(value)?;
        Ok(Self(value.to_owned()))
    }

    fn encode_cursor(&self) -> String {
        self.0.clone()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InvalidCursor;

impl Display for InvalidCursor {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> FmtResult {
        formatter.write_str("invalid cursor")
    }
}

impl std::error::Error for InvalidCursor {}

#[cfg(test)]
mod tests {
    use async_graphql::connection::CursorType as _;

    use super::OpaqueCursor;

    #[test]
    fn opaque_cursor_preserves_backend_token_and_redacts_debug() {
        let token = "Abc-123_xyz".to_owned();
        let cursor = OpaqueCursor::from_backend(token.clone());
        assert_eq!(cursor.encode_cursor(), token);
        assert_eq!(
            OpaqueCursor::decode_cursor(&token)
                .expect("valid token")
                .encode_cursor(),
            token
        );
        assert_eq!(format!("{cursor:?}"), "OpaqueCursor(\"[redacted]\")");
    }

    #[test]
    fn opaque_cursor_rejects_invalid_token_syntax() {
        for bad in ["", "not/a/cursor", &"a".repeat(513)] {
            assert!(OpaqueCursor::decode_cursor(bad).is_err());
        }
        assert!(OpaqueCursor::decode_cursor("valid-token_123").is_ok());
    }
}
