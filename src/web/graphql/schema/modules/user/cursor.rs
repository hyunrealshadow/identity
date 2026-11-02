//! GraphQL cursor wrapper for the user-management connection.
//!
//! The application service owns the protected keyset cursor: it binds the
//! cursor to the normalized filter and order and exposes the opaque token on
//! each page item. The adapter must not decode or rebuild that token, it only
//! carries it through async-graphql's `CursorType` after applying the same
//! syntactic bounds as the shared protected-cursor helper.

use async_graphql::connection::CursorType;
use identity_infrastructure::graphql::cursor::InvalidCursor;

const MAX_CURSOR_LENGTH: usize = 512;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct UserConnectionCursor(String);

impl UserConnectionCursor {
    /// A token emitted by the application user-management service.
    pub(super) fn from_backend(token: String) -> Self {
        Self(token)
    }
}

impl CursorType for UserConnectionCursor {
    type Error = InvalidCursor;

    fn decode_cursor(value: &str) -> Result<Self, Self::Error> {
        if value.is_empty()
            || value.len() > MAX_CURSOR_LENGTH
            || !value
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
        {
            return Err(InvalidCursor);
        }
        Ok(Self(value.to_owned()))
    }

    fn encode_cursor(&self) -> String {
        self.0.clone()
    }
}

#[cfg(test)]
mod tests {
    use async_graphql::connection::CursorType as _;

    use super::UserConnectionCursor;

    #[test]
    fn cursor_wrapper_preserves_the_application_token() {
        let token = "Abc-123_xyz".to_owned();
        let cursor = UserConnectionCursor::from_backend(token.clone());

        assert_eq!(cursor.encode_cursor(), token);
        assert_eq!(
            UserConnectionCursor::decode_cursor(&token)
                .unwrap()
                .encode_cursor(),
            token
        );
    }

    #[test]
    fn cursor_wrapper_rejects_invalid_syntax_before_execution() {
        assert!(UserConnectionCursor::decode_cursor("").is_err());
        assert!(UserConnectionCursor::decode_cursor("not/a/cursor").is_err());
        assert!(UserConnectionCursor::decode_cursor(&"a".repeat(513)).is_err());
    }
}
