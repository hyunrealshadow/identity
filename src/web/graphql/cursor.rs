use std::{
    error::Error,
    fmt::{Debug, Display, Formatter, Result as FmtResult},
    marker::PhantomData,
};

use async_graphql::connection::CursorType;
use identity_application::data_protection::DataProtector;
use identity_domain::data_protection::DataProtectionError;

const MAX_PROTECTED_CURSOR_LENGTH: usize = 512;

/// Validate opaque URL-safe cursor token syntax before decoding or passing to a service.
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

/// Module-specific payload stored inside an opaque GraphQL cursor.
///
/// The purpose is part of the payload type so cursors from different modules
/// cannot be accidentally protected or unprotected under the same context.
pub trait CursorPayload: Sized + Send + Sync {
    const PURPOSE: &'static str;

    fn encode(&self) -> Vec<u8>;

    fn decode(bytes: &[u8]) -> Result<Self, InvalidCursor>;
}

/// Framework-independent representation of a protected GraphQL cursor.
pub struct ProtectedCursor<T> {
    value: String,
    payload: PhantomData<fn() -> T>,
}

impl<T> ProtectedCursor<T> {
    pub fn parse(value: &str) -> Result<Self, InvalidCursor> {
        validate_cursor_token(value)?;
        Ok(Self::new(value.to_owned()))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.value
    }

    fn new(value: String) -> Self {
        Self {
            value,
            payload: PhantomData,
        }
    }
}

impl<T> Clone for ProtectedCursor<T> {
    fn clone(&self) -> Self {
        Self::new(self.value.clone())
    }
}

impl<T> Debug for ProtectedCursor<T> {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> FmtResult {
        formatter
            .debug_tuple("ProtectedCursor")
            .field(&"[redacted]")
            .finish()
    }
}

impl<T> PartialEq for ProtectedCursor<T> {
    fn eq(&self, other: &Self) -> bool {
        self.value == other.value
    }
}

impl<T> Eq for ProtectedCursor<T> {}

impl<T: CursorPayload> CursorType for ProtectedCursor<T> {
    type Error = InvalidCursor;

    fn decode_cursor(value: &str) -> Result<Self, Self::Error> {
        Self::parse(value)
    }

    fn encode_cursor(&self) -> String {
        self.value.clone()
    }
}

pub async fn protect_many<T: CursorPayload>(
    data_protector: &dyn DataProtector,
    payloads: &[T],
) -> Result<Vec<ProtectedCursor<T>>, DataProtectionError> {
    let plaintexts = payloads
        .iter()
        .map(CursorPayload::encode)
        .collect::<Vec<_>>();
    data_protector
        .protect_many(T::PURPOSE, &plaintexts)
        .await
        .map(|tokens| tokens.into_iter().map(ProtectedCursor::new).collect())
}

pub async fn unprotect<T: CursorPayload>(
    data_protector: &dyn DataProtector,
    cursor: &ProtectedCursor<T>,
) -> Result<T, InvalidCursor> {
    let plaintext = data_protector
        .unprotect(T::PURPOSE, cursor.as_str())
        .await
        .map_err(|_| InvalidCursor)?;
    T::decode(&plaintext)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InvalidCursor;

impl Display for InvalidCursor {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> FmtResult {
        formatter.write_str("invalid cursor")
    }
}

impl Error for InvalidCursor {}

#[cfg(test)]
mod tests {
    use async_graphql::connection::CursorType as _;
    use async_trait::async_trait;
    use identity_application::data_protection::DataProtector;
    use identity_domain::data_protection::DataProtectionError;

    use super::{
        CursorPayload, InvalidCursor, OpaqueCursor, ProtectedCursor, protect_many, unprotect,
    };

    #[derive(Debug, PartialEq, Eq)]
    struct TestCursor(u8);

    impl CursorPayload for TestCursor {
        const PURPOSE: &'static str = "graphql:cursor:test";

        fn encode(&self) -> Vec<u8> {
            vec![self.0]
        }

        fn decode(bytes: &[u8]) -> Result<Self, InvalidCursor> {
            match bytes {
                [value] => Ok(Self(*value)),
                _ => Err(InvalidCursor),
            }
        }
    }

    struct OtherCursor(u8);

    impl CursorPayload for OtherCursor {
        const PURPOSE: &'static str = "graphql:cursor:other";

        fn encode(&self) -> Vec<u8> {
            vec![self.0]
        }

        fn decode(bytes: &[u8]) -> Result<Self, InvalidCursor> {
            match bytes {
                [value] => Ok(Self(*value)),
                _ => Err(InvalidCursor),
            }
        }
    }

    struct PurposeBoundProtector;

    #[async_trait]
    impl DataProtector for PurposeBoundProtector {
        async fn protect(
            &self,
            purpose: &str,
            plaintext: &[u8],
        ) -> Result<String, DataProtectionError> {
            let [value] = plaintext else {
                return Err(DataProtectionError::InvalidProtectedPayload);
            };
            Ok(format!("{}-{value:02x}", purpose.replace(':', "-")))
        }

        async fn unprotect(
            &self,
            purpose: &str,
            token: &str,
        ) -> Result<Vec<u8>, DataProtectionError> {
            let prefix = format!("{}-", purpose.replace(':', "-"));
            let encoded = token
                .strip_prefix(&prefix)
                .ok_or(DataProtectionError::InvalidProtectedPayload)?;
            u8::from_str_radix(encoded, 16)
                .map(|value| vec![value])
                .map_err(|_| DataProtectionError::InvalidProtectedPayload)
        }
    }

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
    fn opaque_and_protected_cursors_reject_invalid_token_syntax() {
        for bad in ["", "not/a/cursor", &"a".repeat(513)] {
            assert!(OpaqueCursor::decode_cursor(bad).is_err());
            assert!(ProtectedCursor::<TestCursor>::decode_cursor(bad).is_err());
        }
        assert!(OpaqueCursor::decode_cursor("valid-token_123").is_ok());
        assert!(ProtectedCursor::<TestCursor>::decode_cursor("valid-token_123").is_ok());
    }

    #[tokio::test]
    async fn payload_type_binds_the_data_protection_purpose() {
        let protector = PurposeBoundProtector;
        let protected = protect_many(&protector, &[TestCursor(42)]).await.unwrap();

        assert_eq!(
            unprotect(&protector, &protected[0]).await,
            Ok(TestCursor(42))
        );

        let other = ProtectedCursor::<OtherCursor>::parse(protected[0].as_str()).unwrap();
        assert!(unprotect(&protector, &other).await.is_err());
    }
}
