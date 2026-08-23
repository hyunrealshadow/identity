use std::marker::PhantomData;

use async_graphql::connection::CursorType;
use identity_application::data_protection::DataProtector;
use identity_domain::data_protection::DataProtectionError;

const MAX_PROTECTED_CURSOR_LENGTH: usize = 512;

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
        if value.is_empty()
            || value.len() > MAX_PROTECTED_CURSOR_LENGTH
            || !value
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
        {
            return Err(InvalidCursor);
        }
        Ok(Self::new(value.to_owned()))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.value
    }

    #[must_use]
    pub fn into_string(self) -> String {
        self.value
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

impl<T> std::fmt::Debug for ProtectedCursor<T> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
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

impl std::fmt::Display for InvalidCursor {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("invalid cursor")
    }
}

impl std::error::Error for InvalidCursor {}

#[cfg(test)]
mod tests {
    use async_graphql::connection::CursorType as _;
    use async_trait::async_trait;
    use identity_application::data_protection::DataProtector;
    use identity_domain::data_protection::DataProtectionError;

    use super::{CursorPayload, InvalidCursor, ProtectedCursor, protect_many, unprotect};

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
    fn protected_cursor_rejects_invalid_token_syntax() {
        assert!(ProtectedCursor::<TestCursor>::decode_cursor("not/a/cursor").is_err());
        assert!(ProtectedCursor::<TestCursor>::decode_cursor("").is_err());
        assert!(ProtectedCursor::<TestCursor>::decode_cursor("valid-token").is_ok());
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
