use std::marker::PhantomData;

use async_graphql::ID;
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use uuid::Uuid;

pub trait GlobalIdType {
    const TYPE_NAME: &'static str;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GlobalId<T> {
    oid: Uuid,
    marker: PhantomData<fn() -> T>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecodedGlobalId {
    type_name: Box<str>,
    oid: Uuid,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InvalidGlobalId;

impl<T: GlobalIdType> GlobalId<T> {
    #[must_use]
    pub fn new(oid: Uuid) -> Self {
        Self {
            oid,
            marker: PhantomData,
        }
    }

    #[must_use]
    pub fn oid(&self) -> Uuid {
        self.oid
    }

    #[must_use]
    pub fn encode(&self) -> String {
        debug_assert!(valid_type_name(T::TYPE_NAME));
        let mut bytes = Vec::with_capacity(T::TYPE_NAME.len() + 1 + 16);
        bytes.extend_from_slice(T::TYPE_NAME.as_bytes());
        bytes.push(b':');
        bytes.extend_from_slice(self.oid.as_bytes());
        URL_SAFE_NO_PAD.encode(bytes)
    }

    pub fn decode(value: &str) -> Result<Self, InvalidGlobalId> {
        DecodedGlobalId::decode(value)?.into_typed::<T>()
    }
}

impl<T: GlobalIdType> From<GlobalId<T>> for ID {
    fn from(value: GlobalId<T>) -> Self {
        Self(value.encode())
    }
}

impl<T: GlobalIdType> TryFrom<&ID> for GlobalId<T> {
    type Error = InvalidGlobalId;

    fn try_from(value: &ID) -> Result<Self, Self::Error> {
        Self::decode(value.as_str())
    }
}

impl DecodedGlobalId {
    pub fn decode(value: &str) -> Result<Self, InvalidGlobalId> {
        let bytes = URL_SAFE_NO_PAD
            .decode(value.as_bytes())
            .map_err(|_| InvalidGlobalId)?;
        let separator = bytes
            .iter()
            .position(|byte| *byte == b':')
            .ok_or(InvalidGlobalId)?;
        let (type_name, encoded_oid) = bytes.split_at(separator);
        let encoded_oid = encoded_oid.get(1..).ok_or(InvalidGlobalId)?;
        if type_name.is_empty() || encoded_oid.len() != 16 {
            return Err(InvalidGlobalId);
        }
        let type_name = std::str::from_utf8(type_name).map_err(|_| InvalidGlobalId)?;
        if !valid_type_name(type_name) {
            return Err(InvalidGlobalId);
        }
        Ok(Self {
            type_name: type_name.into(),
            oid: Uuid::from_slice(encoded_oid).map_err(|_| InvalidGlobalId)?,
        })
    }

    pub fn is<T: GlobalIdType>(&self) -> bool {
        self.type_name.as_ref() == T::TYPE_NAME
    }

    pub fn into_typed<T: GlobalIdType>(self) -> Result<GlobalId<T>, InvalidGlobalId> {
        if !self.is::<T>() {
            return Err(InvalidGlobalId);
        }
        Ok(GlobalId::new(self.oid))
    }
}

impl TryFrom<&ID> for DecodedGlobalId {
    type Error = InvalidGlobalId;

    fn try_from(value: &ID) -> Result<Self, Self::Error> {
        Self::decode(value.as_str())
    }
}

fn valid_type_name(type_name: &str) -> bool {
    !type_name.is_empty()
        && type_name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
}

#[cfg(test)]
mod tests {
    use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
    use uuid::Uuid;

    use super::{DecodedGlobalId, GlobalId, GlobalIdType};

    struct UserId;

    impl GlobalIdType for UserId {
        const TYPE_NAME: &'static str = "User";
    }

    struct SessionId;

    impl GlobalIdType for SessionId {
        const TYPE_NAME: &'static str = "Session";
    }

    #[test]
    fn typed_id_contains_type_name_and_raw_uuid_bytes() {
        let uuid = Uuid::parse_str("019c1234-5678-7abc-9def-0123456789ab").unwrap();
        let encoded = GlobalId::<UserId>::new(uuid).encode();
        let decoded = URL_SAFE_NO_PAD.decode(encoded.as_bytes()).unwrap();

        assert_eq!(decoded.len(), 21);
        assert_eq!(&decoded[..5], b"User:");
        assert_eq!(&decoded[5..], uuid.as_bytes());
        assert_eq!(GlobalId::<UserId>::decode(&encoded).unwrap().oid(), uuid);
    }

    #[test]
    fn typed_decode_rejects_another_node_type() {
        let encoded = GlobalId::<SessionId>::new(Uuid::new_v4()).encode();

        assert!(GlobalId::<UserId>::decode(&encoded).is_err());
    }

    #[test]
    fn async_graphql_id_conversion_preserves_type_checks() {
        let uuid = Uuid::new_v4();
        let id: async_graphql::ID = GlobalId::<SessionId>::new(uuid).into();

        assert_eq!(GlobalId::<SessionId>::try_from(&id).unwrap().oid(), uuid);
        assert!(GlobalId::<UserId>::try_from(&id).is_err());
    }

    #[test]
    fn heterogeneous_decode_preserves_type_for_node_dispatch() {
        let uuid = Uuid::new_v4();
        let decoded = DecodedGlobalId::decode(&GlobalId::<SessionId>::new(uuid).encode()).unwrap();

        assert!(decoded.is::<SessionId>());
        assert!(!decoded.is::<UserId>());
        assert_eq!(decoded.into_typed::<SessionId>().unwrap().oid(), uuid);
    }

    #[test]
    fn raw_uuid_is_not_a_global_id() {
        assert!(DecodedGlobalId::decode("019c1234-5678-7abc-9def-0123456789ab").is_err());
    }
}
