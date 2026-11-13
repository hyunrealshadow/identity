//! Opaque, typed identifiers presented outside the service.
//!
//! Every object identifier that leaves the service — GraphQL `ID`s and the
//! OAuth/OIDC `client_id`, public `sub`, `jti` and `kid` values — is a
//! Global ID (`sid` stays a data-protected session handle): the
//! unpadded base64url encoding of `<TypeName>:` followed by the 16 raw UUID
//! bytes. Persistence, events and internal caches keep the plain UUID.
//!
//! A Global ID names an object; it is not a secret and proves nothing about
//! who presents it.

use std::{marker::PhantomData, str};

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::{Deserialize, Deserializer, Serializer, de::Error as _};
use uuid::Uuid;

pub trait GlobalIdType {
    const TYPE_NAME: &'static str;
}

/// The externally visible object kinds. Type names are part of every issued
/// identifier, so renaming one invalidates identifiers already handed out.
pub mod kind {
    use super::GlobalIdType;

    macro_rules! kinds {
        ($($name:ident),* $(,)?) => {
            $(
                #[derive(Debug, Clone, Copy, PartialEq, Eq)]
                pub struct $name;

                impl GlobalIdType for $name {
                    const TYPE_NAME: &'static str = stringify!($name);
                }
            )*
        };
    }

    kinds!(
        User,
        Session,
        Client,
        ClientCredential,
        Resource,
        Scope,
        Role,
        Group,
        Key,
        KeyJwk,
        Passkey,
        PasskeyChallenge,
        AccessToken,
        LogoutToken,
    );
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("invalid global id")]
pub struct InvalidGlobalId;

impl<T: GlobalIdType> GlobalId<T> {
    #[must_use]
    pub fn new(oid: impl Into<Uuid>) -> Self {
        Self {
            oid: oid.into(),
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

/// Encode `oid` as a Global ID of kind `T`.
#[must_use]
pub fn encode<T: GlobalIdType>(oid: impl Into<Uuid>) -> String {
    GlobalId::<T>::new(oid).encode()
}

/// Decode a Global ID of kind `T`; any other kind or a raw UUID is rejected.
pub fn decode<T: GlobalIdType>(value: &str) -> Result<Uuid, InvalidGlobalId> {
    GlobalId::<T>::decode(value).map(|id| id.oid())
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
        let type_name = str::from_utf8(type_name).map_err(|_| InvalidGlobalId)?;
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

/// Serde adapters for a plain UUID field presented as a Global ID, for use
/// with `#[serde(serialize_with = "...::<Kind, _>", deserialize_with = "...")]`.
pub fn serialize_oid<T: GlobalIdType, S: Serializer>(
    oid: &Uuid,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    serializer.serialize_str(&encode::<T>(*oid))
}

pub fn deserialize_oid<'de, T: GlobalIdType, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<Uuid, D::Error> {
    let value = String::deserialize(deserializer)?;
    decode::<T>(&value).map_err(D::Error::custom)
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
    use serde::{Deserialize, Serialize};
    use uuid::Uuid;

    use super::{DecodedGlobalId, GlobalId, decode, encode, kind};

    #[test]
    fn typed_id_contains_type_name_and_raw_uuid_bytes() {
        let uuid = Uuid::parse_str("019c1234-5678-7abc-9def-0123456789ab").unwrap();
        let encoded = encode::<kind::User>(uuid);
        let decoded = URL_SAFE_NO_PAD.decode(encoded.as_bytes()).unwrap();

        assert_eq!(decoded.len(), 21);
        assert_eq!(&decoded[..5], b"User:");
        assert_eq!(&decoded[5..], uuid.as_bytes());
        assert_eq!(decode::<kind::User>(&encoded).unwrap(), uuid);
    }

    #[test]
    fn typed_decode_rejects_another_kind() {
        let encoded = encode::<kind::Session>(Uuid::new_v4());

        assert!(decode::<kind::User>(&encoded).is_err());
        assert!(decode::<kind::Client>(&encoded).is_err());
    }

    #[test]
    fn heterogeneous_decode_preserves_kind_for_dispatch() {
        let uuid = Uuid::new_v4();
        let decoded = DecodedGlobalId::decode(&encode::<kind::Session>(uuid)).unwrap();

        assert!(decoded.is::<kind::Session>());
        assert!(!decoded.is::<kind::User>());
        assert_eq!(decoded.into_typed::<kind::Session>().unwrap().oid(), uuid);
    }

    #[test]
    fn raw_uuid_is_not_a_global_id() {
        let raw = "019c1234-5678-7abc-9def-0123456789ab";
        assert!(DecodedGlobalId::decode(raw).is_err());
        assert!(GlobalId::<kind::Client>::decode(raw).is_err());
    }

    #[derive(Serialize, Deserialize)]
    struct Envelope {
        #[serde(
            serialize_with = "super::serialize_oid::<kind::PasskeyChallenge, _>",
            deserialize_with = "super::deserialize_oid::<kind::PasskeyChallenge, _>"
        )]
        challenge_id: Uuid,
    }

    #[test]
    fn serde_adapter_round_trips_and_rejects_raw_uuid() {
        let uuid = Uuid::new_v4();
        let json = serde_json::to_string(&Envelope { challenge_id: uuid }).unwrap();

        assert!(!json.contains(&uuid.to_string()));
        assert_eq!(
            serde_json::from_str::<Envelope>(&json)
                .unwrap()
                .challenge_id,
            uuid
        );
        assert!(
            serde_json::from_str::<Envelope>(&format!(r#"{{"challenge_id":"{uuid}"}}"#)).is_err()
        );
    }
}
