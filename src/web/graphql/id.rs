use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use uuid::Uuid;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NodeId {
    User(Uuid),
    Session(Uuid),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InvalidNodeId;

impl NodeId {
    #[must_use]
    pub fn encode(self) -> String {
        let (kind, uuid) = match self {
            Self::User(uuid) => (b"User:".as_slice(), uuid),
            Self::Session(uuid) => (b"Session:".as_slice(), uuid),
        };
        let mut bytes = Vec::with_capacity(kind.len() + 16);
        bytes.extend_from_slice(kind);
        bytes.extend_from_slice(uuid.as_bytes());
        URL_SAFE_NO_PAD.encode(bytes)
    }

    pub fn decode(value: &str) -> Result<Self, InvalidNodeId> {
        let bytes = URL_SAFE_NO_PAD
            .decode(value.as_bytes())
            .map_err(|_| InvalidNodeId)?;
        match bytes.as_slice() {
            [b'U', b's', b'e', b'r', b':', uuid @ ..] if uuid.len() == 16 => Ok(Self::User(
                Uuid::from_slice(uuid).map_err(|_| InvalidNodeId)?,
            )),
            [b'S', b'e', b's', b's', b'i', b'o', b'n', b':', uuid @ ..] if uuid.len() == 16 => Ok(
                Self::Session(Uuid::from_slice(uuid).map_err(|_| InvalidNodeId)?),
            ),
            _ => Err(InvalidNodeId),
        }
    }
}

#[cfg(test)]
mod tests {
    use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
    use uuid::Uuid;

    use super::NodeId;

    #[test]
    fn user_id_contains_prefix_and_raw_uuid_bytes() {
        let uuid = Uuid::parse_str("019c1234-5678-7abc-9def-0123456789ab").unwrap();
        let encoded = NodeId::User(uuid).encode();
        let decoded = URL_SAFE_NO_PAD.decode(encoded).unwrap();

        assert_eq!(decoded.len(), 21);
        assert_eq!(&decoded[..5], b"User:");
        assert_eq!(&decoded[5..], uuid.as_bytes());
        assert_eq!(
            NodeId::decode(&URL_SAFE_NO_PAD.encode(decoded)),
            Ok(NodeId::User(uuid))
        );
    }

    #[test]
    fn session_id_contains_prefix_and_raw_uuid_bytes() {
        let uuid = Uuid::parse_str("019c1234-5678-7abc-9def-0123456789ab").unwrap();
        let encoded = NodeId::Session(uuid).encode();
        let decoded = URL_SAFE_NO_PAD.decode(encoded).unwrap();

        assert_eq!(decoded.len(), 24);
        assert_eq!(&decoded[..8], b"Session:");
        assert_eq!(&decoded[8..], uuid.as_bytes());
        assert_eq!(
            NodeId::decode(&URL_SAFE_NO_PAD.encode(decoded)),
            Ok(NodeId::Session(uuid))
        );
    }

    #[test]
    fn raw_uuid_is_not_a_node_id() {
        assert!(NodeId::decode("019c1234-5678-7abc-9def-0123456789ab").is_err());
    }
}
