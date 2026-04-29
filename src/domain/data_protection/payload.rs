use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};

use crate::key::KeyOid;

pub const VERSION: u8 = 0x01;
pub const ALG_ID: u8 = 0x01;
pub const NONCE_SIZE: usize = 24;
pub const TAG_SIZE: usize = 16;
pub const HEADER_SIZE: usize = 1 + 1 + 16 + NONCE_SIZE;

#[derive(Debug, Clone, PartialEq)]
pub struct ProtectedPayload {
    pub version: u8,
    pub alg_id: u8,
    pub key_id: KeyOid,
    pub nonce: [u8; NONCE_SIZE],
    pub ciphertext: Vec<u8>,
}

impl ProtectedPayload {
    pub fn new(key_id: KeyOid, nonce: [u8; NONCE_SIZE], ciphertext: Vec<u8>) -> Self {
        Self {
            version: VERSION,
            alg_id: ALG_ID,
            key_id,
            nonce,
            ciphertext,
        }
    }

    pub fn encode(&self) -> String {
        URL_SAFE_NO_PAD.encode(self.to_bytes())
    }

    pub fn decode(input: &str) -> Result<Self, &'static str> {
        let bytes = URL_SAFE_NO_PAD
            .decode(input)
            .map_err(|_| "invalid base64url")?;
        Self::from_bytes(&bytes)
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(HEADER_SIZE + TAG_SIZE + self.ciphertext.len());
        out.push(self.version);
        out.push(self.alg_id);
        let oid_bytes: [u8; 16] = uuid::Uuid::from(self.key_id).into_bytes();
        out.extend_from_slice(&oid_bytes);
        out.extend_from_slice(&self.nonce);
        out.extend_from_slice(&self.ciphertext);
        out
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, &'static str> {
        if bytes.len() < HEADER_SIZE + TAG_SIZE {
            return Err("payload too short");
        }
        let version = bytes[0];
        if version != VERSION {
            return Err("unsupported version");
        }
        let alg_id = bytes[1];
        if alg_id != ALG_ID {
            return Err("unsupported algorithm");
        }
        let mut key_id_bytes = [0u8; 16];
        key_id_bytes.copy_from_slice(&bytes[2..18]);
        let key_id = KeyOid::from(uuid::Uuid::from_bytes(key_id_bytes));
        let mut nonce = [0u8; NONCE_SIZE];
        nonce.copy_from_slice(&bytes[18..18 + NONCE_SIZE]);
        let ciphertext = bytes[18 + NONCE_SIZE..].to_vec();
        Ok(Self {
            version,
            alg_id,
            key_id,
            nonce,
            ciphertext,
        })
    }

    pub fn aad(&self, purpose_hash: &[u8; 8]) -> Vec<u8> {
        let mut out = Vec::with_capacity(1 + 1 + 16 + 8);
        out.push(self.version);
        out.push(self.alg_id);
        let oid_bytes: [u8; 16] = uuid::Uuid::from(self.key_id).into_bytes();
        out.extend_from_slice(&oid_bytes);
        out.extend_from_slice(purpose_hash);
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_payload() -> ProtectedPayload {
        ProtectedPayload {
            version: VERSION,
            alg_id: ALG_ID,
            key_id: KeyOid::from(uuid::Uuid::new_v4()),
            nonce: [0x01u8; NONCE_SIZE],
            ciphertext: vec![0xAAu8; TAG_SIZE + 4], // minimum size is TAG_SIZE
        }
    }

    #[test]
    fn roundtrip_bytes() {
        let original = make_payload();
        let bytes = original.to_bytes();
        let decoded = ProtectedPayload::from_bytes(&bytes).unwrap();
        assert_eq!(decoded.version, original.version);
        assert_eq!(decoded.alg_id, original.alg_id);
        assert_eq!(decoded.key_id, original.key_id);
        assert_eq!(decoded.nonce, original.nonce);
        assert_eq!(decoded.ciphertext, original.ciphertext);
    }

    #[test]
    fn roundtrip_base64url() {
        let original = make_payload();
        let encoded = original.encode();
        let decoded = ProtectedPayload::decode(&encoded).unwrap();
        assert_eq!(decoded.version, original.version);
        assert_eq!(decoded.key_id, original.key_id);
        assert_eq!(decoded.nonce, original.nonce);
        assert_eq!(decoded.ciphertext, original.ciphertext);
    }

    #[test]
    fn rejects_too_short_payload() {
        let bytes = vec![0x01, 0x01];
        assert!(ProtectedPayload::from_bytes(&bytes).is_err());
    }

    #[test]
    fn rejects_wrong_version() {
        let original = make_payload();
        let mut bytes = original.to_bytes();
        bytes[0] = 0xFF;
        assert_eq!(
            ProtectedPayload::from_bytes(&bytes),
            Err("unsupported version")
        );
    }

    #[test]
    fn rejects_wrong_alg_id() {
        let original = make_payload();
        let mut bytes = original.to_bytes();
        bytes[1] = 0xFF;
        assert_eq!(
            ProtectedPayload::from_bytes(&bytes),
            Err("unsupported algorithm")
        );
    }

    #[test]
    fn rejects_invalid_base64url() {
        assert!(ProtectedPayload::decode("!!!invalid!!!").is_err());
    }

    #[test]
    fn aad_includes_purpose_hash() {
        let payload = make_payload();
        let purpose_hash = [0x99u8; 8];
        let aad = payload.aad(&purpose_hash);
        assert_eq!(aad[0], VERSION);
        assert_eq!(aad[1], ALG_ID);
        assert_eq!(&aad[2..18], &uuid::Uuid::from(payload.key_id).into_bytes());
        assert_eq!(&aad[18..], purpose_hash);
    }
}
