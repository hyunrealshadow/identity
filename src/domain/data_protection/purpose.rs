use hkdf::Hkdf;
use sha2::{Digest, Sha256};

const PROTOCOL_INFO_PREFIX: &[u8] = b"app:data-protection:v1\0";

#[derive(Debug, Clone)]
pub struct Purpose(String);

impl Purpose {
    pub fn new(s: impl Into<String>) -> Self {
        Self(s.into())
    }

    pub fn hkdf_info(&self) -> Vec<u8> {
        [PROTOCOL_INFO_PREFIX, self.0.as_bytes()].concat()
    }

    pub fn hash_prefix(&self) -> [u8; 8] {
        let mut out = [0u8; 8];
        let full = sha2::Sha256::digest(self.0.as_bytes());
        out.copy_from_slice(&full[..8]);
        out
    }
}

pub fn derive_subkey(master_key: &[u8], info: &[u8]) -> [u8; 32] {
    let hkdf = Hkdf::<Sha256>::new(None, master_key);
    let mut out = [0u8; 32];
    hkdf.expand(info, &mut out)
        .expect("32-byte HKDF expand never fails");
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn same_purpose_produces_same_subkey() {
        let master = [0x42u8; 32];
        let purpose = Purpose::new("session");
        let key1 = derive_subkey(&master, &purpose.hkdf_info());
        let key2 = derive_subkey(&master, &purpose.hkdf_info());
        assert_eq!(key1, key2);
    }

    #[test]
    fn different_purposes_produce_different_subkeys() {
        let master = [0x42u8; 32];
        let p1 = Purpose::new("session");
        let p2 = Purpose::new("csrf");
        let k1 = derive_subkey(&master, &p1.hkdf_info());
        let k2 = derive_subkey(&master, &p2.hkdf_info());
        assert_ne!(k1, k2);
    }

    #[test]
    fn hash_prefix_is_deterministic() {
        let p = Purpose::new("session");
        let h1 = p.hash_prefix();
        let h2 = p.hash_prefix();
        assert_eq!(h1, h2);
    }

    #[test]
    fn hash_prefix_differs_by_purpose() {
        let p1 = Purpose::new("session");
        let p2 = Purpose::new("csrf");
        assert_ne!(p1.hash_prefix(), p2.hash_prefix());
    }
}
