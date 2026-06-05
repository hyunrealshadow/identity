use sha2::Digest;

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

#[cfg(test)]
mod tests {
    use super::*;

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
