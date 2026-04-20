use chrono::{DateTime, Utc};

use crate::domain::key::{Key, KeyOid, KeyType};

pub struct KeyRing {
    keys: Vec<Key>,
}

impl KeyRing {
    pub fn new(mut keys: Vec<Key>) -> Self {
        keys.sort_by(|a, b| b.created_at.cmp(&a.created_at));
        Self { keys }
    }

    pub fn encrypting_key(&self, now: DateTime<Utc>) -> Option<&Key> {
        self.keys.iter().find(|k| Self::is_active(k, now))
    }

    pub fn decrypting_key(&self, key_id: &KeyOid) -> Option<&Key> {
        self.keys.iter().find(|k| &k.oid == key_id)
    }

    fn is_active(key: &Key, now: DateTime<Utc>) -> bool {
        key.r#type == KeyType::Symmetric
            && key.revoked_at.is_none()
            && key.expires_at.map_or(true, |exp| exp > now)
    }

    pub fn keys(&self) -> &[Key] {
        &self.keys
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::key::material::SymmetricKeyData;
    use crate::domain::key::{KeyData, SymmetricKeyAlgorithm};
    use chrono::Duration;

    fn make_key(
        created: DateTime<Utc>,
        expires: Option<DateTime<Utc>>,
        revoked: Option<DateTime<Utc>>,
    ) -> Key {
        Key {
            oid: KeyOid::from(uuid::Uuid::new_v4()),
            r#type: KeyType::Symmetric,
            data: KeyData::Symmetric(SymmetricKeyData {
                key: "test".to_owned(),
                algorithm: SymmetricKeyAlgorithm::XChaCha20Poly1305,
            }),
            expires_at: expires,
            revoked_at: revoked,
            created_at: created,
            updated_at: None,
        }
    }

    #[test]
    fn encrypting_key_returns_newest_active() {
        let now = Utc::now();
        let old = make_key(
            now - Duration::hours(1),
            Some(now + Duration::hours(2)),
            None,
        );
        let new = make_key(now, Some(now + Duration::hours(3)), None);
        let ring = KeyRing::new(vec![old.clone(), new.clone()]);
        assert_eq!(ring.encrypting_key(now).unwrap().oid, new.oid);
    }

    #[test]
    fn encrypting_key_skips_expired() {
        let now = Utc::now();
        let expired = make_key(
            now - Duration::hours(2),
            Some(now - Duration::hours(1)),
            None,
        );
        let active = make_key(
            now - Duration::hours(1),
            Some(now + Duration::hours(1)),
            None,
        );
        let ring = KeyRing::new(vec![expired, active.clone()]);
        assert_eq!(ring.encrypting_key(now).unwrap().oid, active.oid);
    }

    #[test]
    fn encrypting_key_skips_revoked() {
        let now = Utc::now();
        let revoked = make_key(
            now - Duration::hours(1),
            Some(now + Duration::hours(1)),
            Some(now),
        );
        let active = make_key(now, Some(now + Duration::hours(2)), None);
        let ring = KeyRing::new(vec![revoked, active.clone()]);
        assert_eq!(ring.encrypting_key(now).unwrap().oid, active.oid);
    }

    #[test]
    fn encrypting_key_none_when_all_inactive() {
        let now = Utc::now();
        let expired = make_key(
            now - Duration::hours(2),
            Some(now - Duration::hours(1)),
            None,
        );
        let revoked = make_key(
            now - Duration::hours(1),
            Some(now + Duration::hours(1)),
            Some(now),
        );
        let ring = KeyRing::new(vec![expired, revoked]);
        assert!(ring.encrypting_key(now).is_none());
    }

    #[test]
    fn decrypting_key_finds_by_oid() {
        let now = Utc::now();
        let key = make_key(now, Some(now - Duration::hours(1)), None);
        let ring = KeyRing::new(vec![key.clone()]);
        assert_eq!(ring.decrypting_key(&key.oid).unwrap().oid, key.oid);
    }

    #[test]
    fn decrypting_key_returns_none_for_missing() {
        let ring = KeyRing::new(vec![]);
        let fake_oid = KeyOid::from(uuid::Uuid::new_v4());
        assert!(ring.decrypting_key(&fake_oid).is_none());
    }
}
