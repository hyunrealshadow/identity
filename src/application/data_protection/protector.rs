use std::sync::Arc;

use async_trait::async_trait;
use base64::{Engine, engine::general_purpose::STANDARD};
use chrono::Utc;
use tracing::warn;

use crate::domain::data_protection::DataProtectionError;
use crate::domain::data_protection::{KeyRing, ProtectedPayload, Purpose, derive_subkey};
use crate::domain::key::repository::KeyRepository;
use crate::infrastructure::crypto::xchacha20::{self, KEY_SIZE};

#[async_trait]
pub trait DataProtector: Send + Sync {
    async fn protect(&self, purpose: &str, plaintext: &[u8])
    -> Result<String, DataProtectionError>;
    async fn unprotect(&self, purpose: &str, token: &str) -> Result<Vec<u8>, DataProtectionError>;
}

pub struct DataProtectorImpl {
    key_repo: Arc<dyn KeyRepository>,
}

impl DataProtectorImpl {
    pub fn new(key_repo: Arc<dyn KeyRepository>) -> Self {
        Self { key_repo }
    }
}

#[async_trait]
impl DataProtector for DataProtectorImpl {
    async fn protect(
        &self,
        purpose: &str,
        plaintext: &[u8],
    ) -> Result<String, DataProtectionError> {
        let keys = self
            .key_repo
            .list_available_symmetric()
            .await
            .map_err(|e| DataProtectionError::Internal(Box::new(e)))?;

        let ring = KeyRing::new(keys);
        let now = Utc::now();

        let key = ring
            .encrypting_key(now)
            .ok_or(DataProtectionError::KeyRingEmpty)?;

        let master_key = decode_master_key(key)?;
        let purpose = Purpose::new(purpose);
        let purpose_hash = purpose.hash_prefix();
        let subkey = derive_subkey(&master_key, &purpose.hkdf_info());
        let aad = ProtectedPayload::new(key.oid, [0u8; 24], vec![]).aad(&purpose_hash);

        let (nonce, ciphertext) = xchacha20::encrypt(&subkey, plaintext, &aad)
            .map_err(|_| DataProtectionError::EncryptionFailed)?;

        let payload = ProtectedPayload::new(key.oid, nonce, ciphertext);
        Ok(payload.encode())
    }

    async fn unprotect(&self, purpose: &str, token: &str) -> Result<Vec<u8>, DataProtectionError> {
        let payload = ProtectedPayload::decode(token).map_err(|reason| {
            warn!(reason, "failed to decode protected payload");
            DataProtectionError::InvalidProtectedPayload
        })?;

        let purpose = Purpose::new(purpose);
        let purpose_hash = purpose.hash_prefix();
        let aad = payload.aad(&purpose_hash);

        let keys = self
            .key_repo
            .list_available_symmetric()
            .await
            .map_err(|e| DataProtectionError::Internal(Box::new(e)))?;

        let ring = KeyRing::new(keys);

        let key = ring.decrypting_key(&payload.key_id).ok_or_else(|| {
            warn!(key_id = %uuid::Uuid::from(payload.key_id), "key not found for decryption");
            DataProtectionError::InvalidProtectedPayload
        })?;

        if key.revoked_at.is_some() {
            warn!(key_id = %uuid::Uuid::from(payload.key_id), "key has been revoked");
            return Err(DataProtectionError::InvalidProtectedPayload);
        }

        let master_key = decode_master_key(key)?;
        let subkey = derive_subkey(&master_key, &purpose.hkdf_info());

        xchacha20::decrypt(&subkey, &payload.nonce, &payload.ciphertext, &aad).map_err(|_| {
            warn!("decryption failed for protected payload");
            DataProtectionError::InvalidProtectedPayload
        })
    }
}

fn decode_master_key(key: &crate::domain::key::Key) -> Result<[u8; KEY_SIZE], DataProtectionError> {
    use crate::domain::key::KeyData;
    let KeyData::Symmetric(sym_data) = &key.data else {
        return Err(DataProtectionError::Internal(Box::new(
            std::io::Error::other("expected symmetric key"),
        )));
    };

    let raw = STANDARD
        .decode(&sym_data.key)
        .map_err(|e| DataProtectionError::Internal(Box::new(e)))?;

    if raw.len() != KEY_SIZE {
        return Err(DataProtectionError::Internal(Box::new(
            std::io::Error::other(format!("expected {}-byte key, got {}", KEY_SIZE, raw.len())),
        )));
    }

    let mut out = [0u8; KEY_SIZE];
    out.copy_from_slice(&raw);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use async_trait::async_trait;
    use base64::Engine;
    use chrono::{DateTime, Duration, Utc};
    use std::sync::Arc;
    use uuid::Uuid;

    use crate::domain::data_protection::DataProtectionError;
    use crate::domain::key::{
        Key, KeyData, KeyOid, KeyType,
        material::{SymmetricKeyAlgorithm, SymmetricKeyData},
        repository::{KeyRepository, KeyRepositoryError},
    };

    use super::{DataProtector, DataProtectorImpl};

    struct MockKeyRepo {
        keys: Vec<Key>,
    }

    #[async_trait]
    impl KeyRepository for MockKeyRepo {
        async fn find_by_oid(&self, _oid: KeyOid) -> Result<Option<Key>, KeyRepositoryError> {
            unimplemented!()
        }

        async fn list_available_asymmetric(&self) -> Result<Vec<Key>, KeyRepositoryError> {
            unimplemented!()
        }

        async fn list_available_symmetric(&self) -> Result<Vec<Key>, KeyRepositoryError> {
            Ok(self.keys.clone())
        }

        async fn create(
            &self,
            _key_type: KeyType,
            _data: &KeyData,
            _expires_at: Option<DateTime<Utc>>,
        ) -> Result<Key, KeyRepositoryError> {
            unimplemented!()
        }

        async fn update_certificate_by_oid(
            &self,
            _oid: KeyOid,
            _certificate_pem: &str,
        ) -> Result<Option<Key>, KeyRepositoryError> {
            unimplemented!()
        }

        async fn revoke_by_oid(
            &self,
            _oid: KeyOid,
            _revoked_at: DateTime<Utc>,
        ) -> Result<Option<Key>, KeyRepositoryError> {
            unimplemented!()
        }
    }

    fn make_symmetric_key(
        created: DateTime<Utc>,
        expires: Option<DateTime<Utc>>,
        revoked: Option<DateTime<Utc>>,
    ) -> Key {
        make_symmetric_key_with_id(Uuid::new_v4(), created, expires, revoked)
    }

    fn make_symmetric_key_with_id(
        id: Uuid,
        created: DateTime<Utc>,
        expires: Option<DateTime<Utc>>,
        revoked: Option<DateTime<Utc>>,
    ) -> Key {
        let raw_key = base64::engine::general_purpose::STANDARD.encode([0x42u8; 32]);
        Key {
            oid: KeyOid::from(id),
            r#type: KeyType::Symmetric,
            data: KeyData::Symmetric(SymmetricKeyData {
                key: raw_key,
                algorithm: SymmetricKeyAlgorithm::XChaCha20Poly1305,
            }),
            expires_at: expires,
            revoked_at: revoked,
            created_at: created,
            updated_at: None,
        }
    }

    #[tokio::test]
    async fn protect_unprotect_roundtrip() {
        let now = Utc::now();
        let key = make_symmetric_key(now, Some(now + Duration::hours(1)), None);
        let repo = Arc::new(MockKeyRepo { keys: vec![key] });
        let protector = DataProtectorImpl::new(repo);

        let plaintext = b"secret session data";
        let token = protector.protect("session", plaintext).await.unwrap();
        let decrypted = protector.unprotect("session", &token).await.unwrap();

        assert_eq!(decrypted, plaintext);
    }

    #[tokio::test]
    async fn wrong_purpose_fails() {
        let now = Utc::now();
        let key = make_symmetric_key(now, Some(now + Duration::hours(1)), None);
        let repo = Arc::new(MockKeyRepo { keys: vec![key] });
        let protector = DataProtectorImpl::new(repo);

        let plaintext = b"secret";
        let token = protector.protect("session", plaintext).await.unwrap();
        let result = protector.unprotect("csrf", &token).await;

        assert!(matches!(
            result,
            Err(DataProtectionError::InvalidProtectedPayload)
        ));
    }

    #[tokio::test]
    async fn revoked_key_cannot_encrypt() {
        let now = Utc::now();
        let key = make_symmetric_key(
            now - Duration::hours(1),
            Some(now + Duration::hours(1)),
            Some(now),
        );
        let repo = Arc::new(MockKeyRepo { keys: vec![key] });
        let protector = DataProtectorImpl::new(repo);

        let result = protector.protect("session", b"secret").await;
        assert!(matches!(result, Err(DataProtectionError::KeyRingEmpty)));
    }

    #[tokio::test]
    async fn expired_key_cannot_encrypt_but_can_decrypt() {
        // Test that an expired key cannot encrypt but CAN still decrypt data it encrypted earlier
        let now = Utc::now();
        let key_id = Uuid::new_v4();

        // Step 1: Create a valid key (no expiry) and encrypt data
        let valid_key = make_symmetric_key_with_id(key_id, now, None, None);
        let repo = Arc::new(MockKeyRepo {
            keys: vec![valid_key],
        });
        let protector = DataProtectorImpl::new(repo);

        let plaintext = b"secret";
        let token = protector.protect("session", plaintext).await.unwrap();

        // Step 2: Same key but expired - should still be able to decrypt
        let expired_key = make_symmetric_key_with_id(
            key_id,
            now - Duration::hours(2),
            Some(now - Duration::hours(1)),
            None,
        );
        let expired_repo = Arc::new(MockKeyRepo {
            keys: vec![expired_key],
        });
        let expired_protector = DataProtectorImpl::new(expired_repo);

        let decrypted = expired_protector
            .unprotect("session", &token)
            .await
            .unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[tokio::test]
    async fn no_active_key_returns_key_ring_empty() {
        let now = Utc::now();
        let expired = make_symmetric_key(
            now - Duration::hours(2),
            Some(now - Duration::hours(1)),
            None,
        );
        let repo = Arc::new(MockKeyRepo {
            keys: vec![expired],
        });
        let protector = DataProtectorImpl::new(repo);

        let result = protector.protect("session", b"test").await;
        assert!(matches!(result, Err(DataProtectionError::KeyRingEmpty)));
    }

    #[tokio::test]
    async fn tampered_token_fails() {
        let now = Utc::now();
        let key = make_symmetric_key(now, Some(now + Duration::hours(1)), None);
        let repo = Arc::new(MockKeyRepo { keys: vec![key] });
        let protector = DataProtectorImpl::new(repo);

        let plaintext = b"secret";
        let mut token = protector.protect("session", plaintext).await.unwrap();
        let mut chars: Vec<char> = token.chars().collect();
        chars[10] = if chars[10] == 'A' { 'B' } else { 'A' };
        token = chars.into_iter().collect();

        let result = protector.unprotect("session", &token).await;
        assert!(matches!(
            result,
            Err(DataProtectionError::InvalidProtectedPayload)
        ));
    }
}
