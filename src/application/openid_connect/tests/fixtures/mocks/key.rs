use chrono::{DateTime, Utc};
use identity_domain::key::repository::{KeyRepository, KeyRepositoryError};
use identity_domain::key::{
    CreateKeyJwkInput, Key, KeyData, KeyJwk, KeyJwkRepository, KeyJwkRepositoryError, KeyOid,
    KeyType,
};

mockall::mock! {
    pub KeyJwkRepository {}

    #[async_trait::async_trait]
    impl KeyJwkRepository for KeyJwkRepository {
        async fn create_batch(&self, inputs: Vec<CreateKeyJwkInput>)
            -> Result<Vec<KeyJwk>, KeyJwkRepositoryError>;
        async fn list_active(&self) -> Result<Vec<KeyJwk>, KeyJwkRepositoryError>;
        async fn find_active_by_key_oid_and_algorithm(&self, key_oid: KeyOid, algorithm: &str)
            -> Result<Option<KeyJwk>, KeyJwkRepositoryError>;
        async fn delete_by_key_oid(&self, key_oid: KeyOid)
            -> Result<(), KeyJwkRepositoryError>;
    }
}

mockall::mock! {
    pub KeyRepository {}

    #[async_trait::async_trait]
    impl KeyRepository for KeyRepository {
        async fn find_by_oid(&self, oid: KeyOid) -> Result<Option<Key>, KeyRepositoryError>;
        async fn list_available_asymmetric(&self) -> Result<Vec<Key>, KeyRepositoryError>;
        async fn list_available_symmetric(&self) -> Result<Vec<Key>, KeyRepositoryError>;
        async fn create(&self, key_type: KeyType, data: &KeyData, expires_at: Option<DateTime<Utc>>)
            -> Result<Key, KeyRepositoryError>;
        async fn update_certificate_by_oid(&self, oid: KeyOid, certificate_pem: &str)
            -> Result<Option<Key>, KeyRepositoryError>;
        async fn revoke_by_oid(&self, oid: KeyOid, revoked_at: DateTime<Utc>)
            -> Result<Option<Key>, KeyRepositoryError>;
    }
}
