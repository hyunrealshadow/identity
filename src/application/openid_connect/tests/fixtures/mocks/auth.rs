// Re-export ClientAuthorizationRepository trait types
use chrono::{DateTime, Utc};
use identity_domain::auth::SessionOid;
use identity_domain::client::model::ClientOid;
pub use identity_domain::client_authorization::repository::{
    ClientAuthorizationRepository, ClientAuthorizationRepositoryError,
};
use identity_domain::client_authorization::{
    ClientAuthorization, ClientAuthorizationType, ConsentState, SelectionSource,
};

mockall::mock! {
    pub ClientAuthorizationRepository {}

    #[async_trait::async_trait]
    impl ClientAuthorizationRepository for ClientAuthorizationRepository {
        async fn create(
            &self,
            client_oid: ClientOid,
            type_: ClientAuthorizationType,
            data: serde_json::Value,
            expires_at: DateTime<Utc>,
        ) -> Result<ClientAuthorization, ClientAuthorizationRepositoryError>;
        async fn find_by_oid(
            &self,
            oid: uuid::Uuid,
        ) -> Result<Option<ClientAuthorization>, ClientAuthorizationRepositoryError>;
        async fn update_authorization_request_selection(
            &self,
            oid: uuid::Uuid,
            session_oid: SessionOid,
            user_oid: uuid::Uuid,
            protected_session_id: Option<String>,
            source: SelectionSource,
        ) -> Result<bool, ClientAuthorizationRepositoryError>;
        async fn record_authorization_request_consent(
            &self,
            oid: uuid::Uuid,
            consent_state: ConsentState,
            decided_at: DateTime<Utc>,
        ) -> Result<bool, ClientAuthorizationRepositoryError>;
        async fn mark_authorization_request_completed(
            &self,
            oid: uuid::Uuid,
            completed_at: DateTime<Utc>,
        ) -> Result<bool, ClientAuthorizationRepositoryError>;
        async fn revoke_access_tokens_for_authorization_code(
            &self,
            authorization_code_oid: uuid::Uuid,
        ) -> Result<(), ClientAuthorizationRepositoryError>;
        async fn revoke(
            &self,
            oid: uuid::Uuid,
        ) -> Result<(), ClientAuthorizationRepositoryError>;
    }
}

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

/// Creates a MockClientAuthorizationRepository backed by internal state,
/// matching the previous InMemoryClientAuthorizationRepository from token tests.
pub fn mock_client_auth_repo() -> MockClientAuthorizationRepository {
    let records: Arc<Mutex<HashMap<uuid::Uuid, ClientAuthorization>>> =
        Arc::new(Mutex::new(HashMap::new()));

    let mut mock = MockClientAuthorizationRepository::new();

    let r = records.clone();
    mock.expect_create()
        .returning(move |client_oid, type_, data, expires_at| {
            let record = ClientAuthorization {
                oid: uuid::Uuid::new_v4(),
                client_oid,
                type_,
                data,
                expires_at,
                completed_at: None,
                revoked_at: None,
                created_at: Utc::now(),
                updated_at: None,
            };
            r.lock().unwrap().insert(record.oid, record.clone());
            Ok(record)
        });

    let r = records.clone();
    mock.expect_find_by_oid()
        .returning(move |oid| Ok(r.lock().unwrap().get(&oid).cloned()));

    mock.expect_update_authorization_request_selection()
        .returning(|_oid, _session_oid, _user_oid, _protected_session_id, _source| Ok(false));
    mock.expect_record_authorization_request_consent()
        .returning(|_oid, _consent_state, _decided_at| Ok(false));
    mock.expect_mark_authorization_request_completed()
        .returning(|_oid, _completed_at| Ok(false));

    let r = records.clone();
    mock.expect_revoke_access_tokens_for_authorization_code()
        .returning(move |authorization_code_oid| {
            let authorization_code_oid = authorization_code_oid.to_string();
            for record in r.lock().unwrap().values_mut() {
                let should_revoke = record.type_ == ClientAuthorizationType::AccessToken
                    && serde_json::from_value::<
                        identity_domain::client_authorization::AccessTokenData,
                    >(record.data.clone())
                    .map(|data| {
                        data.authorization_code_oid.as_deref()
                            == Some(authorization_code_oid.as_str())
                    })
                    .unwrap_or(false);
                if should_revoke {
                    record.revoked_at = Some(Utc::now());
                }
            }
            Ok(())
        });

    let r = records;
    mock.expect_revoke().returning(move |oid| {
        if let Some(record) = r.lock().unwrap().get_mut(&oid) {
            record.revoked_at = Some(Utc::now());
        }
        Ok(())
    });

    mock
}
