use super::*;
use identity_domain::auth::SessionOid;
use identity_domain::client_authorization::{
    ConsentState, SelectionSource, StoredAuthorizationRequest,
};
use identity_domain::openid_connect::AuthorizationRequest;
use identity_domain::openid_connect::AuthorizationRequestData;

fn can_overwrite_selection(current: Option<SelectionSource>, next: SelectionSource) -> bool {
    match (current, next) {
        (Some(SelectionSource::FreshLogin), SelectionSource::AccountPicker) => false,
        (Some(existing), incoming) if existing == incoming => true,
        (Some(SelectionSource::Auto), SelectionSource::AccountPicker) => true,
        (Some(SelectionSource::Auto), SelectionSource::FreshLogin) => true,
        (None, _) => true,
        _ => true,
    }
}

#[derive(Default)]
pub(in crate::openid_connect) struct InMemoryClientAuthorizationRepository {
    pub(in crate::openid_connect) records: Mutex<HashMap<Uuid, ClientAuthorization>>,
}

pub(in crate::openid_connect) struct InMemoryLoginRepository;

#[derive(Default)]
pub(in crate::openid_connect) struct InMemoryCredentialRepository {
    pub(in crate::openid_connect) credentials: Mutex<Vec<OpenIdConnectCredential>>,
}

#[async_trait]
impl ClientAuthorizationRepository for InMemoryClientAuthorizationRepository {
    async fn create(
        &self,
        client_oid: Uuid,
        type_: ClientAuthorizationType,
        data: serde_json::Value,
        expires_at: chrono::DateTime<chrono::Utc>,
    ) -> Result<ClientAuthorization, ClientAuthorizationRepositoryError> {
        let record = ClientAuthorization {
            oid: Uuid::new_v4(),
            client_oid,
            type_,
            data,
            expires_at,
            completed_at: None,
            revoked_at: None,
            created_at: chrono::Utc::now(),
            updated_at: None,
        };
        self.records
            .lock()
            .unwrap()
            .insert(record.oid, record.clone());
        Ok(record)
    }

    async fn find_by_oid(
        &self,
        oid: Uuid,
    ) -> Result<Option<ClientAuthorization>, ClientAuthorizationRepositoryError> {
        Ok(self.records.lock().unwrap().get(&oid).cloned())
    }

    async fn update_authorization_request_selection(
        &self,
        oid: Uuid,
        session_oid: SessionOid,
        user_oid: Uuid,
        protected_session_id: Option<String>,
        source: SelectionSource,
    ) -> Result<bool, ClientAuthorizationRepositoryError> {
        let mut records = self.records.lock().unwrap();
        let Some(record) = records.get_mut(&oid) else {
            return Ok(false);
        };
        if record.completed_at.is_some() {
            return Ok(false);
        }

        let Ok(mut stored) =
            serde_json::from_value::<StoredAuthorizationRequest>(record.data.clone())
        else {
            return Ok(false);
        };
        if !can_overwrite_selection(stored.interaction.selection_source, source) {
            return Ok(false);
        }

        stored.interaction.selected_session_oid = Some(session_oid);
        stored.interaction.selected_protected_session_id = protected_session_id;
        stored.interaction.selected_user_oid = Some(user_oid.to_string());
        stored.interaction.selection_source = Some(source);
        record.data = serde_json::to_value(stored).unwrap();
        record.updated_at = Some(chrono::Utc::now());
        Ok(true)
    }

    async fn record_authorization_request_consent(
        &self,
        oid: Uuid,
        consent_state: ConsentState,
        decided_at: chrono::DateTime<chrono::Utc>,
    ) -> Result<bool, ClientAuthorizationRepositoryError> {
        let mut records = self.records.lock().unwrap();
        let Some(record) = records.get_mut(&oid) else {
            return Ok(false);
        };
        if record.completed_at.is_some() {
            return Ok(false);
        }

        let Ok(mut stored) =
            serde_json::from_value::<StoredAuthorizationRequest>(record.data.clone())
        else {
            return Ok(false);
        };
        if stored.interaction.consent_state != ConsentState::Pending {
            return Ok(false);
        }

        stored.interaction.consent_state = consent_state;
        stored.interaction.consent_decided_at = Some(decided_at.to_rfc3339());
        record.data = serde_json::to_value(stored).unwrap();
        record.updated_at = Some(chrono::Utc::now());
        Ok(true)
    }

    async fn mark_authorization_request_completed(
        &self,
        oid: Uuid,
        completed_at: chrono::DateTime<chrono::Utc>,
    ) -> Result<bool, ClientAuthorizationRepositoryError> {
        let mut records = self.records.lock().unwrap();
        let Some(record) = records.get_mut(&oid) else {
            return Ok(false);
        };
        if record.completed_at.is_some() {
            return Ok(false);
        }

        record.completed_at = Some(completed_at);
        record.updated_at = Some(chrono::Utc::now());
        Ok(true)
    }

    async fn revoke_access_tokens_for_authorization_code(
        &self,
        _authorization_code_oid: Uuid,
    ) -> Result<(), ClientAuthorizationRepositoryError> {
        Ok(())
    }

    async fn revoke(&self, oid: Uuid) -> Result<(), ClientAuthorizationRepositoryError> {
        if let Some(record) = self.records.lock().unwrap().get_mut(&oid) {
            record.revoked_at = Some(chrono::Utc::now());
        }
        Ok(())
    }
}

impl InMemoryClientAuthorizationRepository {
    pub(in crate::openid_connect) fn insert_legacy_authorization_request_for_test(
        &self,
        request: &AuthorizationRequest,
    ) -> Uuid {
        let oid = Uuid::new_v4();
        self.records.lock().unwrap().insert(
            oid,
            ClientAuthorization {
                oid,
                client_oid: request.client_id,
                type_: ClientAuthorizationType::AuthorizationRequest,
                data: serde_json::to_value(AuthorizationRequestData::from(request)).unwrap(),
                expires_at: chrono::Utc::now() + chrono::Duration::minutes(10),
                completed_at: None,
                revoked_at: None,
                created_at: chrono::Utc::now(),
                updated_at: None,
            },
        );
        oid
    }

    pub(in crate::openid_connect) fn set_stored_request_redirect_uri_for_test(
        &self,
        oid: Uuid,
        redirect_uri: &str,
    ) {
        let mut records = self.records.lock().unwrap();
        let record = records.get_mut(&oid).unwrap();
        let mut stored =
            serde_json::from_value::<StoredAuthorizationRequest>(record.data.clone()).unwrap();
        stored.request.redirect_uri = redirect_uri.to_string();
        record.data = serde_json::to_value(stored).unwrap();
        record.updated_at = Some(chrono::Utc::now());
    }

    pub(in crate::openid_connect) fn completed_at_for_test(
        &self,
        oid: Uuid,
    ) -> Option<chrono::DateTime<chrono::Utc>> {
        self.records
            .lock()
            .unwrap()
            .get(&oid)
            .and_then(|record| record.completed_at)
    }
}

#[async_trait]
impl LoginRepository for InMemoryLoginRepository {
    async fn find_by_oid(&self, _oid: Uuid) -> Result<Option<Login>, LoginRepositoryError> {
        Ok(None)
    }

    async fn create_pending(
        &self,
        _client_oid: Uuid,
        _client_authorization_oid: Uuid,
        requested_acr: Option<&str>,
    ) -> Result<Login, LoginRepositoryError> {
        Ok(Login {
            oid: Uuid::new_v4(),
            client_oid: _client_oid,
            client_authorization_oid: _client_authorization_oid,
            session_oid: None,
            user_oid: None,
            status: LoginStatus::CREATED.to_string(),
            failed_attempts: 0,
            created_at: chrono::Utc::now(),
            acr: None,
            requested_acr: requested_acr.map(str::to_owned),
        })
    }

    async fn bind_user(
        &self,
        login_oid: Uuid,
        user_oid: Uuid,
        status: &str,
    ) -> Result<Login, LoginRepositoryError> {
        Ok(Login {
            oid: login_oid,
            client_oid: Uuid::new_v4(),
            client_authorization_oid: Uuid::new_v4(),
            session_oid: None,
            user_oid: Some(user_oid),
            status: status.to_string(),
            failed_attempts: 0,
            created_at: chrono::Utc::now(),
            acr: None,
            requested_acr: None,
        })
    }

    async fn update_status(
        &self,
        _login_oid: Uuid,
        _status: &str,
        _session_oid: Option<SessionOid>,
        _acr: Option<&str>,
    ) -> Result<(), LoginRepositoryError> {
        Ok(())
    }

    async fn increment_failed_attempts(
        &self,
        _login_oid: Uuid,
        _failure_reason: Option<&str>,
    ) -> Result<(), LoginRepositoryError> {
        Ok(())
    }
}

#[async_trait]
impl OpenIdConnectCredentialRepository for InMemoryCredentialRepository {
    async fn find_by_oid(
        &self,
        oid: Uuid,
    ) -> Result<Option<OpenIdConnectCredential>, OpenIdConnectCredentialRepositoryError> {
        Ok(self
            .credentials
            .lock()
            .unwrap()
            .iter()
            .find(|item| item.oid == oid)
            .cloned())
    }

    async fn find_by_client_oid_and_type(
        &self,
        client_oid: Uuid,
        type_: OpenIdConnectCredentialType,
    ) -> Result<Vec<OpenIdConnectCredential>, OpenIdConnectCredentialRepositoryError> {
        Ok(self
            .credentials
            .lock()
            .unwrap()
            .iter()
            .filter(|item| item.client_oid == client_oid && item.r#type == type_)
            .cloned()
            .collect())
    }
}
