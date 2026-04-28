use super::*;

#[derive(Default)]
pub(crate) struct InMemoryClientAuthorizationRepository {
    pub(crate) records: Mutex<HashMap<Uuid, ClientAuthorization>>,
}

pub(crate) struct InMemoryLoginRepository;

#[derive(Default)]
pub(crate) struct InMemoryCredentialRepository {
    pub(crate) credentials: Mutex<Vec<OpenIdConnectCredential>>,
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
        _session_oid: Option<Uuid>,
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
