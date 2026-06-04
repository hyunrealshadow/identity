use chrono::Utc;
use identity_domain::auth::SessionOid;
use identity_domain::auth::model::Login;
use identity_domain::auth::repository::{LoginRepository, LoginRepositoryError};

// ─── LoginRepository test double (mockall can't handle &str lifetime params) ───

/// Simple test double for LoginRepository.  mockall's `mock!` macro cannot
/// generate a mock for this trait because the methods use `Option<&str>` and
/// `&str` parameters with elided lifetimes.
pub struct MockLoginRepository {
    pub find_by_oid_result: std::sync::Mutex<Option<Option<Login>>>,
    pub create_pending_login: std::sync::Mutex<Option<Login>>,
    pub create_pending_error: std::sync::Mutex<Option<LoginRepositoryError>>,
    pub bind_user_login: std::sync::Mutex<Option<Login>>,
    pub bind_user_error: std::sync::Mutex<Option<LoginRepositoryError>>,
    pub update_status_calls:
        std::sync::Mutex<Vec<(uuid::Uuid, String, Option<SessionOid>, Option<String>)>>,
    pub increment_failed_attempts_calls: std::sync::Mutex<Vec<(uuid::Uuid, Option<String>)>>,
}

impl Default for MockLoginRepository {
    fn default() -> Self {
        Self {
            find_by_oid_result: std::sync::Mutex::new(None),
            create_pending_login: std::sync::Mutex::new(None),
            create_pending_error: std::sync::Mutex::new(None),
            bind_user_login: std::sync::Mutex::new(None),
            bind_user_error: std::sync::Mutex::new(None),
            update_status_calls: std::sync::Mutex::new(Vec::new()),
            increment_failed_attempts_calls: std::sync::Mutex::new(Vec::new()),
        }
    }
}

#[async_trait::async_trait]
impl LoginRepository for MockLoginRepository {
    async fn find_by_oid(&self, _oid: uuid::Uuid) -> Result<Option<Login>, LoginRepositoryError> {
        Ok(self.find_by_oid_result.lock().unwrap().clone().flatten())
    }

    async fn create_pending(
        &self,
        client_oid: uuid::Uuid,
        client_authorization_oid: uuid::Uuid,
        requested_acr: Option<&str>,
    ) -> Result<Login, LoginRepositoryError> {
        if let Some(err) = self.create_pending_error.lock().unwrap().take() {
            return Err(err);
        }
        let mut login = self
            .create_pending_login
            .lock()
            .unwrap()
            .clone()
            .ok_or(LoginRepositoryError::LoginNotFound)?;
        login.client_oid = client_oid;
        login.client_authorization_oid = client_authorization_oid;
        login.requested_acr = requested_acr.map(str::to_owned);
        Ok(login)
    }

    async fn bind_user(
        &self,
        login_oid: uuid::Uuid,
        user_oid: uuid::Uuid,
        status: &str,
    ) -> Result<Login, LoginRepositoryError> {
        if let Some(err) = self.bind_user_error.lock().unwrap().take() {
            return Err(err);
        }
        let mut login = self
            .bind_user_login
            .lock()
            .unwrap()
            .clone()
            .ok_or(LoginRepositoryError::LoginNotFound)?;
        login.oid = login_oid;
        login.user_oid = Some(user_oid);
        login.status = status.to_string();
        Ok(login)
    }

    async fn update_status(
        &self,
        login_oid: uuid::Uuid,
        status: &str,
        session_oid: Option<SessionOid>,
        acr: Option<&str>,
    ) -> Result<(), LoginRepositoryError> {
        self.update_status_calls.lock().unwrap().push((
            login_oid,
            status.to_string(),
            session_oid,
            acr.map(str::to_owned),
        ));
        Ok(())
    }

    async fn increment_failed_attempts(
        &self,
        login_oid: uuid::Uuid,
        failure_reason: Option<&str>,
    ) -> Result<(), LoginRepositoryError> {
        self.increment_failed_attempts_calls
            .lock()
            .unwrap()
            .push((login_oid, failure_reason.map(str::to_owned)));
        Ok(())
    }
}

/// Creates a MockLoginRepository with default behaviors matching the
/// previous InMemoryLoginRepository.
pub fn mock_login_repo() -> MockLoginRepository {
    MockLoginRepository {
        find_by_oid_result: std::sync::Mutex::new(None),
        create_pending_login: std::sync::Mutex::new(Some(Login {
            oid: uuid::Uuid::new_v4(),
            client_oid: uuid::Uuid::nil(),
            client_authorization_oid: uuid::Uuid::nil(),
            session_oid: None,
            user_oid: None,
            status: identity_domain::auth::LoginStatus::CREATED.to_string(),
            failed_attempts: 0,
            created_at: Utc::now(),
            acr: None,
            requested_acr: None,
        })),
        create_pending_error: std::sync::Mutex::new(None),
        bind_user_login: std::sync::Mutex::new(Some(Login {
            oid: uuid::Uuid::nil(),
            client_oid: uuid::Uuid::nil(),
            client_authorization_oid: uuid::Uuid::nil(),
            session_oid: None,
            user_oid: None,
            status: identity_domain::auth::LoginStatus::AUTHENTICATED.to_string(),
            failed_attempts: 0,
            created_at: Utc::now(),
            acr: None,
            requested_acr: None,
        })),
        bind_user_error: std::sync::Mutex::new(None),
        update_status_calls: std::sync::Mutex::new(Vec::new()),
        increment_failed_attempts_calls: std::sync::Mutex::new(Vec::new()),
    }
}
