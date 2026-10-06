use std::sync::Mutex;

use chrono::{Duration, Utc};
use identity_domain::auth::{
    LoginFailureReason, LoginStatus, SessionOid,
    model::Login,
    repository::{LoginRepository, LoginRepositoryError},
};
use uuid::Uuid;

// ─── LoginRepository test double (mockall can't handle &str lifetime params) ───

type UpdateStatusCall = (Uuid, String, Option<SessionOid>, Option<String>);
type BindSessionCall = (Uuid, SessionOid);

/// Simple test double for LoginRepository.  mockall's `mock!` macro cannot
/// generate a mock for this trait because the methods use `Option<&str>` and
/// `&str` parameters with elided lifetimes.
pub struct MockLoginRepository {
    pub find_by_oid_result: Mutex<Option<Option<Login>>>,
    pub create_pending_login: Mutex<Option<Login>>,
    pub create_pending_error: Mutex<Option<LoginRepositoryError>>,
    pub create_pending_calls: Mutex<Vec<Uuid>>,
    pub bind_user_login: Mutex<Option<Login>>,
    pub bind_user_error: Mutex<Option<LoginRepositoryError>>,
    pub bind_session_calls: Mutex<Vec<BindSessionCall>>,
    pub update_status_calls: Mutex<Vec<UpdateStatusCall>>,
    pub reset_identity_calls: Mutex<Vec<Uuid>>,
    pub increment_failed_attempts_calls: Mutex<Vec<(Uuid, Option<String>)>>,
    pub reset_failed_attempts_calls: Mutex<Vec<Uuid>>,
}

impl Default for MockLoginRepository {
    fn default() -> Self {
        Self {
            find_by_oid_result: Mutex::new(None),
            create_pending_login: Mutex::new(None),
            create_pending_error: Mutex::new(None),
            create_pending_calls: Mutex::new(Vec::new()),
            bind_user_login: Mutex::new(None),
            bind_user_error: Mutex::new(None),
            bind_session_calls: Mutex::new(Vec::new()),
            update_status_calls: Mutex::new(Vec::new()),
            reset_identity_calls: Mutex::new(Vec::new()),
            increment_failed_attempts_calls: Mutex::new(Vec::new()),
            reset_failed_attempts_calls: Mutex::new(Vec::new()),
        }
    }
}

#[async_trait::async_trait]
impl LoginRepository for MockLoginRepository {
    async fn find_by_oid(&self, _oid: Uuid) -> Result<Option<Login>, LoginRepositoryError> {
        Ok(self.find_by_oid_result.lock().unwrap().clone().flatten())
    }

    async fn create_pending(
        &self,
        client_oid: Uuid,
        client_authorization_oid: Uuid,
        requested_acr: Option<&str>,
    ) -> Result<Login, LoginRepositoryError> {
        self.create_pending_calls
            .lock()
            .unwrap()
            .push(client_authorization_oid);
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
        login_oid: Uuid,
        user_oid: Uuid,
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
        login.status = LoginStatus::IDENTIFIER_VERIFIED.to_owned();
        Ok(login)
    }

    async fn update_status(
        &self,
        login_oid: Uuid,
        status: LoginStatus,
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

    async fn reset_identity(&self, login_oid: Uuid) -> Result<(), LoginRepositoryError> {
        self.reset_identity_calls.lock().unwrap().push(login_oid);
        if let Some(Some(login)) = self.find_by_oid_result.lock().unwrap().as_mut() {
            login.status = LoginStatus::CREATED;
            login.user_oid = None;
            login.session_oid = None;
            login.acr = None;
            login.failed_attempts = 0;
        }
        Ok(())
    }

    async fn bind_session(
        &self,
        login_oid: Uuid,
        session_oid: SessionOid,
    ) -> Result<(), LoginRepositoryError> {
        self.bind_session_calls
            .lock()
            .unwrap()
            .push((login_oid, session_oid));
        if let Some(Some(login)) = self.find_by_oid_result.lock().unwrap().as_mut() {
            login.session_oid = Some(session_oid);
        }
        Ok(())
    }

    async fn increment_failed_attempts(
        &self,
        login_oid: Uuid,
        failure_reason: Option<LoginFailureReason>,
    ) -> Result<i32, LoginRepositoryError> {
        self.increment_failed_attempts_calls.lock().unwrap().push((
            login_oid,
            failure_reason.map(|value| value.as_str().to_owned()),
        ));
        Ok(1)
    }

    async fn reset_failed_attempts(&self, login_oid: Uuid) -> Result<(), LoginRepositoryError> {
        self.reset_failed_attempts_calls
            .lock()
            .unwrap()
            .push(login_oid);
        Ok(())
    }
}

/// Creates a MockLoginRepository with default behaviors matching the
/// previous InMemoryLoginRepository.
pub fn mock_login_repo() -> MockLoginRepository {
    MockLoginRepository {
        find_by_oid_result: Mutex::new(None),
        create_pending_login: Mutex::new(Some(Login {
            oid: Uuid::new_v4(),
            client_oid: Uuid::nil(),
            client_authorization_oid: Uuid::nil(),
            session_oid: None,
            user_oid: None,
            status: LoginStatus::CREATED,
            failed_attempts: 0,
            created_at: Utc::now(),
            expires_at: Utc::now() + Duration::minutes(5),
            acr: None,
            requested_acr: None,
        })),
        create_pending_error: Mutex::new(None),
        create_pending_calls: Mutex::new(Vec::new()),
        bind_user_login: Mutex::new(Some(Login {
            oid: Uuid::nil(),
            client_oid: Uuid::nil(),
            client_authorization_oid: Uuid::nil(),
            session_oid: None,
            user_oid: None,
            status: LoginStatus::AUTHENTICATED,
            failed_attempts: 0,
            created_at: Utc::now(),
            expires_at: Utc::now() + Duration::minutes(5),
            acr: None,
            requested_acr: None,
        })),
        bind_user_error: Mutex::new(None),
        bind_session_calls: Mutex::new(Vec::new()),
        update_status_calls: Mutex::new(Vec::new()),
        reset_identity_calls: Mutex::new(Vec::new()),
        increment_failed_attempts_calls: Mutex::new(Vec::new()),
        reset_failed_attempts_calls: Mutex::new(Vec::new()),
    }
}
