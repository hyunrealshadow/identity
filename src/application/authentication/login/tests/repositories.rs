use super::*;

pub(super) struct TestUserRepo {
    pub(super) user: Arc<Mutex<User>>,
}

#[async_trait]
impl UserRepository for TestUserRepo {
    async fn find_by_identifier(&self, _identifier: &str) -> Result<User, UserRepositoryError> {
        Ok(self.user.lock().unwrap().clone())
    }

    async fn find_by_oid(&self, oid: UserOid) -> Result<Option<User>, UserRepositoryError> {
        let user = self.user.lock().unwrap();
        Ok((user.oid == oid).then(|| user.clone()))
    }

    async fn increment_failed_attempts(
        &self,
        user_oid: UserOid,
        lock_threshold: i32,
        lock_until: DateTime<Utc>,
    ) -> Result<i32, UserRepositoryError> {
        let mut user = self.user.lock().unwrap();
        if user.oid != user_oid {
            return Err(UserRepositoryError::UserNotFound);
        }
        user.failed_attempts += 1;
        if user.failed_attempts >= lock_threshold {
            user.locked = true;
            user.locked_until = Some(lock_until);
        }
        Ok(user.failed_attempts)
    }

    async fn reset_failed_attempts(&self, user_oid: UserOid) -> Result<(), UserRepositoryError> {
        let mut user = self.user.lock().unwrap();
        if user.oid != user_oid {
            return Err(UserRepositoryError::UserNotFound);
        }
        user.failed_attempts = 0;
        user.locked = false;
        user.locked_until = None;
        Ok(())
    }

    async fn update_identifier(
        &self,
        _oid: UserOid,
        _update: UserIdentifierUpdate,
    ) -> Result<Option<User>, UserRepositoryError> {
        unimplemented!("identifier updates are not part of this test double")
    }

    async fn update_profile(
        &self,
        _oid: UserOid,
        _patch: UserProfilePatch,
    ) -> Result<Option<User>, UserRepositoryError> {
        unimplemented!("profile updates are not part of this test double")
    }
}

pub(super) struct TestCredentialRepo {
    pub(super) credentials: Vec<UserCredential>,
}

#[async_trait]
impl UserCredentialRepository for TestCredentialRepo {
    async fn find_by_user_oid_and_type(
        &self,
        _user_oid: UserOid,
        credential_type: CredentialType,
    ) -> Result<Vec<UserCredential>, UserCredentialRepositoryError> {
        Ok(self
            .credentials
            .iter()
            .filter(|credential| credential.r#type == credential_type)
            .cloned()
            .collect())
    }

    async fn update_password_by_oid(
        &self,
        _oid: UserCredentialOid,
        _expected: &Password,
        _password: &Password,
    ) -> Result<(), UserCredentialRepositoryError> {
        Ok(())
    }

    async fn change_password_and_revoke(
        &self,
        _user: UserOid,
        _credential: UserCredentialOid,
        _expected: &Password,
        _password: &Password,
        _keep: Option<SessionOid>,
    ) -> Result<u32, UserCredentialRepositoryError> {
        Ok(2)
    }

    async fn consume_totp_counter(
        &self,
        _credential_oid: UserCredentialOid,
        _counter: u64,
    ) -> Result<bool, UserCredentialRepositoryError> {
        Ok(true)
    }

    async fn replace_by_user_oid(
        &self,
        _user_oid: UserOid,
        _replacements: Vec<(CredentialType, Vec<CredentialData>)>,
    ) -> Result<(), UserCredentialRepositoryError> {
        Ok(())
    }

    async fn enable_totp_if_disabled(
        &self,
        _user_oid: UserOid,
        _otp: OtpCredentialData,
        _recovery_codes: Vec<RecoveryCodeCredentialData>,
    ) -> Result<bool, UserCredentialRepositoryError> {
        Ok(false)
    }

    async fn disable_totp(
        &self,
        _user_oid: UserOid,
    ) -> Result<bool, UserCredentialRepositoryError> {
        Ok(false)
    }

    async fn replace_recovery_codes_if_mfa_enabled(
        &self,
        _user_oid: UserOid,
        _recovery_codes: Vec<RecoveryCodeCredentialData>,
    ) -> Result<bool, UserCredentialRepositoryError> {
        Ok(false)
    }

    async fn consume_recovery_code_by_oid(
        &self,
        _credential_oid: UserCredentialOid,
    ) -> Result<bool, UserCredentialRepositoryError> {
        Ok(true)
    }
}

pub(super) struct TestSessionRepo;

#[async_trait]
impl SessionRepository for TestSessionRepo {
    async fn complete_authentication(
        &self,
        _login: Uuid,
        existing: Option<SessionOid>,
        input: CreateSessionInput,
    ) -> Result<Session, SessionRepositoryError> {
        match existing {
            Some(oid) => {
                self.reauthenticate_by_oid(
                    oid,
                    input.user_oid,
                    input.acr.as_deref().unwrap(),
                    input.acr_expires_at.unwrap(),
                    &input.amr,
                )
                .await
            }
            None => self.create(input).await,
        }
    }

    async fn find_by_oid(
        &self,
        _oid: SessionOid,
    ) -> Result<Option<Session>, SessionRepositoryError> {
        Ok(None)
    }

    async fn find_active_accounts_by_oids(
        &self,
        _oids: &[SessionOid],
    ) -> Result<Vec<ActiveSession>, SessionRepositoryError> {
        Ok(Vec::new())
    }

    async fn create(&self, input: CreateSessionInput) -> Result<Session, SessionRepositoryError> {
        Ok(Session {
            oid: SessionOid(Uuid::new_v4()),
            user_oid: input.user_oid,
            status: SessionStatus::ACTIVE,
            device_name: input.device_name,
            device_type: input.device_type,
            os_name: input.os_name,
            os_version: input.os_version,
            browser_name: input.browser_name,
            browser_version: input.browser_version,
            user_agent: input.user_agent,
            ip_address: input.ip_address,
            last_active_at: None,
            expires_at: input.expires_at,
            revoked_at: None,
            created_at: Utc::now(),
            acr: input.acr,
            acr_expires_at: input.acr_expires_at,
            amr: input.amr,
        })
    }

    async fn reauthenticate_by_oid(
        &self,
        oid: SessionOid,
        expected_user_oid: Uuid,
        acr: &str,
        acr_expires_at: DateTime<Utc>,
        amr: &[String],
    ) -> Result<Session, SessionRepositoryError> {
        Ok(Session {
            oid,
            user_oid: expected_user_oid,
            status: SessionStatus::ACTIVE,
            device_name: None,
            device_type: None,
            os_name: None,
            os_version: None,
            browser_name: None,
            browser_version: None,
            user_agent: None,
            ip_address: None,
            last_active_at: Some(Utc::now()),
            expires_at: None,
            revoked_at: None,
            created_at: Utc::now(),
            acr: Some(acr.to_owned()),
            acr_expires_at: Some(acr_expires_at),
            amr: amr.to_vec(),
        })
    }

    async fn touch_active_by_oid(&self, _oid: SessionOid) -> Result<bool, SessionRepositoryError> {
        Ok(true)
    }

    async fn revoke_by_oid(
        &self,
        _oid: SessionOid,
        _revoked_at: DateTime<Utc>,
    ) -> Result<Option<Session>, SessionRepositoryError> {
        Ok(None)
    }

    async fn list_by_user_oid(
        &self,
        _user_oid: Uuid,
    ) -> Result<Vec<Session>, SessionRepositoryError> {
        Ok(Vec::new())
    }

    async fn list_active_page_by_user_oid(
        &self,
        _user_oid: Uuid,
        _after: Option<SessionSortKey>,
        _before: Option<SessionSortKey>,
        _limit: usize,
        _direction: SessionPageDirection,
    ) -> Result<SessionPage, SessionRepositoryError> {
        Ok(SessionPage {
            items: Vec::new(),
            has_previous_page: false,
            has_next_page: false,
        })
    }
}

#[derive(Default)]
pub(super) struct TestLoginRepoState {
    pub(super) logins: Vec<Login>,
    pub(super) update_status_calls: Vec<(Uuid, LoginStatus)>,
}

pub(super) struct TestLoginRepo {
    pub(super) state: Arc<Mutex<TestLoginRepoState>>,
}

#[async_trait]
impl LoginRepository for TestLoginRepo {
    async fn find_by_oid(&self, oid: Uuid) -> Result<Option<Login>, LoginRepositoryError> {
        let state = self.state.lock().unwrap();
        Ok(state.logins.iter().find(|login| login.oid == oid).cloned())
    }

    async fn create_pending(
        &self,
        _client_oid: Uuid,
        _client_authorization_oid: Uuid,
        _requested_acr: Option<&str>,
    ) -> Result<Login, LoginRepositoryError> {
        Err(LoginRepositoryError::LoginNotFound)
    }

    async fn bind_user(
        &self,
        _login_oid: Uuid,
        _user_oid: Uuid,
    ) -> Result<Login, LoginRepositoryError> {
        Err(LoginRepositoryError::LoginNotFound)
    }

    async fn update_status(
        &self,
        login_oid: Uuid,
        status: LoginStatus,
        _session_oid: Option<SessionOid>,
        _acr: Option<&str>,
    ) -> Result<(), LoginRepositoryError> {
        let mut state = self.state.lock().unwrap();
        state.update_status_calls.push((login_oid, status));
        if let Some(login) = state.logins.iter_mut().find(|login| login.oid == login_oid) {
            login.status = status;
        }
        Ok(())
    }

    async fn reset_identity(&self, login_oid: Uuid) -> Result<(), LoginRepositoryError> {
        let mut state = self.state.lock().unwrap();
        let login = state
            .logins
            .iter_mut()
            .find(|login| login.oid == login_oid)
            .ok_or(LoginRepositoryError::LoginNotFound)?;
        if !matches!(
            login.status,
            LoginStatus::IDENTIFIER_VERIFIED | LoginStatus::MFA_REQUIRED
        ) {
            return Err(LoginRepositoryError::InvalidTransition);
        }
        login.status = LoginStatus::CREATED;
        login.user_oid = None;
        login.session_oid = None;
        login.acr = None;
        login.failed_attempts = 0;
        Ok(())
    }

    async fn bind_session(
        &self,
        login_oid: Uuid,
        session_oid: SessionOid,
    ) -> Result<(), LoginRepositoryError> {
        let mut state = self.state.lock().unwrap();
        let login = state
            .logins
            .iter_mut()
            .find(|login| login.oid == login_oid)
            .ok_or(LoginRepositoryError::LoginNotFound)?;
        login.session_oid = Some(session_oid);
        Ok(())
    }

    async fn increment_failed_attempts(
        &self,
        login_oid: Uuid,
        _failure_reason: Option<LoginFailureReason>,
    ) -> Result<i32, LoginRepositoryError> {
        let mut state = self.state.lock().unwrap();
        let login = state
            .logins
            .iter_mut()
            .find(|login| login.oid == login_oid)
            .ok_or(LoginRepositoryError::LoginNotFound)?;
        login.failed_attempts += 1;
        Ok(login.failed_attempts)
    }

    async fn reset_failed_attempts(&self, login_oid: Uuid) -> Result<(), LoginRepositoryError> {
        let mut state = self.state.lock().unwrap();
        if let Some(login) = state.logins.iter_mut().find(|login| login.oid == login_oid) {
            login.failed_attempts = 0;
        }
        Ok(())
    }
}
