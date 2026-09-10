use std::sync::Arc;

use chrono::Utc;
use identity_domain::auth::SessionOid;
use uuid::Uuid;

use crate::{
    application::error::{AppError, codes::auth::AuthErrorCode},
    domain::auth::{
        SessionStatus,
        model::{ActiveSession, Session},
        repository::SessionRepository,
    },
};

/// Outcome of revoking every session except one. Failures are reported per
/// session instead of being collapsed into a single result so callers can
/// express that a state change partially succeeded.
#[derive(Debug, Default)]
pub struct BatchRevocation {
    pub revoked: u32,
    pub failures: Vec<AppError>,
}

impl BatchRevocation {
    #[must_use]
    pub fn has_failures(&self) -> bool {
        !self.failures.is_empty()
    }

    #[must_use]
    pub fn failure_count(&self) -> u32 {
        self.failures.len() as u32
    }
}

pub struct SessionService {
    session_repo: Arc<dyn SessionRepository>,
    events: Arc<dyn crate::observability::EventSink>,
}

impl SessionService {
    #[must_use]
    pub fn new(session_repo: Arc<dyn SessionRepository>) -> Self {
        Self {
            session_repo,
            events: Arc::new(crate::observability::NoopEventSink),
        }
    }

    /// Attach the key event and audit sink.
    #[must_use]
    pub fn with_events(mut self, events: Arc<dyn crate::observability::EventSink>) -> Self {
        self.events = events;
        self
    }

    /// Resolve a list of session OIDs into active account views.
    ///
    /// Uses a single JOIN query via [`SessionRepository::find_active_accounts_by_oids`].
    /// Invalid, expired, or revoked sessions are silently filtered out.
    pub async fn get_active_accounts(
        &self,
        session_oids: &[SessionOid],
    ) -> Result<Vec<ActiveSession>, AppError> {
        if session_oids.is_empty() {
            return Ok(Vec::new());
        }

        let mut views = self
            .session_repo
            .find_active_accounts_by_oids(session_oids)
            .await?;

        // Filter out expired sessions client-side (DB query already filters by
        // status=active, this just catches rows where expires_at has passed).
        let now = Utc::now();
        views.retain(|v| v.expires_at.is_none_or(|exp| now <= exp));

        // Preserve the original cookie order.
        let oid_order: std::collections::HashMap<SessionOid, usize> = session_oids
            .iter()
            .enumerate()
            .map(|(i, oid)| (*oid, i))
            .collect();
        views.sort_by_key(|v| oid_order.get(&v.session_oid).copied().unwrap_or(usize::MAX));

        Ok(views)
    }

    /// Select an existing session: validate it and update `last_active_at`.
    pub async fn select_session(&self, session_oid: SessionOid) -> Result<Session, AppError> {
        let session = self
            .session_repo
            .find_by_oid(session_oid)
            .await?
            .ok_or_else(|| {
                AppError::from_code(AuthErrorCode::SessionNotFound)
                    .with_param("session_id", session_oid.0.to_string())
            })?;

        validate_selectable_session(&session)?;

        // The write repeats all lifecycle checks atomically. A concurrent
        // revoke or expiry therefore prevents `last_active_at` from changing.
        if !self.session_repo.touch_active_by_oid(session_oid).await? {
            let current = self
                .session_repo
                .find_by_oid(session_oid)
                .await?
                .ok_or_else(|| session_not_found(session_oid))?;
            validate_selectable_session(&current)?;
            return Err(AppError::from_code(AuthErrorCode::SessionExpired));
        }

        // Re-fetch and revalidate so a revoke committed immediately after the
        // touch cannot be returned as a selectable session.
        let session = self
            .session_repo
            .find_by_oid(session_oid)
            .await?
            .ok_or_else(|| session_not_found(session_oid))?;
        validate_selectable_session(&session)?;
        Ok(session)
    }

    pub async fn revoke(&self, session_oid: SessionOid) -> Result<Session, AppError> {
        let result = self
            .session_repo
            .revoke_by_oid(session_oid, Utc::now())
            .await?
            .ok_or_else(|| {
                AppError::from_code(AuthErrorCode::SessionNotFound)
                    .with_param("session_id", session_oid.0.to_string())
            })?;
        self.record_session_revoked(&result);
        Ok(result)
    }

    fn record_session_revoked(&self, session: &Session) {
        use crate::observability::{BusinessEvent, EventValue};
        self.events.emit(
            BusinessEvent::audit("session.revoked")
                .outcome("success")
                .attribute(
                    "session_oid",
                    EventValue::Pseudonymized {
                        purpose: "session_oid",
                        value: session.oid.0.to_string(),
                    },
                )
                .attribute(
                    "user_oid",
                    EventValue::Pseudonymized {
                        purpose: "user_oid",
                        value: session.user_oid.to_string(),
                    },
                ),
        );
    }

    /// Return a session only when it belongs to `user_oid`. Sessions owned by
    /// another account are reported as not found, matching the mutation
    /// contract that never discloses foreign session IDs.
    pub async fn find_owned(
        &self,
        session_oid: SessionOid,
        user_oid: Uuid,
    ) -> Result<Option<Session>, AppError> {
        let session = self.session_repo.find_by_oid(session_oid).await?;
        Ok(session.filter(|session| session.user_oid == user_oid))
    }

    /// Revoke a single session after checking ownership in the use case.
    pub async fn revoke_for_user(
        &self,
        session_oid: SessionOid,
        user_oid: Uuid,
    ) -> Result<Session, AppError> {
        let session = self
            .find_owned(session_oid, user_oid)
            .await?
            .ok_or_else(|| session_not_found(session_oid))?;
        if session.revoked_at.is_some() {
            return Ok(session);
        }
        self.revoke(session_oid).await
    }
    /// Revoke every active session of the user except `keep`.
    pub async fn revoke_other_sessions(
        &self,
        user_oid: Uuid,
        keep: SessionOid,
    ) -> Result<BatchRevocation, AppError> {
        let outcome =
            revoke_other_sessions_with(self.session_repo.as_ref(), user_oid, keep).await?;
        use crate::observability::{BusinessEvent, EventValue};
        let (outcome_label, severity) = if outcome.has_failures() {
            ("partial_failure", crate::observability::EventSeverity::Warn)
        } else {
            ("success", crate::observability::EventSeverity::Info)
        };
        self.events.emit(
            BusinessEvent::audit("session.revocation.batch")
                .severity(severity)
                .outcome(outcome_label)
                .attribute(
                    "user_oid",
                    EventValue::Pseudonymized {
                        purpose: "user_oid",
                        value: user_oid.to_string(),
                    },
                )
                .attribute(
                    "revoked_count",
                    EventValue::Integer(i64::from(outcome.revoked)),
                )
                .attribute(
                    "failed_count",
                    EventValue::Integer(i64::from(outcome.failure_count())),
                ),
        );
        Ok(outcome)
    }

    /// Cursor page over the user's active sessions for the session list view.
    pub async fn list_active_sessions_page(
        &self,
        user_oid: Uuid,
        after: Option<identity_domain::auth::repository::SessionSortKey>,
        before: Option<identity_domain::auth::repository::SessionSortKey>,
        limit: usize,
        direction: identity_domain::auth::repository::SessionPageDirection,
    ) -> Result<identity_domain::auth::repository::SessionPage, AppError> {
        self.session_repo
            .list_active_page_by_user_oid(user_oid, after, before, limit, direction)
            .await
            .map_err(AppError::from)
    }
}

fn validate_selectable_session(session: &Session) -> Result<(), AppError> {
    if session.revoked_at.is_some() {
        return Err(AppError::from_code(AuthErrorCode::SessionRevoked));
    }
    if session.status != SessionStatus::ACTIVE
        || session
            .expires_at
            .is_some_and(|expires_at| Utc::now() > expires_at)
    {
        return Err(AppError::from_code(AuthErrorCode::SessionExpired));
    }
    Ok(())
}

fn session_not_found(session_oid: SessionOid) -> AppError {
    AppError::from_code(AuthErrorCode::SessionNotFound)
        .with_param("session_id", session_oid.0.to_string())
}

/// Shared implementation used by session management and password changes.
/// Individual revocation failures are collected instead of aborting the batch.
pub(crate) async fn revoke_other_sessions_with(
    repo: &dyn SessionRepository,
    user_oid: Uuid,
    keep: SessionOid,
) -> Result<BatchRevocation, AppError> {
    let sessions = repo.list_by_user_oid(user_oid).await?;
    let mut outcome = BatchRevocation::default();
    for session in sessions
        .into_iter()
        .filter(|session| session.oid != keep)
        .filter(|session| session.revoked_at.is_none())
        .filter(|session| session.status == SessionStatus::ACTIVE)
    {
        match repo.revoke_by_oid(session.oid, Utc::now()).await {
            Ok(Some(_)) => outcome.revoked += 1,
            Ok(None) => outcome.failures.push(session_not_found(session.oid)),
            Err(error) => outcome.failures.push(AppError::from(error)),
        }
    }
    Ok(outcome)
}

#[cfg(test)]
mod tests {
    use async_trait::async_trait;
    use chrono::Utc;
    use identity_domain::auth::{
        SessionOid, SessionStatus,
        model::{ActiveSession, Session},
        repository::{
            CreateSessionInput, SessionPage, SessionPageDirection, SessionRepository,
            SessionRepositoryError, SessionSortKey,
        },
    };
    use uuid::Uuid;

    use super::{BatchRevocation, revoke_other_sessions_with};

    struct StubSessionRepo {
        sessions: Vec<Session>,
        failing_oid: Option<SessionOid>,
    }

    fn active_session(oid: SessionOid, user_oid: Uuid) -> Session {
        Session {
            oid,
            user_oid,
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
            acr: None,
            acr_expires_at: None,
            amr: Vec::new(),
        }
    }

    #[async_trait]
    impl SessionRepository for StubSessionRepo {
        async fn find_by_oid(
            &self,
            oid: SessionOid,
        ) -> Result<Option<Session>, SessionRepositoryError> {
            Ok(self
                .sessions
                .iter()
                .find(|session| session.oid == oid)
                .cloned())
        }

        async fn find_active_accounts_by_oids(
            &self,
            _oids: &[SessionOid],
        ) -> Result<Vec<ActiveSession>, SessionRepositoryError> {
            Ok(Vec::new())
        }

        async fn create(
            &self,
            _input: CreateSessionInput,
        ) -> Result<Session, SessionRepositoryError> {
            Err(SessionRepositoryError::CreateFailed(Box::new(
                std::io::Error::other("not used"),
            )))
        }

        async fn reauthenticate_by_oid(
            &self,
            _oid: SessionOid,
            _expected_user_oid: Uuid,
            _acr: &str,
            _acr_expires_at: chrono::DateTime<Utc>,
            _amr: &[String],
        ) -> Result<Session, SessionRepositoryError> {
            Err(SessionRepositoryError::ReauthenticateFailed(Box::new(
                std::io::Error::other("not used"),
            )))
        }

        async fn touch_active_by_oid(
            &self,
            _oid: SessionOid,
        ) -> Result<bool, SessionRepositoryError> {
            Ok(false)
        }

        async fn revoke_by_oid(
            &self,
            oid: SessionOid,
            _revoked_at: chrono::DateTime<Utc>,
        ) -> Result<Option<Session>, SessionRepositoryError> {
            if self.failing_oid == Some(oid) {
                return Err(SessionRepositoryError::RevokeFailed(Box::new(
                    std::io::Error::other("database unavailable"),
                )));
            }
            Ok(self
                .sessions
                .iter()
                .find(|session| session.oid == oid)
                .cloned())
        }

        async fn list_by_user_oid(
            &self,
            user_oid: Uuid,
        ) -> Result<Vec<Session>, SessionRepositoryError> {
            Ok(self
                .sessions
                .iter()
                .filter(|session| session.user_oid == user_oid)
                .cloned()
                .collect())
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

    #[tokio::test]
    async fn partial_revocation_reports_successes_and_failures_separately() {
        let user_oid = Uuid::new_v4();
        let current = SessionOid(Uuid::new_v4());
        let revoked = SessionOid(Uuid::new_v4());
        let failing = SessionOid(Uuid::new_v4());
        let repo = StubSessionRepo {
            sessions: vec![
                active_session(current, user_oid),
                active_session(revoked, user_oid),
                active_session(failing, user_oid),
            ],
            failing_oid: Some(failing),
        };

        let outcome: BatchRevocation = revoke_other_sessions_with(&repo, user_oid, current)
            .await
            .unwrap();

        assert_eq!(outcome.revoked, 1);
        assert_eq!(outcome.failure_count(), 1);
        assert!(outcome.has_failures());
    }

    #[tokio::test]
    async fn revocation_skips_the_current_and_unknown_sessions() {
        let user_oid = Uuid::new_v4();
        let current = SessionOid(Uuid::new_v4());
        let repo = StubSessionRepo {
            sessions: vec![active_session(current, user_oid)],
            failing_oid: None,
        };

        let outcome = revoke_other_sessions_with(&repo, user_oid, current)
            .await
            .unwrap();

        assert_eq!(outcome.revoked, 0);
        assert!(!outcome.has_failures());
    }
}
