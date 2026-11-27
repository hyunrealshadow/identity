use std::{collections::HashMap, sync::Arc};

use chrono::{DateTime, Utc};
use identity_domain::auth::{
    SessionOid,
    repository::{SessionPage, SessionPageDirection, SessionSortKey},
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{
    application::{
        data_protection::DataProtector,
        error::{AppError, codes::graphql},
        pagination::{PageDirection, ValidatedPage, protect_json_cursors, unprotect_json_cursor},
    },
    domain::auth::{
        SessionStatus,
        model::{ActiveSession, Session},
        repository::SessionRepository,
    },
    observability::{BusinessEvent, EventSeverity, EventSink, EventValue, NoopEventSink},
};

const SESSION_CURSOR_PURPOSE: &str = "cursor:session";
const SESSION_CURSOR_VERSION: u8 = 1;

#[derive(Debug, Clone, Serialize, Deserialize)]
struct SessionCursorPayload {
    version: u8,
    user_oid: Uuid,
    last_active_at_micros: i64,
    id: i64,
}

/// One edge in an active-session Relay connection page.
#[derive(Debug, Clone)]
pub struct SessionEdge {
    pub cursor: String,
    pub session: Session,
}

/// Protected Relay connection page of active sessions for one user.
#[derive(Debug, Clone)]
pub struct SessionConnectionPage {
    pub edges: Vec<SessionEdge>,
    pub has_previous_page: bool,
    pub has_next_page: bool,
}

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
    data_protector: Option<Arc<dyn DataProtector>>,
    events: Arc<dyn EventSink>,
}

impl SessionService {
    #[must_use]
    pub fn new(session_repo: Arc<dyn SessionRepository>) -> Self {
        Self {
            session_repo,
            data_protector: None,
            events: Arc::new(NoopEventSink),
        }
    }

    /// Attach the data protector used to seal session pagination cursors.
    #[must_use]
    pub fn with_data_protector(mut self, data_protector: Arc<dyn DataProtector>) -> Self {
        self.data_protector = Some(data_protector);
        self
    }

    /// Attach the key event and audit sink.
    #[must_use]
    pub fn with_events(mut self, events: Arc<dyn EventSink>) -> Self {
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
        let oid_order: HashMap<SessionOid, usize> = session_oids
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
            .ok_or_else(|| session_not_found(session_oid))?;

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
            return Err(crate::error::codes::auth::error::SessionExpired.into());
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
        self.revoke_for_client(session_oid, None).await
    }

    /// Ends a session at the request of `client_oid`, recorded with the
    /// revocation, such as an RP-initiated logout.
    pub async fn revoke_for_client(
        &self,
        session_oid: SessionOid,
        client_oid: Option<Uuid>,
    ) -> Result<Session, AppError> {
        let result = self
            .session_repo
            .revoke_by_oid(session_oid, Utc::now(), client_oid)
            .await?
            .ok_or_else(|| session_not_found(session_oid))?;
        self.record_session_revoked(&result);
        Ok(result)
    }

    fn record_session_revoked(&self, session: &Session) {
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

        let (outcome_label, severity) = if outcome.has_failures() {
            ("partial_failure", EventSeverity::Warn)
        } else {
            ("success", EventSeverity::Info)
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
        after: Option<SessionSortKey>,
        before: Option<SessionSortKey>,
        limit: usize,
        direction: SessionPageDirection,
    ) -> Result<SessionPage, AppError> {
        self.session_repo
            .list_active_page_by_user_oid(user_oid, after, before, limit, direction)
            .await
            .map_err(AppError::from)
    }

    /// Protected Relay cursor connection over `user_oid`'s active sessions.
    pub async fn list_active_sessions_connection(
        &self,
        user_oid: Uuid,
        page: ValidatedPage<'_>,
    ) -> Result<SessionConnectionPage, AppError> {
        let protector = self
            .data_protector
            .as_deref()
            .ok_or_else(|| crate::error::codes::common::error::InternalError.into_error())?;
        let after = match page.after {
            Some(token) => Some(decode_session_cursor(protector, user_oid, token).await?),
            None => None,
        };
        let before = match page.before {
            Some(token) => Some(decode_session_cursor(protector, user_oid, token).await?),
            None => None,
        };
        let direction = match page.direction {
            PageDirection::Forward => SessionPageDirection::Forward,
            PageDirection::Backward => SessionPageDirection::Backward,
        };

        let result = self
            .list_active_sessions_page(user_oid, after, before, page.limit, direction)
            .await?;

        let payloads = result
            .items
            .iter()
            .map(|item| SessionCursorPayload {
                version: SESSION_CURSOR_VERSION,
                user_oid,
                last_active_at_micros: item.sort_key.last_active_at.timestamp_micros(),
                id: item.sort_key.id,
            })
            .collect::<Vec<_>>();
        let tokens = protect_json_cursors(protector, SESSION_CURSOR_PURPOSE, &payloads)
            .await
            .map_err(AppError::internal)?;

        let edges = result
            .items
            .into_iter()
            .zip(tokens)
            .map(|(item, cursor)| SessionEdge {
                cursor,
                session: item.session,
            })
            .collect();

        Ok(SessionConnectionPage {
            edges,
            has_previous_page: result.has_previous_page,
            has_next_page: result.has_next_page,
        })
    }
}

async fn decode_session_cursor(
    protector: &dyn DataProtector,
    expected_user_oid: Uuid,
    token: &str,
) -> Result<SessionSortKey, AppError> {
    let payload: SessionCursorPayload =
        unprotect_json_cursor(protector, SESSION_CURSOR_PURPOSE, token)
            .await
            .map_err(|_| graphql::error::InvalidCursor)?;
    if payload.version != SESSION_CURSOR_VERSION
        || payload.user_oid != expected_user_oid
        || payload.id <= 0
    {
        return Err(graphql::error::InvalidCursor.into());
    }
    let last_active_at = DateTime::from_timestamp_micros(payload.last_active_at_micros)
        .ok_or(graphql::error::InvalidCursor)?;
    Ok(SessionSortKey {
        last_active_at,
        id: payload.id,
    })
}

fn validate_selectable_session(session: &Session) -> Result<(), AppError> {
    if session.revoked_at.is_some() {
        return Err(crate::error::codes::auth::error::SessionRevoked.into());
    }
    if session.status != SessionStatus::ACTIVE
        || session
            .expires_at
            .is_some_and(|expires_at| Utc::now() > expires_at)
    {
        return Err(crate::error::codes::auth::error::SessionExpired.into());
    }
    Ok(())
}

fn session_not_found(session_oid: SessionOid) -> AppError {
    crate::error::codes::auth::error::SessionNotFound::new(session_oid.0).into()
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
        match repo.revoke_by_oid(session.oid, Utc::now(), None).await {
            Ok(Some(_)) => outcome.revoked += 1,
            Ok(None) => outcome.failures.push(session_not_found(session.oid)),
            Err(error) => outcome.failures.push(AppError::from(error)),
        }
    }
    Ok(outcome)
}

#[cfg(test)]
mod tests {
    use std::io::Error;

    use async_trait::async_trait;
    use chrono::{DateTime, Utc};
    use identity_domain::auth::{
        AuthenticationContextClass, SessionOid, SessionStatus,
        model::{ActiveSession, Session},
        repository::{
            CreateSessionInput, SessionPage, SessionPageDirection, SessionRepository,
            SessionRepositoryError, SessionSortKey,
        },
    };
    use uuid::Uuid;

    use super::{BatchRevocation, SessionService, revoke_other_sessions_with};
    use crate::{
        application::{
            data_protection::DataProtector,
            error::codes::graphql::GraphqlErrorCode,
            pagination::{RawPageArgs, validate_page_arguments},
        },
        domain::{auth::repository::SessionPageItem, data_protection::DataProtectionError},
    };
    use std::sync::{Arc, Mutex};

    struct TestProtector;

    #[async_trait]
    impl DataProtector for TestProtector {
        async fn protect(
            &self,
            purpose: &str,
            plaintext: &[u8],
        ) -> Result<String, DataProtectionError> {
            Ok(format!(
                "{purpose}:{}",
                String::from_utf8(plaintext.to_vec()).unwrap()
            ))
        }

        async fn unprotect(
            &self,
            purpose: &str,
            token: &str,
        ) -> Result<Vec<u8>, DataProtectionError> {
            let prefix = format!("{purpose}:");
            token
                .strip_prefix(&prefix)
                .map(|rest| rest.as_bytes().to_vec())
                .ok_or(DataProtectionError::InvalidProtectedPayload)
        }
    }

    struct StubSessionRepo {
        sessions: Vec<Session>,
        failing_oid: Option<SessionOid>,
        page_items: Vec<SessionPageItem>,
        last_after: Mutex<Option<SessionSortKey>>,
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
        async fn complete_authentication(
            &self,
            _login: Uuid,
            _existing: Option<SessionOid>,
            _input: CreateSessionInput,
        ) -> Result<Session, SessionRepositoryError> {
            Err(SessionRepositoryError::SessionNotFound)
        }

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
                Error::other("not used"),
            )))
        }

        async fn reauthenticate_by_oid(
            &self,
            _oid: SessionOid,
            _expected_user_oid: Uuid,
            _acr: AuthenticationContextClass,
            _acr_expires_at: DateTime<Utc>,
            _expires_at: DateTime<Utc>,
            _amr: &[String],
        ) -> Result<Session, SessionRepositoryError> {
            Err(SessionRepositoryError::ReauthenticateFailed(Box::new(
                Error::other("not used"),
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
            _revoked_at: DateTime<Utc>,
            _client_oid: Option<Uuid>,
        ) -> Result<Option<Session>, SessionRepositoryError> {
            if self.failing_oid == Some(oid) {
                return Err(SessionRepositoryError::RevokeFailed(Box::new(
                    Error::other("database unavailable"),
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
            after: Option<SessionSortKey>,
            _before: Option<SessionSortKey>,
            _limit: usize,
            _direction: SessionPageDirection,
        ) -> Result<SessionPage, SessionRepositoryError> {
            *self.last_after.lock().unwrap() = after;
            let items = self
                .page_items
                .iter()
                .map(|item| SessionPageItem {
                    session: item.session.clone(),
                    sort_key: item.sort_key,
                })
                .collect::<Vec<_>>();
            let has_next_page = !items.is_empty();
            Ok(SessionPage {
                items,
                has_previous_page: false,
                has_next_page,
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
            page_items: Vec::new(),
            last_after: Mutex::new(None),
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
            page_items: Vec::new(),
            last_after: Mutex::new(None),
        };

        let outcome = revoke_other_sessions_with(&repo, user_oid, current)
            .await
            .unwrap();

        assert_eq!(outcome.revoked, 0);
        assert!(!outcome.has_failures());
    }

    #[tokio::test]
    async fn session_connection_protects_sort_keys_and_binds_cursors_to_user() {
        let alice = Uuid::new_v4();
        let bob = Uuid::new_v4();
        let session = active_session(SessionOid(Uuid::new_v4()), alice);
        let sort_key = SessionSortKey {
            last_active_at: chrono::TimeZone::timestamp_micros(&Utc, 1_800_000_000_123_456)
                .unwrap(),
            id: 42,
        };
        let repo = Arc::new(StubSessionRepo {
            sessions: Vec::new(),
            failing_oid: None,
            page_items: vec![SessionPageItem { session, sort_key }],
            last_after: Mutex::new(None),
        });
        let service =
            SessionService::new(repo.clone()).with_data_protector(Arc::new(TestProtector));

        let first_page = service
            .list_active_sessions_connection(
                alice,
                validate_page_arguments(RawPageArgs::from_i32(Some(10), None, None, None), 20, 100)
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(first_page.edges.len(), 1);
        let cursor = first_page.edges[0].cursor.clone();

        service
            .list_active_sessions_connection(
                alice,
                validate_page_arguments(
                    RawPageArgs::from_i32(Some(10), Some(&cursor), None, None),
                    20,
                    100,
                )
                .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            repo.last_after
                .lock()
                .unwrap()
                .map(|key| (key.last_active_at, key.id)),
            Some((sort_key.last_active_at, sort_key.id))
        );

        let cross_user_err = service
            .list_active_sessions_connection(
                bob,
                validate_page_arguments(
                    RawPageArgs::from_i32(Some(10), Some(&cursor), None, None),
                    20,
                    100,
                )
                .unwrap(),
            )
            .await
            .unwrap_err();
        assert_eq!(
            cross_user_err.code(),
            GraphqlErrorCode::InvalidCursor as u32
        );
    }

    #[tokio::test]
    async fn session_connection_rejects_non_positive_cursor_id() {
        let user_oid = Uuid::new_v4();
        let protector = Arc::new(TestProtector);
        let repo = Arc::new(StubSessionRepo {
            sessions: Vec::new(),
            failing_oid: None,
            page_items: Vec::new(),
            last_after: Mutex::new(None),
        });
        let service = SessionService::new(repo).with_data_protector(protector.clone());
        let forged = protector
            .protect(
                super::SESSION_CURSOR_PURPOSE,
                serde_json::to_vec(&super::SessionCursorPayload {
                    version: super::SESSION_CURSOR_VERSION,
                    user_oid,
                    last_active_at_micros: 1_800_000_000_000_000,
                    id: 0,
                })
                .unwrap()
                .as_slice(),
            )
            .await
            .unwrap();

        let err = service
            .list_active_sessions_connection(
                user_oid,
                validate_page_arguments(
                    RawPageArgs::from_i32(Some(10), Some(&forged), None, None),
                    20,
                    100,
                )
                .unwrap(),
            )
            .await
            .unwrap_err();
        assert_eq!(err.code(), GraphqlErrorCode::InvalidCursor as u32);
    }
}
