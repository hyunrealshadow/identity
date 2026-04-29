use std::sync::Arc;

use chrono::Utc;
use uuid::Uuid;

use crate::{
    application::error::{AppError, codes::auth::AuthErrorCode},
    domain::auth::{
        SessionStatus,
        model::{ActiveSession, Session},
        repository::SessionRepository,
    },
};

pub struct SessionService {
    pub session_repo: Arc<dyn SessionRepository>,
}

impl SessionService {
    /// Resolve a list of session OIDs into active account views.
    ///
    /// Uses a single JOIN query via [`SessionRepository::find_active_accounts_by_oids`].
    /// Invalid, expired, or revoked sessions are silently filtered out.
    pub async fn get_active_accounts(
        &self,
        session_oids: &[Uuid],
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
        let oid_order: std::collections::HashMap<Uuid, usize> = session_oids
            .iter()
            .enumerate()
            .map(|(i, oid)| (*oid, i))
            .collect();
        views.sort_by_key(|v| oid_order.get(&v.session_oid).copied().unwrap_or(usize::MAX));

        Ok(views)
    }

    /// Select an existing session: validate it and update `last_active_at`.
    pub async fn select_session(&self, session_oid: Uuid) -> Result<Session, AppError> {
        let session = self
            .session_repo
            .find_by_oid(session_oid)
            .await?
            .ok_or_else(|| {
                AppError::from_code(AuthErrorCode::SessionNotFound)
                    .with_param("session_id", session_oid.to_string())
            })?;

        if session.status != SessionStatus::ACTIVE {
            return Err(AppError::from_code(AuthErrorCode::SessionExpired));
        }

        if let Some(expires_at) = &session.expires_at
            && Utc::now() > *expires_at
        {
            return Err(AppError::from_code(AuthErrorCode::SessionExpired));
        }

        if session.revoked_at.is_some() {
            return Err(AppError::from_code(AuthErrorCode::SessionRevoked));
        }

        // Touch the session.
        self.session_repo.touch_by_oid(session_oid).await?;

        // Re-fetch to get updated `last_active_at`.
        self.session_repo
            .find_by_oid(session_oid)
            .await?
            .ok_or_else(|| {
                AppError::from_code(AuthErrorCode::SessionNotFound)
                    .with_param("session_id", session_oid.to_string())
            })
    }

    pub async fn revoke(&self, session_oid: Uuid) -> Result<Session, AppError> {
        self.session_repo
            .revoke_by_oid(session_oid, Utc::now())
            .await?
            .ok_or_else(|| {
                AppError::from_code(AuthErrorCode::SessionNotFound)
                    .with_param("session_id", session_oid.to_string())
            })
    }
}
