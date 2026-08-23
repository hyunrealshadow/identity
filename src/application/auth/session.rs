use std::sync::Arc;

use chrono::Utc;
use identity_domain::auth::SessionOid;

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
        self.session_repo
            .revoke_by_oid(session_oid, Utc::now())
            .await?
            .ok_or_else(|| {
                AppError::from_code(AuthErrorCode::SessionNotFound)
                    .with_param("session_id", session_oid.0.to_string())
            })
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
