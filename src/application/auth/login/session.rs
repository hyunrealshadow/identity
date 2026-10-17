use super::{LoginService, SessionContext};
use crate::{
    error::{AppError, codes::auth::AuthErrorCode},
    user::model::User,
};
use chrono::{DateTime, Duration, Utc};
use identity_domain::auth::{
    ACR_AAL2, ELEVATED_AUTHENTICATION_TTL, RECENT_AUTHENTICATION_TTL, SESSION_EXPIRY,
    model::{Login, Session},
    repository::CreateSessionInput,
};
use uuid::Uuid;

impl LoginService {
    pub(super) async fn complete_session(
        &self,
        login: &Login,
        user_oid: Uuid,
        ctx: SessionContext,
        acr: &str,
        amr: &[String],
    ) -> Result<Session, AppError> {
        // A fresh login (including prompt=login) must complete its credential
        // checks before matching the authenticated user to a browser session.
        let session_oid = match login.session_oid {
            Some(oid) => Some(oid),
            None if ctx.browser_session_oids.is_empty() => None,
            None => {
                let sessions = self
                    .session_repo
                    .find_active_accounts_by_oids(&ctx.browser_session_oids)
                    .await?;
                let now = Utc::now();
                ctx.browser_session_oids.iter().copied().find(|oid| {
                    sessions.iter().any(|session| {
                        session.session_oid == *oid
                            && session.user_oid == user_oid
                            && session.expires_at.is_none_or(|expiry| expiry > now)
                    })
                })
            }
        };
        if let Some(session_oid) = session_oid {
            return Ok(self
                .session_repo
                .reauthenticate_by_oid(
                    session_oid,
                    user_oid,
                    acr,
                    authentication_context_expires_at(acr),
                    amr,
                )
                .await?);
        }
        self.create_session(user_oid, ctx, acr, amr).await
    }

    /// Create a session only for a login that is not bound to an existing one.
    async fn create_session(
        &self,
        user_oid: Uuid,
        ctx: SessionContext,
        acr: &str,
        amr: &[String],
    ) -> Result<Session, AppError> {
        let now = Utc::now();
        let expires_at =
            now + Duration::from_std(SESSION_EXPIRY).unwrap_or_else(|_| Duration::days(7));
        let acr_expires_at = Some(authentication_context_expires_at(acr));
        Ok(self
            .session_repo
            .create(CreateSessionInput {
                user_oid,
                device_name: ctx.device_name,
                device_type: ctx.device_type,
                os_name: ctx.os_name,
                os_version: ctx.os_version,
                browser_name: ctx.browser_name,
                browser_version: ctx.browser_version,
                user_agent: ctx.user_agent,
                ip_address: ctx.ip_address,
                expires_at: Some(expires_at),
                acr: Some(acr.to_owned()),
                acr_expires_at,
                amr: amr.to_vec(),
            })
            .await?)
    }

    pub(super) async fn ensure_user_can_authenticate(&self, user: &User) -> Result<(), AppError> {
        if !user.enabled {
            return Err(AppError::from_code(AuthErrorCode::UserLocked));
        }
        if !user.locked {
            return Ok(());
        }
        match user.locked_until {
            Some(until) if Utc::now() >= until => {
                self.user_repo.reset_failed_attempts(user.oid).await?;
                Ok(())
            }
            _ => Err(AppError::from_code(AuthErrorCode::UserLocked)),
        }
    }
}

fn authentication_context_expires_at(acr: &str) -> DateTime<Utc> {
    let ttl = if acr == ACR_AAL2 {
        ELEVATED_AUTHENTICATION_TTL
    } else {
        RECENT_AUTHENTICATION_TTL
    };
    Utc::now() + Duration::from_std(ttl).unwrap_or_else(|_| Duration::minutes(5))
}
