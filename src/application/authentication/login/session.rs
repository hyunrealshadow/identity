use super::{ChallengeOutcome, LoginService, SessionContext, requires_phishing_resistance};
use crate::{
    error::{AppError, codes::auth::AuthErrorCode},
    user::model::User,
};
use chrono::{DateTime, Duration, Utc};
use identity_domain::auth::{
    AuthenticationContextClass, ELEVATED_AUTHENTICATION_TTL, LoginStatus,
    RECENT_AUTHENTICATION_TTL, SESSION_EXPIRY,
    model::{Login, Session},
    repository::CreateSessionInput,
};
use tracing::error;
use uuid::Uuid;

impl LoginService {
    /// Finish a verified second factor short of `phr`. A `phr` request then
    /// asks the user to register a passkey on this device and authenticate
    /// with it; any other request completes at the multi-factor class.
    pub(super) async fn complete_second_factor(
        &self,
        login: Login,
        user_oid: Uuid,
        ctx: SessionContext,
        amr: &[String],
    ) -> Result<ChallengeOutcome, AppError> {
        if requires_phishing_resistance(&login) {
            self.login_repo
                .update_status(login.oid, LoginStatus::MFA_ENROLLMENT_REQUIRED, None, None)
                .await?;
            if let Err(e) = self.login_repo.reset_failed_attempts(login.oid).await {
                error!(error = %e, "failed to reset login failed attempts for passkey enrollment");
            }
            return Ok(ChallengeOutcome::MfaEnrollmentRequired { login });
        }
        self.complete_authentication(
            login,
            user_oid,
            ctx,
            AuthenticationContextClass::MultiFactor,
            amr,
        )
        .await
    }

    /// Establish `acr` on a new or bound session and mark the login
    /// authenticated. A forced reauthentication upgrades the bound session in
    /// place.
    pub(super) async fn complete_authentication(
        &self,
        login: Login,
        user_oid: Uuid,
        ctx: SessionContext,
        acr: AuthenticationContextClass,
        amr: &[String],
    ) -> Result<ChallengeOutcome, AppError> {
        let session = self
            .complete_session(&login, user_oid, ctx, acr, amr)
            .await?;
        if let Err(e) = self
            .login_repo
            .update_status(
                login.oid,
                LoginStatus::AUTHENTICATED,
                Some(session.oid),
                Some(acr),
            )
            .await
        {
            error!(error = %e, "failed to update login status to authenticated");
        }
        Ok(ChallengeOutcome::Authenticated {
            login,
            session: Box::new(session),
        })
    }

    pub(super) async fn complete_session(
        &self,
        login: &Login,
        user_oid: Uuid,
        ctx: SessionContext,
        acr: AuthenticationContextClass,
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
        let now = Utc::now();
        let expires_at =
            now + Duration::from_std(SESSION_EXPIRY).unwrap_or_else(|_| Duration::days(7));
        let acr_expires_at = Some(authentication_context_expires_at(acr));
        Ok(self
            .session_repo
            .complete_authentication(
                login.oid,
                session_oid,
                CreateSessionInput {
                    user_oid,
                    client_oid: Some(login.client_oid),
                    device_name: ctx.device_name,
                    device_type: ctx.device_type,
                    os_name: ctx.os_name,
                    os_version: ctx.os_version,
                    browser_name: ctx.browser_name,
                    browser_version: ctx.browser_version,
                    user_agent: ctx.user_agent,
                    ip_address: ctx.ip_address,
                    expires_at: Some(expires_at),
                    acr: Some(acr),
                    acr_expires_at,
                    amr: amr.to_vec(),
                },
            )
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

fn authentication_context_expires_at(acr: AuthenticationContextClass) -> DateTime<Utc> {
    let ttl = if acr.is_multi_factor() {
        ELEVATED_AUTHENTICATION_TTL
    } else {
        RECENT_AUTHENTICATION_TTL
    };
    Utc::now() + Duration::from_std(ttl).unwrap_or_else(|_| Duration::minutes(5))
}
