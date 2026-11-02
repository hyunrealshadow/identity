use super::{
    AuthorizeService, code_flow::AuthorizationCodeContext, implicit_flow::AuthenticationContext,
    management::ApprovalAuthentication,
};
use crate::{
    error::{AppError, codes::authorize::AuthorizeErrorCode},
    observability::{BusinessEvent, EventValue, error_outcome},
};
use chrono::{DateTime, Utc};
use identity_domain::{
    auth::{ACR_AAL2, AMR_MFA, AMR_OTP, AMR_PASSWORD, SessionOid, SessionStatus},
    openid_connect::AuthorizationRequestData,
    user::UserOid,
};
use url::Url;
use uuid::Uuid;

#[derive(Debug)]
pub struct TerminalReservation {
    pub completed_at: DateTime<Utc>,
}

#[derive(Debug)]
pub struct AuthorizationApproval {
    pub session_oid: SessionOid,
    pub user_oid: Uuid,
    pub protected_session_id: Option<String>,
    pub auth_time: Option<i64>,
    pub acr: Option<String>,
    pub amr: Vec<String>,
}

impl AuthorizeService {
    pub(super) fn interaction_conflict() -> AppError {
        AppError::from_code(AuthorizeErrorCode::AuthzInteractionConflict)
    }

    pub async fn mark_authorization_request_completed(
        &self,
        authorization_request_id: Uuid,
    ) -> Result<(), AppError> {
        let updated = self
            .client_authorization_repo
            .mark_authorization_request_completed(authorization_request_id, Utc::now())
            .await
            .map_err(AppError::map_source(AuthorizeErrorCode::StoreRequestFailed))?;

        if !updated {
            return Err(Self::interaction_conflict());
        }

        Ok(())
    }

    pub async fn reserve_authorization_request_terminal(
        &self,
        authorization_request_id: Uuid,
    ) -> Result<TerminalReservation, AppError> {
        let completed_at = Utc::now();
        let updated = self
            .client_authorization_repo
            .mark_authorization_request_completed(authorization_request_id, completed_at)
            .await
            .map_err(AppError::map_source(AuthorizeErrorCode::StoreRequestFailed))?;

        if !updated {
            return Err(Self::interaction_conflict());
        }

        Ok(TerminalReservation { completed_at })
    }

    pub async fn approve_authorization_request(
        &self,
        authorization_request_id: Uuid,
        session_oid: SessionOid,
        user_oid: Uuid,
        auth_time: Option<i64>,
        acr: Option<String>,
    ) -> Result<Url, AppError> {
        let amr = default_amr_for_acr(acr.as_deref());
        self.approve_authorization_request_with_protected_session_id(
            authorization_request_id,
            AuthorizationApproval {
                session_oid,
                user_oid,
                protected_session_id: None,
                auth_time,
                acr,
                amr,
            },
        )
        .await
    }

    #[tracing::instrument(skip_all, name = "authorization.approve")]
    pub async fn approve_authorization_request_with_protected_session_id(
        &self,
        authorization_request_id: Uuid,
        approval: AuthorizationApproval,
    ) -> Result<Url, AppError> {
        let user_oid = approval.user_oid;
        let session_oid = approval.session_oid;
        let result = self
            .approve_authorization_request_inner(authorization_request_id, approval)
            .await;
        match &result {
            Ok(_) => self.events.emit(
                BusinessEvent::business("authorization.flow.result")
                    .outcome("granted")
                    .attribute(
                        "authorization_request_id",
                        EventValue::Text(authorization_request_id.to_string()),
                    )
                    .attribute(
                        "user_oid",
                        EventValue::Pseudonymized {
                            purpose: "user_oid",
                            value: user_oid.to_string(),
                        },
                    )
                    .attribute(
                        "session_oid",
                        EventValue::Pseudonymized {
                            purpose: "session_oid",
                            value: session_oid.0.to_string(),
                        },
                    ),
            ),
            Err(error) => {
                let (outcome, reason) = error_outcome(error);
                self.events.emit(
                    BusinessEvent::business("authorization.flow.result")
                        .outcome(outcome)
                        .reason(reason)
                        .attribute(
                            "authorization_request_id",
                            EventValue::Text(authorization_request_id.to_string()),
                        )
                        .attribute(
                            "session_oid",
                            EventValue::Pseudonymized {
                                purpose: "session_oid",
                                value: session_oid.0.to_string(),
                            },
                        )
                        .attribute("error_code", EventValue::Integer(i64::from(error.code()))),
                );
            }
        }
        result
    }

    /// Approval must use a live, matching session. When the optional port is
    /// absent (old unit factories) the caller-provided context is retained;
    /// production always supplies the repository. A live session's effective
    /// ACR is used so an expired AAL2 window cannot be promoted again from
    /// historical AMR.
    async fn validated_approval_authentication(
        &self,
        session_oid: SessionOid,
        user_oid: Uuid,
        auth_time: Option<i64>,
        acr: Option<String>,
        amr: Vec<String>,
    ) -> Result<(Option<i64>, Option<String>, Vec<String>), AppError> {
        let Some(session_repo) = &self.session_repo else {
            return Ok((auth_time, acr, amr));
        };
        let session = session_repo
            .find_by_oid(session_oid)
            .await
            .map_err(AppError::map_source(AuthorizeErrorCode::LoadRequestFailed))?
            .ok_or_else(|| {
                AppError::from_code(AuthorizeErrorCode::AuthzInteractionConflict)
                    .with_param("reason", "approval session was not found")
            })?;
        let now = Utc::now();
        let active = session.status == SessionStatus::ACTIVE
            && session.revoked_at.is_none()
            && session.expires_at.is_none_or(|expires_at| expires_at > now)
            && session.user_oid == user_oid;
        if !active {
            return Err(
                AppError::from_code(AuthorizeErrorCode::AuthzInteractionConflict)
                    .with_param("reason", "approval session is not active for the user"),
            );
        }
        Ok((
            auth_time,
            session.effective_acr(now).map(str::to_owned),
            session.amr,
        ))
    }

    async fn ensure_front_channel_user_enabled(&self, user_oid: Uuid) -> Result<(), AppError> {
        let user = self
            .user_repo
            .find_by_oid(UserOid(user_oid))
            .await
            .map_err(AppError::map_source(AuthorizeErrorCode::ClientLookupFailed))?
            .ok_or_else(|| AppError::from_code(AuthorizeErrorCode::ImplicitUserNotFound))?;
        if !user.enabled || user.locked {
            return Err(
                AppError::from_code(AuthorizeErrorCode::ImplicitUserNotFound)
                    .with_param("reason", "user is disabled or locked"),
            );
        }
        Ok(())
    }

    async fn approve_authorization_request_inner(
        &self,
        authorization_request_id: Uuid,
        approval: AuthorizationApproval,
    ) -> Result<Url, AppError> {
        let AuthorizationApproval {
            session_oid,
            user_oid,
            protected_session_id,
            auth_time,
            acr,
            amr,
        } = approval;
        let stored = self
            .load_stored_authorization_request(authorization_request_id)
            .await?;
        let request = stored.request;
        let _client_oid = Uuid::parse_str(&request.client_id).map_err(AppError::map_source(
            AuthorizeErrorCode::StoredClientIdInvalid,
        ))?;

        let (auth_time, acr, amr) = self
            .validated_approval_authentication(session_oid, user_oid, auth_time, acr, amr)
            .await?;
        let request = self
            .clip_management_for_approval(
                &request,
                user_oid,
                ApprovalAuthentication {
                    acr: acr.as_deref(),
                    amr: &amr,
                },
            )
            .await?;
        let rbac = self.clip_rbac_for_approval(&request, user_oid).await?;
        let request = rbac.request;
        let rbac_snapshot = rbac.snapshot;
        let protected_session_id = match protected_session_id {
            Some(protected_session_id) => protected_session_id,
            None => self.encrypt_session_id(session_oid).await?,
        };

        let response_type = request.response_type.clone();
        if response_type.is_implicit() || response_type.uses_front_channel_response() {
            self.ensure_front_channel_user_enabled(user_oid).await?;
        }

        let redirect = if response_type.is_implicit() {
            if rbac_snapshot.is_some() {
                return Err(AppError::from_code(AuthorizeErrorCode::ResponseTypeInvalid)
                    .with_param("response_type", response_type.to_string()));
            }
            self.approve_implicit_flow(
                &request,
                session_oid,
                &protected_session_id,
                user_oid,
                response_type,
                AuthenticationContext {
                    auth_time,
                    acr: acr.as_deref(),
                    amr: &amr,
                },
            )
            .await?
        } else if response_type.uses_front_channel_response() {
            if rbac_snapshot.is_some() {
                return Err(AppError::from_code(AuthorizeErrorCode::ResponseTypeInvalid)
                    .with_param("response_type", response_type.to_string()));
            }
            self.approve_hybrid_flow(
                &request,
                authorization_request_id,
                session_oid,
                &protected_session_id,
                user_oid,
                response_type,
                AuthenticationContext {
                    auth_time,
                    acr: acr.as_deref(),
                    amr: &amr,
                },
            )
            .await?
        } else {
            self.approve_code_flow(
                &request,
                AuthorizationCodeContext {
                    authorization_request_id,
                    user_oid,
                    session_oid,
                    protected_session_id: &protected_session_id,
                    authentication: AuthenticationContext {
                        auth_time,
                        acr: acr.as_deref(),
                        amr: &amr,
                    },
                    rbac_snapshot: rbac_snapshot.as_ref(),
                },
            )
            .await?
        };

        self.mark_authorization_request_completed(authorization_request_id)
            .await?;

        Ok(redirect)
    }

    #[tracing::instrument(skip_all, name = "authorization.deny")]
    pub async fn deny_authorization_request(
        &self,
        authorization_request_id: Uuid,
    ) -> Result<AuthorizationRequestData, AppError> {
        let request = self
            .load_authorization_request(authorization_request_id)
            .await?;
        Url::parse(&request.redirect_uri).map_err(AppError::map_source(
            AuthorizeErrorCode::StoredRedirectUriInvalid,
        ))?;
        self.provider_service.issuer()?;

        self.mark_authorization_request_completed(authorization_request_id)
            .await?;

        self.events.emit(
            BusinessEvent::business("authorization.flow.result")
                .outcome("denied")
                .reason("access_denied")
                .attribute(
                    "authorization_request_id",
                    EventValue::Text(authorization_request_id.to_string()),
                ),
        );

        Ok(request)
    }

    pub async fn approve_authorization_request_by_login(
        &self,
        protected_login_oid: &str,
        session_oid: SessionOid,
        user_oid: Uuid,
        protected_session_id: Option<String>,
        auth_time: Option<i64>,
    ) -> Result<Url, AppError> {
        let login = self.load_login_by_protected_id(protected_login_oid).await?;
        let amr = default_amr_for_acr(login.acr.as_deref());
        self.approve_authorization_request_with_protected_session_id(
            login.client_authorization_oid,
            AuthorizationApproval {
                session_oid,
                user_oid,
                protected_session_id,
                auth_time,
                acr: login.acr,
                amr,
            },
        )
        .await
    }

    pub async fn deny_authorization_request_by_login(
        &self,
        protected_login_oid: &str,
    ) -> Result<AuthorizationRequestData, AppError> {
        let login = self.load_login_by_protected_id(protected_login_oid).await?;
        self.deny_authorization_request(login.client_authorization_oid)
            .await
    }
}

fn default_amr_for_acr(acr: Option<&str>) -> Vec<String> {
    let mut methods = vec![AMR_PASSWORD.to_owned()];
    if acr == Some(ACR_AAL2) {
        methods.push(AMR_OTP.to_owned());
        methods.push(AMR_MFA.to_owned());
    }
    methods
}
