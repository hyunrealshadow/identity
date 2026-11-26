use super::{
    AuthorizeService, code_flow::AuthorizationCodeContext, implicit_flow::AuthenticationContext,
    management::ApprovalAuthentication,
};
use crate::{
    error::{AppError, codes::authorize},
    observability::{BusinessEvent, EventValue, error_outcome},
};
use chrono::{DateTime, Utc};
use identity_domain::{
    auth::{
        AMR_MFA, AMR_OTP, AMR_PASSWORD, AuthenticationContextClass, LoginStatus, SessionOid,
        SessionStatus, reported_acr,
    },
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
    pub acr: Option<AuthenticationContextClass>,
    pub amr: Vec<String>,
    /// The session was established before this request and the user did not
    /// authenticate during its interaction, so no sign-in was audited.
    pub existing_session: bool,
}

impl AuthorizeService {
    pub(super) fn interaction_conflict() -> AppError {
        authorize::error::AuthzInteractionConflict.into_error()
    }

    pub async fn mark_authorization_request_completed(
        &self,
        authorization_request_id: Uuid,
    ) -> Result<(), AppError> {
        let updated = self
            .client_authorization_repo
            .mark_authorization_request_completed(authorization_request_id, Utc::now())
            .await
            .map_err(authorize::error::StoreRequestFailed::map_source())?;

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
            .map_err(authorize::error::StoreRequestFailed::map_source())?;

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
        acr: Option<AuthenticationContextClass>,
    ) -> Result<Url, AppError> {
        let amr = default_amr_for_acr(acr);
        self.approve_authorization_request_with_protected_session_id(
            authorization_request_id,
            AuthorizationApproval {
                session_oid,
                user_oid,
                protected_session_id: None,
                auth_time,
                acr,
                amr,
                existing_session: false,
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
        acr: Option<AuthenticationContextClass>,
        amr: Vec<String>,
    ) -> Result<(Option<i64>, Option<AuthenticationContextClass>, Vec<String>), AppError> {
        let Some(session_repo) = &self.session_repo else {
            return Ok((auth_time, acr, amr));
        };
        let session = session_repo
            .find_by_oid(session_oid)
            .await
            .map_err(authorize::error::LoadRequestFailed::map_source())?
            .ok_or_else(|| authorize::error::AuthzInteractionConflict.into_error())?;
        let now = Utc::now();
        let active = session.status == SessionStatus::ACTIVE
            && session.revoked_at.is_none()
            && session.expires_at.is_none_or(|expires_at| expires_at > now)
            && session.user_oid == user_oid;
        if !active {
            return Err(authorize::error::AuthzInteractionConflict.into_error());
        }
        Ok((auth_time, session.effective_acr(now), session.amr))
    }

    async fn ensure_front_channel_user_enabled(&self, user_oid: Uuid) -> Result<(), AppError> {
        let user = self
            .user_repo
            .find_by_oid(UserOid(user_oid))
            .await
            .map_err(authorize::error::ClientLookupFailed::map_source())?
            .ok_or_else(|| authorize::error::ImplicitUserNotFound.into_error())?;
        if !user.enabled || user.locked {
            return Err(authorize::error::ImplicitUserNotFound.into_error());
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
            existing_session,
        } = approval;
        let stored = self
            .load_stored_authorization_request(authorization_request_id)
            .await?;
        let request = stored.request;
        let client_oid = Uuid::parse_str(&request.client_id)
            .map_err(authorize::error::StoredClientIdInvalid::map_source())?;

        let (auth_time, acr, amr) = self
            .validated_approval_authentication(session_oid, user_oid, auth_time, acr, amr)
            .await?;
        let request = self
            .clip_management_for_approval(&request, user_oid, ApprovalAuthentication { acr })
            .await?;
        // Management admission above uses the class actually established;
        // the client sees the most preferred class it asked for that is met.
        let acr = reported_acr(acr, request.acr_values.as_deref().unwrap_or_default());
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
                return Err(authorize::error::ResponseTypeInvalid::new(response_type).into_error());
            }
            self.approve_implicit_flow(
                &request,
                session_oid,
                &protected_session_id,
                user_oid,
                response_type,
                AuthenticationContext {
                    auth_time,
                    acr,
                    amr: &amr,
                },
            )
            .await?
        } else if response_type.uses_front_channel_response() {
            if rbac_snapshot.is_some() {
                return Err(authorize::error::ResponseTypeInvalid::new(response_type).into_error());
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
                    acr,
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
                        acr,
                        amr: &amr,
                    },
                    rbac_snapshot: rbac_snapshot.as_ref(),
                },
            )
            .await?
        };

        if existing_session {
            let completed = self
                .client_authorization_repo
                .complete_authorization_request_with_existing_session(
                    authorization_request_id,
                    Utc::now(),
                    user_oid,
                    client_oid,
                )
                .await
                .map_err(authorize::error::StoreRequestFailed::map_source())?;
            if !completed {
                return Err(Self::interaction_conflict());
            }
        } else {
            self.mark_authorization_request_completed(authorization_request_id)
                .await?;
        }

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
        Url::parse(&request.redirect_uri)
            .map_err(authorize::error::StoredRedirectUriInvalid::map_source())?;
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
        let amr = default_amr_for_acr(login.acr);
        self.approve_authorization_request_with_protected_session_id(
            login.client_authorization_oid,
            AuthorizationApproval {
                session_oid,
                user_oid,
                protected_session_id,
                auth_time,
                acr: login.acr,
                amr,
                existing_session: login.status != LoginStatus::AUTHENTICATED,
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

fn default_amr_for_acr(acr: Option<AuthenticationContextClass>) -> Vec<String> {
    let mut methods = vec![AMR_PASSWORD.to_owned()];
    if acr.is_some_and(AuthenticationContextClass::is_multi_factor) {
        methods.push(AMR_OTP.to_owned());
        methods.push(AMR_MFA.to_owned());
    }
    methods
}
