use super::{
    AuthorizeService, code_flow::AuthorizationCodeContext, implicit_flow::AuthenticationContext,
};
use crate::{
    error::{AppError, codes::authorize::AuthorizeErrorCode},
    observability::{BusinessEvent, EventValue, error_outcome},
};
use chrono::{DateTime, Utc};
use identity_domain::{
    auth::{ACR_AAL2, AMR_MFA, AMR_OTP, AMR_PASSWORD, SessionOid},
    openid_connect::AuthorizationRequestData,
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
        let protected_session_id = match protected_session_id {
            Some(protected_session_id) => protected_session_id,
            None => self.encrypt_session_id(session_oid).await?,
        };

        let response_type = request.response_type.clone();

        let redirect = if response_type.is_implicit() {
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
