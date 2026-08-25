use super::*;

use identity_domain::auth::SessionOid;
use identity_domain::client_authorization::{
    ClientAuthorizationData, ConsentState, SelectionSource, StoredAuthorizationRequest,
};

#[derive(Debug)]
pub struct TerminalReservation {
    pub completed_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug)]
pub struct ContinueContext {
    pub login: identity_domain::auth::model::Login,
    pub stored: StoredAuthorizationRequest,
    pub client: OpenIdConnectClient,
    pub expires_at: chrono::DateTime<chrono::Utc>,
    pub completed_at: Option<chrono::DateTime<chrono::Utc>>,
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

#[derive(Clone, Copy)]
pub(super) struct AuthorizationCodeContext<'a> {
    pub user_oid: Uuid,
    pub session_oid: SessionOid,
    pub protected_session_id: &'a str,
    pub authentication: super::implicit_flow::AuthenticationContext<'a>,
}

impl AuthorizeService {
    fn interaction_conflict() -> AppError {
        AppError::from_code(AuthorizeErrorCode::AuthzInteractionConflict)
    }

    async fn load_authorization_request_record(
        &self,
        authorization_request_id: Uuid,
    ) -> Result<identity_domain::client_authorization::ClientAuthorization, AppError> {
        let record = self
            .client_authorization_repo
            .find_by_oid(authorization_request_id)
            .await
            .map_err(|error| {
                AppError::from_code(AuthorizeErrorCode::LoadRequestFailed).with_source(error)
            })?
            .ok_or_else(|| AppError::from_code(AuthorizeErrorCode::AuthzRequestNotFound))?;

        if record.type_ != ClientAuthorizationType::AuthorizationRequest {
            return Err(AppError::from_code(
                AuthorizeErrorCode::AuthzRequestTypeMismatch,
            ));
        }

        Ok(record)
    }

    fn stored_authorization_request(
        data: ClientAuthorizationData,
    ) -> Result<StoredAuthorizationRequest, AppError> {
        match data {
            ClientAuthorizationData::AuthorizationRequest(stored) => Ok(stored),
            _ => Err(AppError::from_code(
                AuthorizeErrorCode::DeserializeRequestFailed,
            )),
        }
    }

    pub async fn create_authorization_request(
        &self,
        request: &AuthorizationRequest,
    ) -> Result<Uuid, AppError> {
        let data = ClientAuthorizationData::AuthorizationRequest(StoredAuthorizationRequest {
            request: AuthorizationRequestData::from(request),
            interaction: Default::default(),
        });

        let record = self
            .client_authorization_repo
            .create(
                request.client_id,
                data,
                chrono::Utc::now() + chrono::Duration::minutes(10),
            )
            .await
            .map_err(|error| {
                AppError::from_code(AuthorizeErrorCode::StoreRequestFailed).with_source(error)
            })?;

        Ok(record.oid)
    }

    pub async fn create_login_flow(
        &self,
        client_oid: Uuid,
        authorization_request_id: Uuid,
        requested_acr: Option<&str>,
    ) -> Result<String, AppError> {
        let login = self
            .login_repo
            .create_pending(client_oid, authorization_request_id, requested_acr)
            .await
            .map_err(|error| {
                AppError::from_code(AuthorizeErrorCode::StoreLoginFailed).with_source(error)
            })?;

        self.encrypt_login_id(login.oid).await
    }

    pub async fn load_authorization_request(
        &self,
        authorization_request_id: Uuid,
    ) -> Result<AuthorizationRequestData, AppError> {
        Ok(self
            .load_stored_authorization_request(authorization_request_id)
            .await?
            .request)
    }

    pub async fn load_stored_authorization_request(
        &self,
        authorization_request_id: Uuid,
    ) -> Result<StoredAuthorizationRequest, AppError> {
        let record = self
            .load_authorization_request_record(authorization_request_id)
            .await?;

        Self::stored_authorization_request(record.data)
    }

    pub async fn load_consent_context(
        &self,
        authorization_request_id: Uuid,
    ) -> Result<(AuthorizationRequestData, OpenIdConnectClient), AppError> {
        let request = self
            .load_authorization_request(authorization_request_id)
            .await?;
        let client_id = Uuid::parse_str(&request.client_id).map_err(|error| {
            AppError::from_code(AuthorizeErrorCode::StoredClientIdInvalid).with_source(error)
        })?;
        let client = self
            .client_repo
            .find_by_oid(client_id)
            .await
            .map_err(|error| {
                AppError::from_code(AuthorizeErrorCode::ClientLookupFailed).with_source(error)
            })?
            .ok_or_else(|| AppError::from_code(AuthorizeErrorCode::ClientNotFound))?;

        Ok((request, client))
    }

    pub async fn load_consent_context_by_login(
        &self,
        protected_login_oid: &str,
    ) -> Result<
        (
            identity_domain::auth::model::Login,
            AuthorizationRequestData,
            OpenIdConnectClient,
        ),
        AppError,
    > {
        let login = self.load_login_by_protected_id(protected_login_oid).await?;
        let (request, client) = self
            .load_consent_context(login.client_authorization_oid)
            .await?;
        Ok((login, request, client))
    }

    pub async fn load_continue_context_by_login(
        &self,
        protected_login_oid: &str,
    ) -> Result<ContinueContext, AppError> {
        let login = self.load_login_by_protected_id(protected_login_oid).await?;
        let record = self
            .load_authorization_request_record(login.client_authorization_oid)
            .await?;
        let expires_at = record.expires_at;
        let completed_at = record.completed_at;
        let stored = Self::stored_authorization_request(record.data)?;
        let client_id = Uuid::parse_str(&stored.request.client_id).map_err(|error| {
            AppError::from_code(AuthorizeErrorCode::StoredClientIdInvalid).with_source(error)
        })?;
        let client = self
            .client_repo
            .find_by_oid(client_id)
            .await
            .map_err(|error| {
                AppError::from_code(AuthorizeErrorCode::ClientLookupFailed).with_source(error)
            })?
            .ok_or_else(|| AppError::from_code(AuthorizeErrorCode::ClientNotFound))?;

        Ok(ContinueContext {
            login,
            stored,
            client,
            expires_at,
            completed_at,
        })
    }

    pub async fn record_selection_by_login(
        &self,
        protected_login_oid: &str,
        session_oid: SessionOid,
        user_oid: Uuid,
        protected_session_id: Option<String>,
        source: SelectionSource,
    ) -> Result<(), AppError> {
        let login = self.load_login_by_protected_id(protected_login_oid).await?;
        let stored = self
            .load_stored_authorization_request(login.client_authorization_oid)
            .await?;
        let selected_user_oid = user_oid.to_string();
        let is_reauthentication =
            stored.interaction.selection_source == Some(SelectionSource::Reauthentication);
        if is_reauthentication
            && (stored.interaction.selected_session_oid != Some(session_oid)
                || stored.interaction.selected_user_oid.as_deref()
                    != Some(selected_user_oid.as_str()))
        {
            return Err(Self::interaction_conflict());
        }
        let source = if is_reauthentication {
            SelectionSource::Reauthentication
        } else {
            source
        };
        self.record_authorization_selection(
            login.client_authorization_oid,
            session_oid,
            user_oid,
            protected_session_id,
            source,
        )
        .await?;
        // The initial forced-login selection binds the existing subject so the
        // challenge page can authenticate it.  Controllers record the selected
        // session again after a successful challenge; do not downgrade that
        // completed login back to `identifier_verified` on the second write.
        if source == SelectionSource::Reauthentication
            && login.status != identity_domain::auth::LoginStatus::AUTHENTICATED
        {
            self.login_repo
                .bind_user(login.oid, user_oid)
                .await
                .map_err(|error| {
                    AppError::from_code(AuthorizeErrorCode::StoreLoginFailed).with_source(error)
                })?;
        }
        self.login_repo
            .bind_session(login.oid, session_oid)
            .await
            .map_err(|error| {
                AppError::from_code(AuthorizeErrorCode::StoreLoginFailed).with_source(error)
            })
    }

    pub async fn record_consent_by_login(
        &self,
        protected_login_oid: &str,
        consent_state: ConsentState,
    ) -> Result<(), AppError> {
        let login = self.load_login_by_protected_id(protected_login_oid).await?;
        self.record_consent_decision(login.client_authorization_oid, consent_state)
            .await
    }

    pub async fn record_authorization_selection(
        &self,
        authorization_request_id: Uuid,
        session_oid: SessionOid,
        user_oid: Uuid,
        protected_session_id: Option<String>,
        source: SelectionSource,
    ) -> Result<(), AppError> {
        let updated = self
            .client_authorization_repo
            .update_authorization_request_selection(
                authorization_request_id,
                session_oid,
                user_oid,
                protected_session_id,
                source,
            )
            .await
            .map_err(|error| {
                AppError::from_code(AuthorizeErrorCode::StoreRequestFailed).with_source(error)
            })?;

        if !updated {
            return Err(Self::interaction_conflict());
        }

        Ok(())
    }

    pub async fn record_consent_decision(
        &self,
        authorization_request_id: Uuid,
        consent_state: ConsentState,
    ) -> Result<(), AppError> {
        let updated = self
            .client_authorization_repo
            .record_authorization_request_consent(
                authorization_request_id,
                consent_state,
                chrono::Utc::now(),
            )
            .await
            .map_err(|error| {
                AppError::from_code(AuthorizeErrorCode::StoreRequestFailed).with_source(error)
            })?;

        if !updated {
            return Err(Self::interaction_conflict());
        }

        Ok(())
    }

    pub async fn mark_authorization_request_completed(
        &self,
        authorization_request_id: Uuid,
    ) -> Result<(), AppError> {
        let updated = self
            .client_authorization_repo
            .mark_authorization_request_completed(authorization_request_id, chrono::Utc::now())
            .await
            .map_err(|error| {
                AppError::from_code(AuthorizeErrorCode::StoreRequestFailed).with_source(error)
            })?;

        if !updated {
            return Err(Self::interaction_conflict());
        }

        Ok(())
    }

    pub async fn reserve_authorization_request_terminal(
        &self,
        authorization_request_id: Uuid,
    ) -> Result<TerminalReservation, AppError> {
        let completed_at = chrono::Utc::now();
        let updated = self
            .client_authorization_repo
            .mark_authorization_request_completed(authorization_request_id, completed_at)
            .await
            .map_err(|error| {
                AppError::from_code(AuthorizeErrorCode::StoreRequestFailed).with_source(error)
            })?;

        if !updated {
            return Err(Self::interaction_conflict());
        }

        Ok(TerminalReservation { completed_at })
    }

    pub async fn load_login_by_protected_id(
        &self,
        protected_login_id: &str,
    ) -> Result<identity_domain::auth::model::Login, AppError> {
        let login_oid = self.decrypt_login_id(protected_login_id).await?;

        self.login_repo
            .find_by_oid(login_oid)
            .await
            .map_err(|error| {
                AppError::from_code(AuthorizeErrorCode::LoadLoginFailed).with_source(error)
            })?
            .ok_or_else(|| AppError::from_code(AuthorizeErrorCode::LoginNotFound))
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

    pub async fn approve_authorization_request_with_protected_session_id(
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
                super::implicit_flow::AuthenticationContext {
                    auth_time,
                    acr: acr.as_deref(),
                    amr: &amr,
                },
            )
            .await?
        } else if response_type.uses_front_channel_response() {
            self.approve_hybrid_flow(
                &request,
                session_oid,
                &protected_session_id,
                user_oid,
                response_type,
                super::implicit_flow::AuthenticationContext {
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
                    user_oid,
                    session_oid,
                    protected_session_id: &protected_session_id,
                    authentication: super::implicit_flow::AuthenticationContext {
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

    async fn approve_code_flow(
        &self,
        request: &AuthorizationRequestData,
        context: AuthorizationCodeContext<'_>,
    ) -> Result<Url, AppError> {
        let redirect_uri = Url::parse(&request.redirect_uri).map_err(|error| {
            AppError::from_code(AuthorizeErrorCode::StoredRedirectUriInvalid).with_source(error)
        })?;

        let (protected_code, _) = self.create_authorization_code(request, context).await?;

        let mut redirect = redirect_uri;
        redirect
            .query_pairs_mut()
            .append_pair("code", &protected_code)
            .append_pair("state", &request.state)
            .append_pair(
                "session_state",
                &session_state_for_authorize_response(request, context.protected_session_id)?,
            );

        Ok(redirect)
    }

    pub(super) async fn create_authorization_code(
        &self,
        request: &AuthorizationRequestData,
        context: AuthorizationCodeContext<'_>,
    ) -> Result<(String, Uuid), AppError> {
        let AuthorizationCodeContext {
            user_oid,
            session_oid,
            protected_session_id,
            authentication,
        } = context;
        let record = self
            .client_authorization_repo
            .create(
                Uuid::parse_str(&request.client_id).map_err(|error| {
                    AppError::from_code(AuthorizeErrorCode::StoredClientIdInvalid)
                        .with_source(error)
                })?,
                ClientAuthorizationData::AuthorizationCode(
                    identity_domain::client_authorization::AuthorizationCodeData {
                        scope: request.scope.clone(),
                        nonce: request.nonce.clone(),
                        code_challenge: request.code_challenge.clone(),
                        code_challenge_method: request.code_challenge_method,
                        user_oid: user_oid.to_string(),
                        session_oid,
                        protected_session_id: Some(protected_session_id.to_string()),
                        acr: authentication.acr.map(str::to_owned),
                        amr: authentication.amr.to_vec(),
                        redirect_uri: request.redirect_uri.clone(),
                        auth_time: authentication.auth_time,
                        claims: request
                            .claims
                            .as_deref()
                            .map(Self::parse_claims_request)
                            .transpose()?,
                    },
                ),
                chrono::Utc::now() + chrono::Duration::minutes(10),
            )
            .await
            .map_err(|error| {
                AppError::from_code(AuthorizeErrorCode::StoreCodeFailed).with_source(error)
            })?;

        let protected_code = self
            .data_protector
            .protect("authorization-code", record.oid.as_bytes())
            .await
            .map_err(|error| {
                AppError::from_code(AuthorizeErrorCode::StoreCodeFailed).with_source(error)
            })?;

        Ok((protected_code, record.oid))
    }

    pub async fn deny_authorization_request(
        &self,
        authorization_request_id: Uuid,
    ) -> Result<Url, AppError> {
        let request = self
            .load_authorization_request(authorization_request_id)
            .await?;
        let redirect_uri = Url::parse(&request.redirect_uri).map_err(|error| {
            AppError::from_code(AuthorizeErrorCode::StoredRedirectUriInvalid).with_source(error)
        })?;
        let error = OAuthErrorResponse::new(OAuthErrorCode::AccessDenied).with_state(request.state);

        let response_type = request.response_type.clone();

        let redirect = if response_type.uses_front_channel_response() {
            error.to_fragment_redirect_url(&redirect_uri)
        } else {
            error.to_redirect_url(&redirect_uri)
        };

        self.mark_authorization_request_completed(authorization_request_id)
            .await?;

        Ok(redirect)
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
    ) -> Result<Url, AppError> {
        let login = self.load_login_by_protected_id(protected_login_oid).await?;
        self.deny_authorization_request(login.client_authorization_oid)
            .await
    }
}

fn default_amr_for_acr(acr: Option<&str>) -> Vec<String> {
    let mut methods = vec![identity_domain::auth::AMR_PASSWORD.to_owned()];
    if acr == Some(identity_domain::auth::ACR_AAL2) {
        methods.push(identity_domain::auth::AMR_OTP.to_owned());
        methods.push(identity_domain::auth::AMR_MFA.to_owned());
    }
    methods
}

pub(super) fn session_state_for_authorize_response(
    request: &AuthorizationRequestData,
    protected_session_id: &str,
) -> Result<String, AppError> {
    let redirect_uri = Url::parse(&request.redirect_uri).map_err(|error| {
        AppError::from_code(AuthorizeErrorCode::StoredRedirectUriInvalid).with_source(error)
    })?;
    let origin = redirect_uri.origin().ascii_serialization();
    Ok(crate::openid_connect::session::calculate_session_state(
        &request.client_id,
        &origin,
        protected_session_id,
        protected_session_id,
    ))
}
