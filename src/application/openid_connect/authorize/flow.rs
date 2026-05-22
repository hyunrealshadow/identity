use super::*;
use std::str::FromStr;

use identity_domain::auth::SessionOid;
use identity_domain::client_authorization::{
    AuthorizationInteractionState, ConsentState, SelectionSource, StoredAuthorizationRequest,
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

    fn deserialize_stored_authorization_request(
        data: serde_json::Value,
    ) -> Result<StoredAuthorizationRequest, AppError> {
        serde_json::from_value::<StoredAuthorizationRequest>(data.clone())
            .or_else(|_| {
                serde_json::from_value::<AuthorizationRequestData>(data).map(|request| {
                    StoredAuthorizationRequest {
                        request,
                        interaction: AuthorizationInteractionState::default(),
                    }
                })
            })
            .map_err(|error| {
                AppError::from_code(AuthorizeErrorCode::DeserializeRequestFailed).with_source(error)
            })
    }

    pub async fn create_authorization_request(
        &self,
        request: &AuthorizationRequest,
    ) -> Result<Uuid, AppError> {
        let data = serde_json::to_value(StoredAuthorizationRequest {
            request: AuthorizationRequestData::from(request),
            interaction: AuthorizationInteractionState::default(),
        })
        .map_err(|error| {
            AppError::from_code(AuthorizeErrorCode::SerializeRequestFailed).with_source(error)
        })?;

        let record = self
            .client_authorization_repo
            .create(
                request.client_id,
                ClientAuthorizationType::AuthorizationRequest,
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

        Self::deserialize_stored_authorization_request(record.data)
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
        let stored = Self::deserialize_stored_authorization_request(record.data)?;
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
        self.record_authorization_selection(
            login.client_authorization_oid,
            session_oid,
            user_oid,
            protected_session_id,
            source,
        )
        .await
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
    ) -> Result<Url, AppError> {
        self.approve_authorization_request_with_protected_session_id(
            authorization_request_id,
            session_oid,
            user_oid,
            None,
            auth_time,
        )
        .await
    }

    pub async fn approve_authorization_request_with_protected_session_id(
        &self,
        authorization_request_id: Uuid,
        session_oid: SessionOid,
        user_oid: Uuid,
        protected_session_id: Option<String>,
        auth_time: Option<i64>,
    ) -> Result<Url, AppError> {
        let stored = self
            .load_stored_authorization_request(authorization_request_id)
            .await?;
        let request = stored.request;
        let protected_session_id = match stored.interaction.selected_protected_session_id {
            Some(protected_session_id) => {
                let stored_session_oid = self.decrypt_session_id(&protected_session_id).await?;
                if stored_session_oid != session_oid {
                    return Err(AppError::from_code(
                        AuthorizeErrorCode::StoredSessionIdInvalid,
                    ));
                }
                protected_session_id
            }
            None => match protected_session_id {
                Some(protected_session_id) => {
                    let stored_session_oid = self.decrypt_session_id(&protected_session_id).await?;
                    if stored_session_oid != session_oid {
                        return Err(AppError::from_code(
                            AuthorizeErrorCode::StoredSessionIdInvalid,
                        ));
                    }
                    protected_session_id
                }
                None => self.encrypt_session_id(session_oid).await?,
            },
        };

        let response_type = ResponseType::from_str(&request.response_type).map_err(|error| {
            AppError::from_code(AuthorizeErrorCode::ResponseTypeInvalid)
                .with_param("response_type", request.response_type.as_str())
                .with_source(error)
        })?;

        let redirect = if response_type.is_implicit() {
            self.approve_implicit_flow(
                &request,
                session_oid,
                &protected_session_id,
                user_oid,
                response_type,
                auth_time,
            )
            .await?
        } else if response_type.uses_front_channel_response() {
            self.approve_hybrid_flow(
                &request,
                session_oid,
                &protected_session_id,
                user_oid,
                response_type,
                auth_time,
            )
            .await?
        } else {
            self.approve_code_flow(
                &request,
                user_oid,
                session_oid,
                &protected_session_id,
                auth_time,
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
        user_oid: Uuid,
        session_oid: SessionOid,
        protected_session_id: &str,
        auth_time: Option<i64>,
    ) -> Result<Url, AppError> {
        let redirect_uri = Url::parse(&request.redirect_uri).map_err(|error| {
            AppError::from_code(AuthorizeErrorCode::StoredRedirectUriInvalid).with_source(error)
        })?;

        let (protected_code, _) = self
            .create_authorization_code(
                request,
                user_oid,
                session_oid,
                protected_session_id,
                auth_time,
            )
            .await?;

        let mut redirect = redirect_uri;
        redirect
            .query_pairs_mut()
            .append_pair("code", &protected_code)
            .append_pair("state", &request.state)
            .append_pair(
                "session_state",
                &session_state_for_authorize_response(request, protected_session_id)?,
            );

        Ok(redirect)
    }

    pub(super) async fn create_authorization_code(
        &self,
        request: &AuthorizationRequestData,
        user_oid: Uuid,
        session_oid: SessionOid,
        protected_session_id: &str,
        auth_time: Option<i64>,
    ) -> Result<(String, Uuid), AppError> {
        let record = self
            .client_authorization_repo
            .create(
                Uuid::parse_str(&request.client_id).map_err(|error| {
                    AppError::from_code(AuthorizeErrorCode::StoredClientIdInvalid)
                        .with_source(error)
                })?,
                ClientAuthorizationType::AuthorizationCode,
                serde_json::to_value(
                    identity_domain::client_authorization::AuthorizationCodeData {
                        scope: request.scope.clone(),
                        nonce: request.nonce.clone(),
                        code_challenge: request.code_challenge.clone(),
                        code_challenge_method: request.code_challenge_method.clone(),
                        user_oid: user_oid.to_string(),
                        session_oid,
                        protected_session_id: Some(protected_session_id.to_string()),
                        acr: request.acr_values.as_ref().and_then(|v| v.first().cloned()),
                        redirect_uri: request.redirect_uri.clone(),
                        auth_time,
                        claims: request
                            .claims
                            .as_ref()
                            .and_then(|c| serde_json::from_str(c).ok()),
                    },
                )
                .map_err(|error| {
                    AppError::from_code(AuthorizeErrorCode::SerializeCodeFailed).with_source(error)
                })?,
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

        let response_type = ResponseType::from_str(&request.response_type).map_err(|error| {
            AppError::from_code(AuthorizeErrorCode::ResponseTypeInvalid)
                .with_param("response_type", request.response_type.as_str())
                .with_source(error)
        })?;

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
        self.approve_authorization_request_with_protected_session_id(
            login.client_authorization_oid,
            session_oid,
            user_oid,
            protected_session_id,
            auth_time,
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
