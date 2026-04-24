use super::*;

impl AuthorizeService {
    pub async fn create_authorization_request(
        &self,
        request: &AuthorizationRequest,
    ) -> Result<Uuid, AppError> {
        let data =
            serde_json::to_value(AuthorizationRequestData::from(request)).map_err(|error| {
                AppError::from_code(AuthorizeErrorCode::SerializeRequestFailed).with_source(error)
            })?;

        let record = self
            .client_request_repo
            .create(
                request.client_id,
                ClientRequestType::AuthorizationRequest,
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
        let record = self
            .client_request_repo
            .find_by_oid(authorization_request_id)
            .await
            .map_err(|error| {
                AppError::from_code(AuthorizeErrorCode::LoadRequestFailed).with_source(error)
            })?
            .ok_or_else(|| AppError::from_code(AuthorizeErrorCode::AuthzRequestNotFound))?;

        if record.type_ != ClientRequestType::AuthorizationRequest {
            return Err(AppError::from_code(
                AuthorizeErrorCode::AuthzRequestTypeMismatch,
            ));
        }

        serde_json::from_value::<AuthorizationRequestData>(record.data).map_err(|error| {
            AppError::from_code(AuthorizeErrorCode::DeserializeRequestFailed).with_source(error)
        })
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
            crate::domain::auth::model::Login,
            AuthorizationRequestData,
            OpenIdConnectClient,
        ),
        AppError,
    > {
        let login = self.load_login_by_protected_id(protected_login_oid).await?;
        let (request, client) = self.load_consent_context(login.client_request_oid).await?;
        Ok((login, request, client))
    }

    pub async fn load_login_by_protected_id(
        &self,
        protected_login_id: &str,
    ) -> Result<crate::domain::auth::model::Login, AppError> {
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
        session_oid: Uuid,
        user_oid: Uuid,
        auth_time: Option<i64>,
    ) -> Result<Url, AppError> {
        let request = self
            .load_authorization_request(authorization_request_id)
            .await?;
        let redirect_uri = Url::parse(&request.redirect_uri).map_err(|error| {
            AppError::from_code(AuthorizeErrorCode::StoredRedirectUriInvalid).with_source(error)
        })?;

        let record = self
            .client_request_repo
            .create(
                Uuid::parse_str(&request.client_id).map_err(|error| {
                    AppError::from_code(AuthorizeErrorCode::StoredClientIdInvalid)
                        .with_source(error)
                })?,
                ClientRequestType::AuthorizationCode,
                serde_json::to_value(crate::domain::client_request::AuthorizationCodeData {
                    scope: request.scope.clone(),
                    nonce: request.nonce.clone(),
                    code_challenge: request.code_challenge.clone(),
                    code_challenge_method: request.code_challenge_method.clone(),
                    user_oid: user_oid.to_string(),
                    session_oid: session_oid.to_string(),
                    acr: request.acr_values.as_ref().and_then(|v| v.first().cloned()),
                    redirect_uri: request.redirect_uri.clone(),
                    auth_time,
                    claims: request
                        .claims
                        .as_ref()
                        .and_then(|c| serde_json::from_str(c).ok()),
                })
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

        let mut redirect = redirect_uri;
        redirect
            .query_pairs_mut()
            .append_pair("code", &protected_code)
            .append_pair("state", &request.state);

        Ok(redirect)
    }

    pub async fn approve_authorization_request_by_login(
        &self,
        protected_login_oid: &str,
        session_oid: Uuid,
        user_oid: Uuid,
        auth_time: Option<i64>,
    ) -> Result<Url, AppError> {
        let login = self.load_login_by_protected_id(protected_login_oid).await?;
        self.approve_authorization_request(
            login.client_request_oid,
            session_oid,
            user_oid,
            auth_time,
        )
        .await
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
        Ok(OAuthErrorResponse::new(OAuthErrorCode::AccessDenied)
            .with_state(request.state)
            .to_redirect_url(&redirect_uri))
    }

    pub async fn deny_authorization_request_by_login(
        &self,
        protected_login_oid: &str,
    ) -> Result<Url, AppError> {
        let login = self.load_login_by_protected_id(protected_login_oid).await?;
        self.deny_authorization_request(login.client_request_oid)
            .await
    }
}
