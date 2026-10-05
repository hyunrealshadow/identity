use super::flow::{AuthorizationCodeContext, session_state_for_authorize_response};
use super::signing::{SignImplicitAccessTokenInput, SignImplicitIdTokenInput};
use super::*;
use crate::error::codes::common::CommonErrorCode;
use chrono::Duration;
use chrono::Utc;
use identity_domain::auth::SessionOid;
use identity_domain::client_authorization::ClientAuthenticationMode;
use identity_domain::client_authorization::{AccessTokenData, ClientAuthorizationData};
use identity_domain::openid_connect::API_RESOURCE;
use identity_domain::openid_connect::TokenEndpointAuthMethod;
use url::form_urlencoded::Serializer;
use uuid::Uuid;

fn front_channel_token_mode(client: &OpenIdConnectClient) -> ClientAuthenticationMode {
    if client
        .metadata()
        .allows_token_endpoint_auth_method(TokenEndpointAuthMethod::None)
    {
        ClientAuthenticationMode::Public
    } else {
        ClientAuthenticationMode::Confidential
    }
}

#[derive(Clone, Copy)]
pub(super) struct AuthenticationContext<'a> {
    pub auth_time: Option<i64>,
    pub acr: Option<&'a str>,
    pub amr: &'a [String],
}

impl AuthorizeService {
    pub(super) async fn approve_implicit_flow(
        &self,
        request: &AuthorizationRequestData,
        session_oid: SessionOid,
        protected_session_id: &str,
        user_oid: Uuid,
        response_type: ResponseType,
        authentication: AuthenticationContext<'_>,
    ) -> Result<Url, AppError> {
        let nonce = request
            .nonce
            .as_deref()
            .ok_or_else(|| AppError::from_code(AuthorizeErrorCode::ImplicitNonceRequired))?;

        let redirect_uri = Url::parse(&request.redirect_uri).map_err(AppError::map_source(
            AuthorizeErrorCode::StoredRedirectUriInvalid,
        ))?;

        let client_id = Uuid::parse_str(&request.client_id).map_err(AppError::map_source(
            AuthorizeErrorCode::StoredClientIdInvalid,
        ))?;

        let client = self
            .client_repo
            .find_by_oid(client_id)
            .await
            .map_err(AppError::map_source(AuthorizeErrorCode::ClientLookupFailed))?
            .ok_or_else(|| AppError::from_code(AuthorizeErrorCode::ClientNotFound))?;
        if client.metadata().require_auth_time == Some(true) && authentication.auth_time.is_none() {
            return Err(AppError::from_code(AuthorizeErrorCode::SerializeCodeFailed));
        }

        let user_oid_obj = UserOid(user_oid);
        let user = self
            .user_repo
            .find_by_oid(user_oid_obj)
            .await
            .map_err(AppError::map_source(AuthorizeErrorCode::ClientLookupFailed))?
            .ok_or_else(|| AppError::from_code(AuthorizeErrorCode::ClientNotFound))?;

        let issuer = self.provider_service.issuer()?;
        let (signing_key_id, signing_key_pem, signing_alg) = self.load_signing_key_impl().await?;
        let audience = client_id.to_string();
        let auth_time_val = authentication
            .auth_time
            .unwrap_or_else(|| Utc::now().timestamp());
        let scope = ScopeSet::parse(&request.scope)
            .map_err(AppError::map_source(AuthorizeErrorCode::ScopeInvalid))?;
        let access_token_audience = if scope.has_api_scopes() {
            API_RESOURCE
        } else {
            audience.as_str()
        };
        let claims = request
            .claims
            .as_deref()
            .map(Self::parse_claims_request)
            .transpose()?;

        let access_token = if response_type.includes_access_token() {
            let (token_oid, resources) = self
                .create_front_channel_access_token_record(
                    client_id,
                    &request.resources,
                    AccessTokenData {
                        scope: request.scope.clone(),
                        user_oid: user_oid.to_string(),
                        session_oid: Some(session_oid),
                        protected_session_id: Some(protected_session_id.to_owned()),
                        authorization_code_oid: None,
                        refresh_token_oid: None,
                        device_authorization_oid: None,
                        client_authentication_mode: Some(front_channel_token_mode(&client)),
                    },
                )
                .await?;
            Some(
                self.sign_implicit_access_token(SignImplicitAccessTokenInput {
                    resources: &resources,
                    key_id: &signing_key_id,
                    private_key_pem: &signing_key_pem,
                    alg: signing_alg,
                    issuer: &issuer,
                    audience: access_token_audience,
                    client_id: &audience,
                    user_oid: &user_oid.to_string(),
                    protected_session_id,
                    scope: &request.scope,
                    token_id: &token_oid.to_string(),
                    claims: claims.as_ref(),
                    auth_time: auth_time_val,
                    acr: authentication.acr,
                    amr: authentication.amr,
                })?,
            )
        } else {
            None
        };

        let expires_in = if access_token.is_some() { 3600u64 } else { 0 };

        let (id_key_id, id_key_pem, id_token_alg) = self
            .load_id_token_signing_key_impl(
                client.metadata().id_token_signed_response_algs.as_deref(),
            )
            .await?;
        let signed_id_token = self.sign_implicit_id_token(SignImplicitIdTokenInput {
            key_id: &id_key_id,
            private_key_pem: &id_key_pem,
            alg: id_token_alg,
            issuer: &issuer,
            audience: &audience,
            user: &user,
            client: &client,
            nonce,
            auth_time: auth_time_val,
            acr: authentication.acr,
            amr: authentication.amr,
            access_token: access_token.as_deref(),
            code: None,
            protected_session_id: Some(protected_session_id),
            scope: &scope,
            claims_request: claims.as_ref(),
        })?;

        let id_token = self
            .encrypt_id_token_for_client(&signed_id_token, &client)
            .await?;

        let mut fragment = Serializer::new(String::new());
        fragment.append_pair("id_token", &id_token);
        if let Some(ref at) = access_token {
            fragment.append_pair("access_token", at);
            fragment.append_pair("token_type", "Bearer");
            fragment.append_pair("expires_in", &expires_in.to_string());
            fragment.append_pair("scope", &request.scope);
        }
        fragment.append_pair("state", &request.state);
        fragment.append_pair("iss", issuer.as_str());
        fragment.append_pair(
            "session_state",
            &session_state_for_authorize_response(request, protected_session_id)?,
        );

        let mut url = redirect_uri;
        url.set_fragment(Some(&fragment.finish()));

        Ok(url)
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) async fn approve_hybrid_flow(
        &self,
        request: &AuthorizationRequestData,
        authorization_request_id: Uuid,
        session_oid: SessionOid,
        protected_session_id: &str,
        user_oid: Uuid,
        response_type: ResponseType,
        authentication: AuthenticationContext<'_>,
    ) -> Result<Url, AppError> {
        let redirect_uri = Url::parse(&request.redirect_uri).map_err(AppError::map_source(
            AuthorizeErrorCode::StoredRedirectUriInvalid,
        ))?;
        let client_id = Uuid::parse_str(&request.client_id).map_err(AppError::map_source(
            AuthorizeErrorCode::StoredClientIdInvalid,
        ))?;
        let client = self
            .client_repo
            .find_by_oid(client_id)
            .await
            .map_err(AppError::map_source(AuthorizeErrorCode::ClientLookupFailed))?
            .ok_or_else(|| AppError::from_code(AuthorizeErrorCode::ClientNotFound))?;
        if response_type.includes_id_token()
            && client.metadata().require_auth_time == Some(true)
            && authentication.auth_time.is_none()
        {
            return Err(AppError::from_code(AuthorizeErrorCode::SerializeCodeFailed));
        }
        let (code, authorization_code_oid) = self
            .create_authorization_code(
                request,
                AuthorizationCodeContext {
                    authorization_request_id,
                    user_oid,
                    session_oid,
                    protected_session_id,
                    authentication,
                },
            )
            .await?;

        let issuer = self.provider_service.issuer()?;
        let (signing_key_id, signing_key_pem, signing_alg) = self.load_signing_key_impl().await?;
        let audience = client_id.to_string();
        let scope = ScopeSet::parse(&request.scope)
            .map_err(AppError::map_source(AuthorizeErrorCode::ScopeInvalid))?;
        let access_token_audience = if scope.has_api_scopes() {
            API_RESOURCE
        } else {
            audience.as_str()
        };
        let claims = request
            .claims
            .as_deref()
            .map(Self::parse_claims_request)
            .transpose()?;

        let access_token = if response_type.includes_access_token() {
            let auth_time_val = authentication
                .auth_time
                .unwrap_or_else(|| Utc::now().timestamp());
            let (token_oid, resources) = self
                .create_front_channel_access_token_record(
                    client_id,
                    &request.resources,
                    AccessTokenData {
                        scope: request.scope.clone(),
                        user_oid: user_oid.to_string(),
                        session_oid: Some(session_oid),
                        protected_session_id: Some(protected_session_id.to_owned()),
                        authorization_code_oid: Some(authorization_code_oid.to_string()),
                        refresh_token_oid: None,
                        device_authorization_oid: None,
                        client_authentication_mode: Some(front_channel_token_mode(&client)),
                    },
                )
                .await?;
            Some(
                self.sign_implicit_access_token(SignImplicitAccessTokenInput {
                    resources: &resources,
                    key_id: &signing_key_id,
                    private_key_pem: &signing_key_pem,
                    alg: signing_alg,
                    issuer: &issuer,
                    audience: access_token_audience,
                    client_id: &audience,
                    user_oid: &user_oid.to_string(),
                    protected_session_id,
                    scope: &request.scope,
                    token_id: &token_oid.to_string(),
                    claims: claims.as_ref(),
                    auth_time: auth_time_val,
                    acr: authentication.acr,
                    amr: authentication.amr,
                })?,
            )
        } else {
            None
        };

        let id_token = if response_type.includes_id_token() {
            let (id_key_id, id_key_pem, id_token_alg) = self
                .load_id_token_signing_key_impl(
                    client.metadata().id_token_signed_response_algs.as_deref(),
                )
                .await?;
            let nonce = request
                .nonce
                .as_deref()
                .ok_or_else(|| AppError::from_code(AuthorizeErrorCode::ImplicitNonceRequired))?;
            let user = self
                .user_repo
                .find_by_oid(UserOid(user_oid))
                .await
                .map_err(AppError::map_source(AuthorizeErrorCode::ClientLookupFailed))?
                .ok_or_else(|| AppError::from_code(AuthorizeErrorCode::ClientNotFound))?;
            let signed_id_token = self.sign_implicit_id_token(SignImplicitIdTokenInput {
                key_id: &id_key_id,
                private_key_pem: &id_key_pem,
                alg: id_token_alg,
                issuer: &issuer,
                audience: &audience,
                user: &user,
                client: &client,
                nonce,
                auth_time: authentication
                    .auth_time
                    .unwrap_or_else(|| Utc::now().timestamp()),
                acr: authentication.acr,
                amr: authentication.amr,
                access_token: access_token.as_deref(),
                code: Some(&code),
                protected_session_id: Some(protected_session_id),
                scope: &scope,
                claims_request: claims.as_ref(),
            })?;
            Some(
                self.encrypt_id_token_for_client(&signed_id_token, &client)
                    .await?,
            )
        } else {
            None
        };

        let mut fragment = Serializer::new(String::new());
        fragment.append_pair("code", &code);
        if let Some(ref id_token) = id_token {
            fragment.append_pair("id_token", id_token);
        }
        if let Some(ref access_token) = access_token {
            fragment.append_pair("access_token", access_token);
            fragment.append_pair("token_type", "Bearer");
            fragment.append_pair("expires_in", "3600");
            fragment.append_pair("scope", &request.scope);
        }
        fragment.append_pair("state", &request.state);
        fragment.append_pair("iss", issuer.as_str());
        fragment.append_pair(
            "session_state",
            &session_state_for_authorize_response(request, protected_session_id)?,
        );

        let mut url = redirect_uri;
        url.set_fragment(Some(&fragment.finish()));
        Ok(url)
    }

    async fn create_front_channel_access_token_record(
        &self,
        client_id: Uuid,
        resources: &[String],
        data: AccessTokenData,
    ) -> Result<(Uuid, Vec<String>), AppError> {
        let selection = self
            .provider_service
            .select_resources(resources, resources, &data.scope)
            .await?;
        if selection.scope != data.scope {
            return Err(AppError::from_code(CommonErrorCode::InvalidTarget));
        }
        let record = self
            .client_authorization_repo
            .create(
                client_id,
                ClientAuthorizationData::AccessToken(data),
                Utc::now() + Duration::hours(1),
            )
            .await
            .map_err(AppError::map_source(AuthorizeErrorCode::StoreCodeFailed))?;
        Ok((record.oid, selection.resources))
    }
}
