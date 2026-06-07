use super::flow::session_state_for_authorize_response;
use super::signing::{SignImplicitAccessTokenInput, SignImplicitIdTokenInput};
use super::*;
use crate::openid_connect::token::resolve_id_token_alg;
use identity_domain::auth::SessionOid;
use std::fmt::Write;
use uuid::Uuid;

struct CreateFrontChannelAccessTokenInput<'a> {
    client_id: Uuid,
    user_oid: Uuid,
    session_oid: SessionOid,
    protected_session_id: &'a str,
    request: &'a AuthorizationRequestData,
    authorization_code_oid: Option<Uuid>,
    signing_key_id: &'a str,
    signing_key_pem: &'a str,
    signing_alg: &'a str,
    issuer: &'a Url,
    audience: &'a str,
    claims: Option<&'a serde_json::Value>,
}

impl AuthorizeService {
    pub(super) async fn approve_implicit_flow(
        &self,
        request: &AuthorizationRequestData,
        session_oid: SessionOid,
        protected_session_id: &str,
        user_oid: Uuid,
        response_type: ResponseType,
        auth_time: Option<i64>,
    ) -> Result<Url, AppError> {
        let nonce = request
            .nonce
            .as_deref()
            .ok_or_else(|| AppError::from_code(AuthorizeErrorCode::ImplicitNonceRequired))?;

        let redirect_uri = Url::parse(&request.redirect_uri).map_err(|error| {
            AppError::from_code(AuthorizeErrorCode::StoredRedirectUriInvalid).with_source(error)
        })?;

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

        let user_oid_obj = UserOid(user_oid);
        let user = self
            .user_repo
            .find_by_oid(user_oid_obj)
            .await
            .map_err(|error| {
                AppError::from_code(AuthorizeErrorCode::ClientLookupFailed).with_source(error)
            })?
            .ok_or_else(|| AppError::from_code(AuthorizeErrorCode::ClientNotFound))?;

        let issuer = self.provider_service.issuer()?;
        let (signing_key_id, signing_key_pem, signing_alg) = self.load_signing_key_impl().await?;
        let id_token_alg = resolve_id_token_alg(
            &signing_alg,
            client.metadata().id_token_signed_response_alg.as_deref(),
        );
        let audience = client_id.to_string();
        let auth_time_val = auth_time.unwrap_or_else(|| chrono::Utc::now().timestamp());
        let scope = ScopeSet::parse(&request.scope).map_err(|error| {
            AppError::from_code(AuthorizeErrorCode::ScopeInvalid).with_source(error)
        })?;
        let claims = request
            .claims
            .as_ref()
            .and_then(|claims| serde_json::from_str::<serde_json::Value>(claims).ok());

        let include_access_token = response_type.includes_access_token();

        let (access_token, expires_in) = if include_access_token {
            (
                Some(
                    self.create_front_channel_access_token(CreateFrontChannelAccessTokenInput {
                        client_id,
                        user_oid,
                        session_oid,
                        protected_session_id,
                        request,
                        authorization_code_oid: None,
                        signing_key_id: &signing_key_id,
                        signing_key_pem: &signing_key_pem,
                        signing_alg: &signing_alg,
                        issuer: &issuer,
                        audience: &audience,
                        claims: claims.as_ref(),
                    })
                    .await?,
                ),
                3600u64,
            )
        } else {
            (None, 0)
        };

        let signed_id_token = self.sign_implicit_id_token(SignImplicitIdTokenInput {
            key_id: &signing_key_id,
            private_key_pem: &signing_key_pem,
            alg: &id_token_alg,
            issuer: &issuer,
            audience: &audience,
            user: &user,
            nonce,
            auth_time: auth_time_val,
            acr: request
                .acr_values
                .as_ref()
                .and_then(|v| v.first().map(String::as_str)),
            access_token: access_token.as_deref(),
            code: None,
            protected_session_id: Some(protected_session_id),
            scope: &scope,
            claims_request: claims.as_ref(),
        })?;

        let id_token = match client.metadata().id_token_encrypted_response_alg.as_deref() {
            Some(alg) => {
                let enc = client
                    .metadata()
                    .id_token_encrypted_response_enc
                    .as_deref()
                    .unwrap_or("A128CBC-HS256");
                self.encrypt_id_token(&signed_id_token, &client, alg, enc)
                    .await?
            }
            None => signed_id_token,
        };

        let mut fragment = format!("id_token={id_token}");
        if let Some(ref at) = access_token {
            write!(fragment, "&access_token={at}").unwrap();
            write!(fragment, "&token_type=Bearer").unwrap();
            write!(fragment, "&expires_in={expires_in}").unwrap();
            write!(fragment, "&scope={}", urlencoding(&request.scope)).unwrap();
        }
        write!(fragment, "&state={}", urlencoding(&request.state)).unwrap();
        write!(
            fragment,
            "&session_state={}",
            urlencoding(&session_state_for_authorize_response(
                request,
                protected_session_id
            )?)
        )
        .unwrap();

        let mut url = redirect_uri;
        url.set_fragment(Some(&fragment));

        Ok(url)
    }

    pub(super) async fn approve_hybrid_flow(
        &self,
        request: &AuthorizationRequestData,
        session_oid: SessionOid,
        protected_session_id: &str,
        user_oid: Uuid,
        response_type: ResponseType,
        auth_time: Option<i64>,
    ) -> Result<Url, AppError> {
        let redirect_uri = Url::parse(&request.redirect_uri).map_err(|error| {
            AppError::from_code(AuthorizeErrorCode::StoredRedirectUriInvalid).with_source(error)
        })?;
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
        let (code, authorization_code_oid) = self
            .create_authorization_code(
                request,
                user_oid,
                session_oid,
                protected_session_id,
                auth_time,
            )
            .await?;

        let issuer = self.provider_service.issuer()?;
        let (signing_key_id, signing_key_pem, signing_alg) = self.load_signing_key_impl().await?;
        let id_token_alg = resolve_id_token_alg(
            &signing_alg,
            client.metadata().id_token_signed_response_alg.as_deref(),
        );
        let audience = client_id.to_string();
        let scope = ScopeSet::parse(&request.scope).map_err(|error| {
            AppError::from_code(AuthorizeErrorCode::ScopeInvalid).with_source(error)
        })?;
        let claims = request
            .claims
            .as_ref()
            .and_then(|claims| serde_json::from_str::<serde_json::Value>(claims).ok());

        let access_token = if response_type.includes_access_token() {
            Some(
                self.create_front_channel_access_token(CreateFrontChannelAccessTokenInput {
                    client_id,
                    user_oid,
                    session_oid,
                    protected_session_id,
                    request,
                    authorization_code_oid: Some(authorization_code_oid),
                    signing_key_id: &signing_key_id,
                    signing_key_pem: &signing_key_pem,
                    signing_alg: &signing_alg,
                    issuer: &issuer,
                    audience: &audience,
                    claims: claims.as_ref(),
                })
                .await?,
            )
        } else {
            None
        };

        let id_token = if response_type.includes_id_token() {
            let nonce = request
                .nonce
                .as_deref()
                .ok_or_else(|| AppError::from_code(AuthorizeErrorCode::ImplicitNonceRequired))?;
            let user = self
                .user_repo
                .find_by_oid(UserOid(user_oid))
                .await
                .map_err(|error| {
                    AppError::from_code(AuthorizeErrorCode::ClientLookupFailed).with_source(error)
                })?
                .ok_or_else(|| AppError::from_code(AuthorizeErrorCode::ClientNotFound))?;
            let signed_id_token = self.sign_implicit_id_token(SignImplicitIdTokenInput {
                key_id: &signing_key_id,
                private_key_pem: &signing_key_pem,
                alg: &id_token_alg,
                issuer: &issuer,
                audience: &audience,
                user: &user,
                nonce,
                auth_time: auth_time.unwrap_or_else(|| chrono::Utc::now().timestamp()),
                acr: request
                    .acr_values
                    .as_ref()
                    .and_then(|v| v.first().map(String::as_str)),
                access_token: access_token.as_deref(),
                code: Some(&code),
                protected_session_id: Some(protected_session_id),
                scope: &scope,
                claims_request: claims.as_ref(),
            })?;
            Some(
                match client.metadata().id_token_encrypted_response_alg.as_deref() {
                    Some(alg) => {
                        let enc = client
                            .metadata()
                            .id_token_encrypted_response_enc
                            .as_deref()
                            .unwrap_or("A128CBC-HS256");
                        self.encrypt_id_token(&signed_id_token, &client, alg, enc)
                            .await?
                    }
                    None => signed_id_token,
                },
            )
        } else {
            None
        };

        let mut fragment = format!("code={}", urlencoding(&code));
        if let Some(ref id_token) = id_token {
            write!(fragment, "&id_token={}", urlencoding(id_token)).unwrap();
        }
        if let Some(ref access_token) = access_token {
            write!(fragment, "&access_token={}", urlencoding(access_token)).unwrap();
            write!(fragment, "&token_type=Bearer").unwrap();
            write!(fragment, "&expires_in=3600").unwrap();
            write!(fragment, "&scope={}", urlencoding(&request.scope)).unwrap();
        }
        write!(fragment, "&state={}", urlencoding(&request.state)).unwrap();
        write!(
            fragment,
            "&session_state={}",
            urlencoding(&session_state_for_authorize_response(
                request,
                protected_session_id
            )?)
        )
        .unwrap();

        let mut url = redirect_uri;
        url.set_fragment(Some(&fragment));
        Ok(url)
    }

    async fn create_front_channel_access_token(
        &self,
        input: CreateFrontChannelAccessTokenInput<'_>,
    ) -> Result<String, AppError> {
        let access_token_record = self
            .client_authorization_repo
            .create(
                input.client_id,
                ClientAuthorizationType::AccessToken,
                serde_json::to_value(identity_domain::client_authorization::AccessTokenData {
                    scope: input.request.scope.clone(),
                    user_oid: input.user_oid.to_string(),
                    session_oid: input.session_oid,
                    protected_session_id: Some(input.protected_session_id.to_string()),
                    authorization_code_oid: input.authorization_code_oid.map(|oid| oid.to_string()),
                })
                .map_err(|error| {
                    AppError::from_code(AuthorizeErrorCode::SerializeCodeFailed).with_source(error)
                })?,
                chrono::Utc::now() + chrono::Duration::hours(1),
            )
            .await
            .map_err(|error| {
                AppError::from_code(AuthorizeErrorCode::StoreCodeFailed).with_source(error)
            })?;

        self.sign_implicit_access_token(SignImplicitAccessTokenInput {
            key_id: input.signing_key_id,
            private_key_pem: input.signing_key_pem,
            alg: input.signing_alg,
            issuer: input.issuer,
            audience: input.audience,
            client_id: input.audience,
            user_oid: &input.user_oid.to_string(),
            protected_session_id: input.protected_session_id,
            scope: &input.request.scope,
            token_id: &access_token_record.oid.to_string(),
            claims: input.claims,
        })
    }
}

fn urlencoding(s: &str) -> String {
    let mut result = String::new();
    for &b in s.as_bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                result.push(b as char);
            }
            b' ' => result.push_str("%20"),
            _ => {
                use std::fmt::Write;
                write!(result, "%{:02X}", b).unwrap();
            }
        }
    }
    result
}
