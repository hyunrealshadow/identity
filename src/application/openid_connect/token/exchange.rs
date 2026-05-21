use super::signing::StoreRefreshTokenParams;
use super::*;
use identity_domain::auth::SessionOid;

impl TokenService {
    pub async fn exchange_authorization_code(
        &self,
        params: AuthorizationCodeGrantParams,
    ) -> Result<TokenResponse, AppError> {
        if params.grant_type != "authorization_code" {
            return Err(AppError::from_code(TokenErrorCode::UnsupportedGrantType));
        }

        let client_id = resolve_client_id(
            params.client_id,
            params.client_assertion_type.as_deref(),
            params.client_assertion.as_deref(),
        )?;
        let authenticated_client_oid = self
            .authenticate_client(
                &client_id,
                params.client_secret.as_deref(),
                params.client_assertion_type.as_deref(),
                params.client_assertion.as_deref(),
            )
            .await?;
        let authenticated_client = self
            .client_repo
            .find_by_oid(authenticated_client_oid)
            .await
            .map_err(|error| {
                AppError::from_code(TokenErrorCode::ClientLookupFailed).with_source(error)
            })?
            .ok_or_else(|| AppError::from_code(TokenErrorCode::ClientNotFound))?;

        let code_oid_bytes = self
            .data_protector
            .unprotect("authorization-code", &params.code)
            .await
            .map_err(|error| {
                AppError::from_code(TokenErrorCode::AuthCodeNotFound).with_source(error)
            })?;
        let code_oid = Uuid::from_slice(&code_oid_bytes).map_err(|error| {
            AppError::from_code(TokenErrorCode::AuthCodeNotFound).with_source(error)
        })?;

        let record = self
            .client_authorization_repo
            .find_by_oid(code_oid)
            .await
            .map_err(|error| {
                AppError::from_code(TokenErrorCode::CodeLookupFailed).with_source(error)
            })?
            .ok_or_else(|| AppError::from_code(TokenErrorCode::AuthCodeNotFound))?;

        if record.type_ != ClientAuthorizationType::AuthorizationCode {
            return Err(AppError::from_code(TokenErrorCode::AuthCodeNotFound));
        }

        if record.client_oid != authenticated_client_oid {
            return Err(AppError::from_code(TokenErrorCode::CodeClientMismatch));
        }

        if record.revoked_at.is_some() {
            self.client_authorization_repo
                .revoke_access_tokens_for_authorization_code(record.oid)
                .await
                .map_err(|error| {
                    AppError::from_code(TokenErrorCode::RevokeCodeFailed).with_source(error)
                })?;
            return Err(AppError::from_code(TokenErrorCode::AuthCodeInvalid));
        }

        if record.expires_at <= chrono::Utc::now() {
            return Err(AppError::from_code(TokenErrorCode::AuthCodeInvalid));
        }

        let data: AuthorizationCodeData =
            serde_json::from_value(record.data.clone()).map_err(|error| {
                AppError::from_code(TokenErrorCode::DeserializeCodeFailed).with_source(error)
            })?;
        let protected_session_id = self
            .protected_session_id(data.session_oid, data.protected_session_id.as_deref())
            .await?;

        let redirect_uri = params
            .redirect_uri
            .as_deref()
            .ok_or_else(|| AppError::from_code(TokenErrorCode::RedirectUriMismatch))?;
        if redirect_uri != data.redirect_uri {
            return Err(AppError::from_code(TokenErrorCode::RedirectUriMismatch));
        }

        let verifier = params.code_verifier.as_deref();

        verify_pkce(
            data.code_challenge.as_deref(),
            data.code_challenge_method.as_deref(),
            verifier,
        )?;

        let user_oid = Uuid::parse_str(&data.user_oid).map_err(|error| {
            AppError::from_code(TokenErrorCode::StoredUserOidInvalid).with_source(error)
        })?;
        let user = self
            .user_repo
            .find_by_oid(UserOid(user_oid))
            .await
            .map_err(|error| {
                AppError::from_code(TokenErrorCode::UserLookupFailed).with_source(error)
            })?
            .ok_or_else(|| AppError::from_code(TokenErrorCode::AuthCodeUserNotFound))?;

        let issuer = self.provider_service.issuer()?;
        let (signing_key_id, signing_key_pem, signing_alg) = self.load_signing_key().await?;
        let id_token_alg = resolve_id_token_alg(
            &signing_alg,
            authenticated_client
                .metadata()
                .id_token_signed_response_alg
                .as_deref(),
        );
        let audience = client_id.clone();
        let client_id_str = record.client_oid.to_string();
        let access_token_record = self
            .create_access_token_record(
                record.client_oid,
                &data.scope,
                &data.user_oid,
                data.session_oid,
                Some(&protected_session_id),
                Some(record.oid),
            )
            .await?;
        let access_token = self.sign_access_token(
            &access_token_record.oid.to_string(),
            &signing_key_id,
            &signing_key_pem,
            &signing_alg,
            &issuer,
            &audience,
            &client_id_str,
            &user_oid,
            &protected_session_id,
            &data.scope,
            data.claims.as_ref(),
        )?;
        let id_token = if data.scope.split_whitespace().any(|scope| scope == "openid") {
            let signed = self.sign_id_token(
                &signing_key_id,
                &signing_key_pem,
                &id_token_alg,
                &issuer,
                &audience,
                &authenticated_client,
                &user,
                data.nonce.as_deref(),
                data.auth_time,
                data.acr.as_deref(),
                Some(&access_token),
                Some(&protected_session_id),
                &data.scope,
            )?;
            let id_token = match authenticated_client
                .metadata()
                .id_token_encrypted_response_alg
                .as_deref()
            {
                Some(alg) => {
                    let enc = authenticated_client
                        .metadata()
                        .id_token_encrypted_response_enc
                        .as_deref()
                        .unwrap_or("A128CBC-HS256");
                    self.encrypt_token(&signed, &authenticated_client, alg, enc)
                        .await?
                }
                None => signed,
            };
            Some(id_token)
        } else {
            None
        };
        let refresh_token = if data
            .scope
            .split_whitespace()
            .any(|scope| scope == "offline_access")
        {
            Some(
                self.store_refresh_token(StoreRefreshTokenParams {
                    client_oid: record.client_oid,
                    scope: &data.scope,
                    user_oid: &data.user_oid,
                    session_oid: data.session_oid,
                    protected_session_id: Some(&protected_session_id),
                    auth_time: data.auth_time,
                    rotated_from: None,
                })
                .await?,
            )
        } else {
            None
        };

        self.client_authorization_repo
            .revoke(record.oid)
            .await
            .map_err(|error| {
                AppError::from_code(TokenErrorCode::RevokeCodeFailed).with_source(error)
            })?;

        Ok(TokenResponse {
            access_token,
            id_token,
            refresh_token,
            token_type: "Bearer".to_string(),
            expires_in: 3600,
            scope: data.scope,
        })
    }

    pub async fn exchange_refresh_token(
        &self,
        params: RefreshTokenGrantParams,
    ) -> Result<TokenResponse, AppError> {
        if params.grant_type != "refresh_token" {
            return Err(AppError::from_code(TokenErrorCode::UnsupportedGrantType));
        }

        let client_id = resolve_client_id(
            params.client_id,
            params.client_assertion_type.as_deref(),
            params.client_assertion.as_deref(),
        )?;
        let authenticated_client_oid = self
            .authenticate_client(
                &client_id,
                params.client_secret.as_deref(),
                params.client_assertion_type.as_deref(),
                params.client_assertion.as_deref(),
            )
            .await?;
        let authenticated_client = self
            .client_repo
            .find_by_oid(authenticated_client_oid)
            .await
            .map_err(|error| {
                AppError::from_code(TokenErrorCode::ClientLookupFailed).with_source(error)
            })?
            .ok_or_else(|| AppError::from_code(TokenErrorCode::ClientNotFound))?;

        let refresh_oid_bytes = self
            .data_protector
            .unprotect("refresh-token", &params.refresh_token)
            .await
            .map_err(|error| {
                AppError::from_code(TokenErrorCode::RefreshTokenNotFound).with_source(error)
            })?;
        let refresh_oid = Uuid::from_slice(&refresh_oid_bytes).map_err(|error| {
            AppError::from_code(TokenErrorCode::RefreshTokenNotFound).with_source(error)
        })?;

        let refresh_record = self
            .client_authorization_repo
            .find_by_oid(refresh_oid)
            .await
            .map_err(|error| {
                AppError::from_code(TokenErrorCode::RefreshTokenLookupFailed).with_source(error)
            })?
            .ok_or_else(|| AppError::from_code(TokenErrorCode::RefreshTokenNotFound))?;
        if refresh_record.type_ != ClientAuthorizationType::RefreshToken {
            return Err(AppError::from_code(TokenErrorCode::RefreshTokenNotFound));
        }
        if refresh_record.revoked_at.is_some() || refresh_record.expires_at <= chrono::Utc::now() {
            return Err(AppError::from_code(TokenErrorCode::RefreshTokenInvalid));
        }
        let refresh_data: RefreshTokenData = serde_json::from_value(refresh_record.data.clone())
            .map_err(|error| {
                AppError::from_code(TokenErrorCode::DeserializeRefreshFailed).with_source(error)
            })?;
        let protected_session_id = self
            .protected_session_id(
                refresh_data.session_oid,
                refresh_data.protected_session_id.as_deref(),
            )
            .await?;
        if authenticated_client_oid.to_string() != client_id
            || refresh_record.client_oid != authenticated_client_oid
        {
            return Err(AppError::from_code(
                TokenErrorCode::RefreshTokenClientMismatch,
            ));
        }

        let user_oid = Uuid::parse_str(&refresh_data.user_oid).map_err(|error| {
            AppError::from_code(TokenErrorCode::RefreshTokenSubInvalid).with_source(error)
        })?;
        let user = self
            .user_repo
            .find_by_oid(UserOid(user_oid))
            .await
            .map_err(|error| {
                AppError::from_code(TokenErrorCode::UserLookupFailed).with_source(error)
            })?
            .ok_or_else(|| AppError::from_code(TokenErrorCode::RefreshTokenUserNotFound))?;

        let issuer = self.provider_service.issuer()?;
        let (signing_key_id, signing_key_pem, signing_alg) = self.load_signing_key().await?;
        let scope = refresh_data.scope.clone();
        let access_token_record = self
            .create_access_token_record(
                authenticated_client_oid,
                &scope,
                &refresh_data.user_oid,
                refresh_data.session_oid,
                Some(&protected_session_id),
                None,
            )
            .await?;
        let access_token = self.sign_access_token(
            &access_token_record.oid.to_string(),
            &signing_key_id,
            &signing_key_pem,
            &signing_alg,
            &issuer,
            &client_id,
            &client_id,
            &user_oid,
            &protected_session_id,
            &scope,
            None,
        )?;
        let signed_id_token = self.sign_id_token(
            &signing_key_id,
            &signing_key_pem,
            &signing_alg,
            &issuer,
            &client_id,
            &authenticated_client,
            &user,
            None,
            refresh_data.auth_time,
            None,
            Some(&access_token),
            Some(&protected_session_id),
            &scope,
        )?;
        let id_token = Some(
            match authenticated_client
                .metadata()
                .id_token_encrypted_response_alg
                .as_deref()
            {
                Some(alg) => {
                    let enc = authenticated_client
                        .metadata()
                        .id_token_encrypted_response_enc
                        .as_deref()
                        .unwrap_or("A128CBC-HS256");
                    self.encrypt_token(&signed_id_token, &authenticated_client, alg, enc)
                        .await?
                }
                None => signed_id_token,
            },
        );
        self.client_authorization_repo
            .revoke(refresh_record.oid)
            .await
            .map_err(|error| {
                AppError::from_code(TokenErrorCode::RevokeRefreshFailed).with_source(error)
            })?;
        let rotated_from = refresh_record.oid.to_string();
        let refresh_token = Some(
            self.store_refresh_token(StoreRefreshTokenParams {
                client_oid: authenticated_client_oid,
                scope: &scope,
                user_oid: &refresh_data.user_oid,
                session_oid: refresh_data.session_oid,
                protected_session_id: Some(&protected_session_id),
                auth_time: refresh_data.auth_time,
                rotated_from: Some(rotated_from.as_str()),
            })
            .await?,
        );

        Ok(TokenResponse {
            access_token,
            id_token,
            refresh_token,
            token_type: "Bearer".to_string(),
            expires_in: 3600,
            scope,
        })
    }

    async fn protected_session_id(
        &self,
        session_oid: SessionOid,
        existing: Option<&str>,
    ) -> Result<String, AppError> {
        if let Some(existing) = existing {
            return Ok(existing.to_string());
        }

        self.data_protector
            .protect("session-id", Uuid::from(session_oid).as_bytes())
            .await
            .map_err(|error| {
                AppError::from_code(TokenErrorCode::DeserializeCodeFailed).with_source(error)
            })
    }
}

fn resolve_client_id(
    client_id: Option<String>,
    client_assertion_type: Option<&str>,
    client_assertion: Option<&str>,
) -> Result<String, AppError> {
    if let Some(client_id) = client_id {
        return Ok(client_id);
    }

    if client_assertion_type == Some("urn:ietf:params:oauth:client-assertion-type:jwt-bearer")
        && let Some(assertion) = client_assertion
    {
        return client_id_from_assertion(assertion);
    }

    Err(AppError::from_code(TokenErrorCode::ClientIdRequired))
}

pub(crate) fn resolve_id_token_alg(fallback: &str, client_alg: Option<&str>) -> String {
    #[cfg(feature = "oidc-conformance")]
    if client_alg == Some("none") {
        return "none".to_owned();
    }

    #[cfg(not(feature = "oidc-conformance"))]
    if client_alg == Some("none") {
        return fallback.to_owned();
    }

    fallback.to_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn unsigned_assertion(payload: serde_json::Value) -> String {
        let header = URL_SAFE_NO_PAD.encode(r#"{"alg":"none"}"#);
        let payload = URL_SAFE_NO_PAD.encode(payload.to_string());
        format!("{header}.{payload}.")
    }

    #[test]
    fn resolve_client_id_uses_request_client_id_first() {
        let assertion = unsigned_assertion(serde_json::json!({"sub": "assertion-client"}));

        let client_id = resolve_client_id(
            Some("request-client".to_owned()),
            Some("urn:ietf:params:oauth:client-assertion-type:jwt-bearer"),
            Some(&assertion),
        )
        .unwrap();

        assert_eq!(client_id, "request-client");
    }

    #[test]
    fn resolve_client_id_extracts_jwt_bearer_assertion_subject() {
        let assertion = unsigned_assertion(serde_json::json!({
            "iss": "assertion-client",
            "sub": "assertion-client"
        }));

        let client_id = resolve_client_id(
            None,
            Some("urn:ietf:params:oauth:client-assertion-type:jwt-bearer"),
            Some(&assertion),
        )
        .unwrap();

        assert_eq!(client_id, "assertion-client");
    }
}
