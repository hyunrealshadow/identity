use super::*;

impl TokenService {
    pub async fn exchange_authorization_code(
        &self,
        params: AuthorizationCodeGrantParams,
    ) -> Result<TokenResponse, AppError> {
        if params.grant_type != "authorization_code" {
            return Err(AppError::from_code(TokenErrorCode::UnsupportedGrantType));
        }

        let client_id = params
            .client_id
            .as_deref()
            .ok_or_else(|| AppError::from_code(TokenErrorCode::ClientIdRequired))?;
        let authenticated_client_oid = self
            .authenticate_client(
                client_id,
                params.client_secret.as_deref(),
                params.client_assertion_type.as_deref(),
                params.client_assertion.as_deref(),
            )
            .await?;

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

        if record.revoked_at.is_some() || record.expires_at <= chrono::Utc::now() {
            return Err(AppError::from_code(TokenErrorCode::AuthCodeInvalid));
        }

        let data: AuthorizationCodeData =
            serde_json::from_value(record.data.clone()).map_err(|error| {
                AppError::from_code(TokenErrorCode::DeserializeCodeFailed).with_source(error)
            })?;

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
        let audience = params
            .client_id
            .clone()
            .unwrap_or_else(|| record.client_oid.to_string());
        let client_id_str = record.client_oid.to_string();
        let access_token = self.sign_access_token(
            &signing_key_id,
            &signing_key_pem,
            &signing_alg,
            &issuer,
            &audience,
            &client_id_str,
            &user_oid,
            &data.session_oid,
            &data.scope,
            data.claims.as_ref(),
        )?;
        let id_token = if data.scope.split_whitespace().any(|scope| scope == "openid") {
            Some(self.sign_id_token(
                &signing_key_id,
                &signing_key_pem,
                &signing_alg,
                &issuer,
                &audience,
                &user,
                data.nonce.as_deref(),
                data.auth_time,
                data.acr.as_deref(),
                &data.scope,
            )?)
        } else {
            None
        };
        let refresh_token = if data
            .scope
            .split_whitespace()
            .any(|scope| scope == "offline_access")
        {
            let refresh_token = self.sign_refresh_token(
                &signing_key_id,
                &signing_key_pem,
                &signing_alg,
                &issuer,
                &audience,
                &user_oid,
            )?;
            self.store_refresh_token(
                record.client_oid,
                &refresh_token,
                &data.scope,
                &data.user_oid,
                &data.session_oid,
                None,
            )
            .await?;
            Some(refresh_token)
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

        let client_id = params
            .client_id
            .as_deref()
            .ok_or_else(|| AppError::from_code(TokenErrorCode::ClientIdRequired))?;
        let authenticated_client_oid = self
            .authenticate_client(
                client_id,
                params.client_secret.as_deref(),
                params.client_assertion_type.as_deref(),
                params.client_assertion.as_deref(),
            )
            .await?;

        let refresh_record = self
            .client_authorization_repo
            .find_refresh_token_by_token(&params.refresh_token)
            .await
            .map_err(|error| {
                AppError::from_code(TokenErrorCode::RefreshTokenLookupFailed).with_source(error)
            })?
            .ok_or_else(|| AppError::from_code(TokenErrorCode::RefreshTokenNotFound))?;
        if refresh_record.revoked_at.is_some() || refresh_record.expires_at <= chrono::Utc::now() {
            return Err(AppError::from_code(TokenErrorCode::RefreshTokenInvalid));
        }
        let refresh_data: RefreshTokenData = serde_json::from_value(refresh_record.data.clone())
            .map_err(|error| {
                AppError::from_code(TokenErrorCode::DeserializeRefreshFailed).with_source(error)
            })?;
        let refresh_claims = self.verify_refresh_token(&params.refresh_token).await?;
        let subject = refresh_claims
            .subject()
            .ok_or_else(|| AppError::from_code(TokenErrorCode::RefreshTokenSubMissing))?
            .to_string();
        let token_use = refresh_claims
            .claim(JwtClaimNames::TOKEN_USE)
            .and_then(|value| value.as_str())
            .ok_or_else(|| AppError::from_code(TokenErrorCode::RefreshTokenUseMissing))?;
        if token_use != TokenUseValues::REFRESH_TOKEN {
            return Err(AppError::from_code(TokenErrorCode::RefreshTokenUseInvalid));
        }

        let audience_matches = refresh_claims
            .claim(JwtClaimNames::AUD)
            .and_then(|value| {
                value.as_str().map(|aud| aud == client_id).or_else(|| {
                    value.as_array().map(|items| {
                        items
                            .iter()
                            .filter_map(|item| item.as_str())
                            .any(|aud| aud == client_id)
                    })
                })
            })
            .unwrap_or(false);
        if !audience_matches
            || authenticated_client_oid.to_string() != client_id
            || refresh_record.client_oid != authenticated_client_oid
        {
            return Err(AppError::from_code(
                TokenErrorCode::RefreshTokenClientMismatch,
            ));
        }

        let user_oid = Uuid::parse_str(&subject).map_err(|error| {
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
        let access_token = self.sign_access_token(
            &signing_key_id,
            &signing_key_pem,
            &signing_alg,
            &issuer,
            client_id,
            client_id,
            &user_oid,
            &refresh_data.session_oid,
            &scope,
            None,
        )?;
        let id_token = Some(self.sign_id_token(
            &signing_key_id,
            &signing_key_pem,
            &signing_alg,
            &issuer,
            client_id,
            &user,
            None,
            None,
            None,
            &scope,
        )?);
        let refresh_token = Some(self.sign_refresh_token(
            &signing_key_id,
            &signing_key_pem,
            &signing_alg,
            &issuer,
            client_id,
            &user_oid,
        )?);
        self.client_authorization_repo
            .revoke(refresh_record.oid)
            .await
            .map_err(|error| {
                AppError::from_code(TokenErrorCode::RevokeRefreshFailed).with_source(error)
            })?;
        if let Some(refresh_token_value) = &refresh_token {
            self.store_refresh_token(
                authenticated_client_oid,
                refresh_token_value,
                &scope,
                &subject,
                &refresh_data.session_oid,
                Some(params.refresh_token.as_str()),
            )
            .await?;
        }

        Ok(TokenResponse {
            access_token,
            id_token,
            refresh_token,
            token_type: "Bearer".to_string(),
            expires_in: 3600,
            scope,
        })
    }
}
