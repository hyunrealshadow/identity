use super::signing::StoreRefreshTokenParams;
use super::signing::{SignAccessTokenInput, SignIdTokenInput};
use super::*;
use identity_domain::auth::SessionOid;

impl TokenService {
    pub async fn exchange_authorization_code(
        &self,
        params: AuthorizationCodeGrantParams,
    ) -> Result<TokenResponse, AppError> {
        let client_id = resolve_client_id(
            params.client_id,
            params.client_assertion_type,
            params.client_assertion.as_deref(),
        )?;
        let authenticated_client_oid = self
            .authenticate_client(
                &client_id,
                params.client_secret.as_deref(),
                params.client_assertion_type,
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

        let now = chrono::Utc::now();
        if record.revoked_at.is_some() {
            self.client_authorization_repo
                .revoke_access_tokens_for_authorization_code(record.oid)
                .await
                .map_err(|error| {
                    AppError::from_code(TokenErrorCode::RevokeCodeFailed).with_source(error)
                })?;
            return Err(AppError::from_code(TokenErrorCode::AuthCodeInvalid));
        }

        if record.expires_at <= now {
            return Err(AppError::from_code(TokenErrorCode::AuthCodeInvalid));
        }

        let data = match record.data {
            ClientAuthorizationData::AuthorizationCode(data) => data,
            _ => return Err(AppError::from_code(TokenErrorCode::DeserializeCodeFailed)),
        };
        let (session_acr, session_amr) = if let Some(session_repo) = &self.session_repo {
            let session = session_repo
                .find_by_oid(data.session_oid)
                .await
                .map_err(|error| {
                    AppError::from_code(TokenErrorCode::AuthCodeInvalid).with_source(error)
                })?
                .ok_or_else(|| AppError::from_code(TokenErrorCode::AuthCodeInvalid))?;
            let active = session.status == crate::domain::auth::SessionStatus::ACTIVE
                && session.revoked_at.is_none()
                && session.expires_at.is_none_or(|expires_at| expires_at > now)
                && session.user_oid.to_string() == data.user_oid;
            if !active {
                return Err(AppError::from_code(TokenErrorCode::AuthCodeInvalid));
            }
            (session.effective_acr(now).map(str::to_owned), session.amr)
        } else {
            (data.acr.clone(), data.amr.clone())
        };
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

        if authenticated_client
            .metadata()
            .settings
            .allow_public_client_flow
            && (data.code_challenge.as_deref().is_none_or(str::is_empty)
                || data.code_challenge_method
                    != Some(identity_domain::openid_connect::CodeChallengeMethod::S256))
        {
            return Err(AppError::from_code(TokenErrorCode::PkceMethodUnsupported)
                .with_param("code_challenge_method", "S256 required for public client"));
        }

        verify_pkce(
            data.code_challenge.as_deref(),
            data.code_challenge_method,
            verifier,
        )?;

        let claimed = self
            .client_authorization_repo
            .revoke_if_active(record.oid, ClientAuthorizationType::AuthorizationCode, now)
            .await
            .map_err(|error| {
                AppError::from_code(TokenErrorCode::RevokeCodeFailed).with_source(error)
            })?;
        if !claimed {
            self.client_authorization_repo
                .revoke_access_tokens_for_authorization_code(record.oid)
                .await
                .map_err(|error| {
                    AppError::from_code(TokenErrorCode::RevokeCodeFailed).with_source(error)
                })?;
            return Err(AppError::from_code(TokenErrorCode::AuthCodeInvalid));
        }

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
            signing_alg,
            authenticated_client.metadata().id_token_signed_response_alg,
        );
        let audience = client_id.clone();
        let access_token_audience = if identity_domain::openid_connect::ScopeSet::parse(&data.scope)
            .map(|scope| scope.has_api_scopes())
            .unwrap_or(false)
        {
            identity_domain::openid_connect::API_RESOURCE
        } else {
            audience.as_str()
        };
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
        let access_token = self
            .sign_access_token(SignAccessTokenInput {
                token_id: &access_token_record.oid.to_string(),
                key_id: &signing_key_id,
                private_key_pem: &signing_key_pem,
                alg: signing_alg,
                issuer: &issuer,
                audience: access_token_audience,
                client_id: &client_id_str,
                user_oid: &user_oid,
                protected_session_id: &protected_session_id,
                scope: &data.scope,
                claims: data.claims.as_ref(),
                auth_time: data.auth_time,
                acr: session_acr.as_deref(),
                amr: &session_amr,
            })
            .await?;
        let id_token = if data.scope.split_whitespace().any(|scope| scope == "openid") {
            let signed = self
                .sign_id_token(SignIdTokenInput {
                    key_id: &signing_key_id,
                    private_key_pem: &signing_key_pem,
                    alg: id_token_alg,
                    issuer: &issuer,
                    audience: &audience,
                    client: &authenticated_client,
                    user: &user,
                    nonce: data.nonce.as_deref(),
                    auth_time: data.auth_time,
                    acr: session_acr.as_deref(),
                    amr: &session_amr,
                    access_token: Some(&access_token),
                    protected_session_id: Some(&protected_session_id),
                })
                .await?;
            let id_token = match authenticated_client
                .metadata()
                .id_token_encrypted_response_alg
            {
                Some(alg) => {
                    let enc = authenticated_client
                        .metadata()
                        .id_token_encrypted_response_enc
                        .unwrap_or(JweContentEncryption::A128CbcHs256);
                    self.encrypt_token(&signed, &authenticated_client, alg, enc)
                        .await?
                }
                None => signed,
            };
            Some(id_token)
        } else {
            None
        };
        let refreshable_scope = data
            .scope
            .split_whitespace()
            .filter(|scope| *scope != identity_domain::openid_connect::ApiScope::PASSWORD_CHANGE)
            .collect::<Vec<_>>()
            .join(" ");
        let refresh_token = if data
            .scope
            .split_whitespace()
            .any(|scope| scope == "offline_access")
        {
            Some(
                self.store_refresh_token(StoreRefreshTokenParams {
                    client_oid: record.client_oid,
                    scope: &refreshable_scope,
                    user_oid: &data.user_oid,
                    session_oid: data.session_oid,
                    protected_session_id: Some(&protected_session_id),
                    auth_time: data.auth_time,
                    acr: session_acr.as_deref(),
                    amr: &session_amr,
                    rotated_from: None,
                })
                .await?,
            )
        } else {
            None
        };

        Ok(TokenResponse {
            access_token,
            id_token,
            refresh_token,
            token_type: TokenType::Bearer,
            expires_in: 3600,
            scope: data.scope,
        })
    }

    pub async fn exchange_refresh_token(
        &self,
        params: RefreshTokenGrantParams,
    ) -> Result<TokenResponse, AppError> {
        let client_id = resolve_client_id(
            params.client_id,
            params.client_assertion_type,
            params.client_assertion.as_deref(),
        )?;
        let authenticated_client_oid = self
            .authenticate_client(
                &client_id,
                params.client_secret.as_deref(),
                params.client_assertion_type,
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
        let now = chrono::Utc::now();
        if refresh_record.revoked_at.is_some() || refresh_record.expires_at <= now {
            return Err(AppError::from_code(TokenErrorCode::RefreshTokenInvalid));
        }
        let refresh_data = match refresh_record.data {
            ClientAuthorizationData::RefreshToken(data) => data,
            _ => {
                return Err(AppError::from_code(
                    TokenErrorCode::DeserializeRefreshFailed,
                ));
            }
        };
        let (session_acr, session_amr) = if let Some(session_repo) = &self.session_repo {
            let session = session_repo
                .find_by_oid(refresh_data.session_oid)
                .await
                .map_err(|error| {
                    AppError::from_code(TokenErrorCode::RefreshTokenInvalid).with_source(error)
                })?
                .ok_or_else(|| AppError::from_code(TokenErrorCode::RefreshTokenInvalid))?;
            let session_is_active = session.status == crate::domain::auth::SessionStatus::ACTIVE
                && session.revoked_at.is_none()
                && session.expires_at.is_none_or(|expires_at| expires_at > now)
                && session.user_oid.to_string() == refresh_data.user_oid;
            if !session_is_active {
                return Err(AppError::from_code(TokenErrorCode::RefreshTokenInvalid));
            }
            (session.effective_acr(now).map(str::to_owned), session.amr)
        } else {
            (refresh_data.acr.clone(), refresh_data.amr.clone())
        };
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

        let claimed = self
            .client_authorization_repo
            .revoke_if_active(
                refresh_record.oid,
                ClientAuthorizationType::RefreshToken,
                now,
            )
            .await
            .map_err(|error| {
                AppError::from_code(TokenErrorCode::RevokeRefreshFailed).with_source(error)
            })?;
        if !claimed {
            return Err(AppError::from_code(TokenErrorCode::RefreshTokenInvalid));
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
        let scope = refresh_data
            .scope
            .split_whitespace()
            .filter(|scope| *scope != identity_domain::openid_connect::ApiScope::PASSWORD_CHANGE)
            .collect::<Vec<_>>()
            .join(" ");
        let access_token_audience = if identity_domain::openid_connect::ScopeSet::parse(&scope)
            .map(|scope| scope.has_api_scopes())
            .unwrap_or(false)
        {
            identity_domain::openid_connect::API_RESOURCE
        } else {
            client_id.as_str()
        };
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
        let access_token = self
            .sign_access_token(SignAccessTokenInput {
                token_id: &access_token_record.oid.to_string(),
                key_id: &signing_key_id,
                private_key_pem: &signing_key_pem,
                alg: signing_alg,
                issuer: &issuer,
                audience: access_token_audience,
                client_id: &client_id,
                user_oid: &user_oid,
                protected_session_id: &protected_session_id,
                scope: &scope,
                claims: None,
                auth_time: refresh_data.auth_time,
                acr: session_acr.as_deref(),
                amr: &session_amr,
            })
            .await?;
        let signed_id_token = self
            .sign_id_token(SignIdTokenInput {
                key_id: &signing_key_id,
                private_key_pem: &signing_key_pem,
                alg: identity_domain::key::JwsAlgorithm::Asymmetric(signing_alg),
                issuer: &issuer,
                audience: &client_id,
                client: &authenticated_client,
                user: &user,
                nonce: None,
                auth_time: refresh_data.auth_time,
                acr: session_acr.as_deref(),
                amr: &session_amr,
                access_token: Some(&access_token),
                protected_session_id: Some(&protected_session_id),
            })
            .await?;
        let id_token = Some(
            match authenticated_client
                .metadata()
                .id_token_encrypted_response_alg
            {
                Some(alg) => {
                    let enc = authenticated_client
                        .metadata()
                        .id_token_encrypted_response_enc
                        .unwrap_or(JweContentEncryption::A128CbcHs256);
                    self.encrypt_token(&signed_id_token, &authenticated_client, alg, enc)
                        .await?
                }
                None => signed_id_token,
            },
        );
        let rotated_from = refresh_record.oid.to_string();
        let refresh_token = Some(
            self.store_refresh_token(StoreRefreshTokenParams {
                client_oid: authenticated_client_oid,
                scope: &scope,
                user_oid: &refresh_data.user_oid,
                session_oid: refresh_data.session_oid,
                protected_session_id: Some(&protected_session_id),
                auth_time: refresh_data.auth_time,
                acr: session_acr.as_deref(),
                amr: &session_amr,
                rotated_from: Some(rotated_from.as_str()),
            })
            .await?,
        );

        Ok(TokenResponse {
            access_token,
            id_token,
            refresh_token,
            token_type: TokenType::Bearer,
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
    client_assertion_type: Option<identity_domain::openid_connect::ClientAssertionType>,
    client_assertion: Option<&str>,
) -> Result<String, AppError> {
    if let Some(client_id) = client_id {
        return Ok(client_id);
    }

    if client_assertion_type
        == Some(identity_domain::openid_connect::ClientAssertionType::JwtBearer)
        && let Some(assertion) = client_assertion
    {
        return client_id_from_assertion(assertion);
    }

    Err(AppError::from_code(TokenErrorCode::ClientIdRequired))
}

pub(crate) fn resolve_id_token_alg(
    fallback: identity_domain::key::JwaSigningAlgorithm,
    client_alg: Option<identity_domain::key::JwsAlgorithm>,
) -> identity_domain::key::JwsAlgorithm {
    #[cfg(feature = "allow-none-alg")]
    if client_alg == Some(identity_domain::key::JwsAlgorithm::None) {
        return identity_domain::key::JwsAlgorithm::None;
    }

    #[cfg(not(feature = "allow-none-alg"))]
    if client_alg == Some(identity_domain::key::JwsAlgorithm::None) {
        return identity_domain::key::JwsAlgorithm::Asymmetric(fallback);
    }

    identity_domain::key::JwsAlgorithm::Asymmetric(fallback)
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
            Some(identity_domain::openid_connect::ClientAssertionType::JwtBearer),
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
            Some(identity_domain::openid_connect::ClientAssertionType::JwtBearer),
            Some(&assertion),
        )
        .unwrap();

        assert_eq!(client_id, "assertion-client");
    }
}
