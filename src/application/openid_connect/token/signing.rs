use super::*;

impl TokenService {
    pub(super) async fn load_signing_key(&self) -> Result<(String, String, String), AppError> {
        let keys = self
            .key_repo
            .list_available_asymmetric()
            .await
            .map_err(|error| {
                AppError::from_code(TokenErrorCode::KeyListFailed).with_source(error)
            })?;

        for key in keys {
            if let KeyData::Asymmetric(data) = key.data {
                let pem = data.private_key.as_bytes();
                if RS256.signer_from_pem(pem).is_ok() {
                    return Ok((
                        Uuid::from(key.oid).to_string(),
                        data.private_key,
                        "RS256".to_string(),
                    ));
                }
                if ES256.signer_from_pem(pem).is_ok() {
                    return Ok((
                        Uuid::from(key.oid).to_string(),
                        data.private_key,
                        "ES256".to_string(),
                    ));
                }
            }
        }

        Err(AppError::from_code(TokenErrorCode::NoSigningKeyAvailable))
    }

    pub(super) async fn verify_refresh_token(&self, raw: &str) -> Result<JwtPayload, AppError> {
        let keys = self
            .key_repo
            .list_available_asymmetric()
            .await
            .map_err(|error| {
                AppError::from_code(TokenErrorCode::KeyListFailed).with_source(error)
            })?;

        for key in keys {
            if let KeyData::Asymmetric(data) = key.data {
                if let Ok(verifier) = RS256.verifier_from_pem(data.public_key.as_bytes()) {
                    if let Ok((payload, _)) = jwt::decode_with_verifier(raw, &verifier) {
                        return Ok(payload);
                    }
                }
                if let Ok(verifier) = ES256.verifier_from_pem(data.public_key.as_bytes()) {
                    if let Ok((payload, _)) = jwt::decode_with_verifier(raw, &verifier) {
                        return Ok(payload);
                    }
                }
                if let Ok(verifier) = ES256K.verifier_from_pem(data.public_key.as_bytes()) {
                    if let Ok((payload, _)) = jwt::decode_with_verifier(raw, &verifier) {
                        return Ok(payload);
                    }
                }
                if let Ok(verifier) = ES384.verifier_from_pem(data.public_key.as_bytes()) {
                    if let Ok((payload, _)) = jwt::decode_with_verifier(raw, &verifier) {
                        return Ok(payload);
                    }
                }
                if let Ok(verifier) = ES512.verifier_from_pem(data.public_key.as_bytes()) {
                    if let Ok((payload, _)) = jwt::decode_with_verifier(raw, &verifier) {
                        return Ok(payload);
                    }
                }
                if let Ok(verifier) = RS384.verifier_from_pem(data.public_key.as_bytes()) {
                    if let Ok((payload, _)) = jwt::decode_with_verifier(raw, &verifier) {
                        return Ok(payload);
                    }
                }
                if let Ok(verifier) = RS512.verifier_from_pem(data.public_key.as_bytes()) {
                    if let Ok((payload, _)) = jwt::decode_with_verifier(raw, &verifier) {
                        return Ok(payload);
                    }
                }
                if let Ok(verifier) = EdDSA.verifier_from_pem(data.public_key.as_bytes()) {
                    if let Ok((payload, _)) = jwt::decode_with_verifier(raw, &verifier) {
                        return Ok(payload);
                    }
                }
            }
        }

        Err(AppError::from_code(
            TokenErrorCode::RefreshTokenVerifyFailed,
        ))
    }

    pub(super) fn sign_access_token(
        &self,
        key_id: &str,
        private_key_pem: &str,
        alg: &str,
        issuer: &url::Url,
        audience: &str,
        client_id: &str,
        user_oid: &Uuid,
        session_oid: &str,
        scope: &str,
        claims: Option<&serde_json::Value>,
    ) -> Result<String, AppError> {
        let mut header = JwsHeader::new();
        header.set_token_type(JwtTokenType::ACCESS_TOKEN);
        header.set_key_id(key_id);

        let mut payload = JwtPayload::new();
        let now = std::time::SystemTime::now();
        payload.set_issuer(issuer.as_str());
        payload.set_subject(&user_oid.to_string());
        payload.set_audience(vec![audience]);
        payload.set_issued_at(&now);
        payload.set_expires_at(&(now + std::time::Duration::from_secs(3600)));
        payload.set_jwt_id(&Uuid::new_v4().to_string());
        payload
            .set_claim(JwtClaimNames::CLIENT_ID, Some(serde_json::json!(client_id)))
            .map_err(|error| {
                AppError::from_code(TokenErrorCode::SignAccessTokenFailed).with_source(error)
            })?;
        payload
            .set_claim(JwtClaimNames::SCOPE, Some(serde_json::json!(scope)))
            .map_err(|error| {
                AppError::from_code(TokenErrorCode::SignAccessTokenFailed).with_source(error)
            })?;
        payload
            .set_claim(JwtClaimNames::SID, Some(serde_json::json!(session_oid)))
            .map_err(|error| {
                AppError::from_code(TokenErrorCode::SignAccessTokenFailed).with_source(error)
            })?;
        payload
            .set_claim(
                JwtClaimNames::TOKEN_USE,
                Some(serde_json::json!(TokenUseValues::ACCESS_TOKEN)),
            )
            .map_err(|error| {
                AppError::from_code(TokenErrorCode::SignAccessTokenFailed).with_source(error)
            })?;
        if let Some(claims_value) = claims {
            payload
                .set_claim("claims", Some(claims_value.clone()))
                .map_err(|error| {
                    AppError::from_code(TokenErrorCode::SignAccessTokenFailed).with_source(error)
                })?;
        }

        let signer: Box<dyn josekit::jws::JwsSigner> = match alg {
            "RS256" => Box::new(RS256.signer_from_pem(private_key_pem.as_bytes()).map_err(
                |error| {
                    AppError::from_code(TokenErrorCode::SignAccessTokenFailed).with_source(error)
                },
            )?),
            _ => Box::new(
                ES256
                    .signer_from_pem(private_key_pem.as_bytes())
                    .map_err(|error| {
                        AppError::from_code(TokenErrorCode::SignAccessTokenFailed)
                            .with_source(error)
                    })?,
            ),
        };
        jwt::encode_with_signer(&payload, &header, &*signer).map_err(|error| {
            AppError::from_code(TokenErrorCode::SignAccessTokenFailed).with_source(error)
        })
    }

    pub(super) fn sign_id_token(
        &self,
        key_id: &str,
        private_key_pem: &str,
        alg: &str,
        issuer: &url::Url,
        audience: &str,
        user: &crate::domain::user::User,
        nonce: Option<&str>,
        auth_time: Option<i64>,
        acr: Option<&str>,
        _scope: &str,
    ) -> Result<String, AppError> {
        let mut header = JwsHeader::new();
        header.set_token_type("JWT");
        header.set_key_id(key_id);

        let mut payload = JwtPayload::new();
        let now = std::time::SystemTime::now();
        payload.set_issuer(issuer.as_str());
        payload.set_subject(&Uuid::from(user.oid).to_string());
        payload.set_audience(vec![audience]);
        payload.set_issued_at(&now);
        payload.set_expires_at(&(now + std::time::Duration::from_secs(3600)));
        if let Some(nonce) = nonce {
            payload
                .set_claim(JwtClaimNames::NONCE, Some(serde_json::json!(nonce)))
                .map_err(|error| {
                    AppError::from_code(TokenErrorCode::SignIdTokenFailed).with_source(error)
                })?;
        }
        if let Some(auth_time) = auth_time {
            payload
                .set_claim(JwtClaimNames::AUTH_TIME, Some(serde_json::json!(auth_time)))
                .map_err(|error| {
                    AppError::from_code(TokenErrorCode::SignIdTokenFailed).with_source(error)
                })?;
        }
        if let Some(acr) = acr {
            payload
                .set_claim(JwtClaimNames::ACR, Some(serde_json::json!(acr)))
                .map_err(|error| {
                    AppError::from_code(TokenErrorCode::SignIdTokenFailed).with_source(error)
                })?;
        }

        let signer: Box<dyn josekit::jws::JwsSigner> = match alg {
            "RS256" => Box::new(RS256.signer_from_pem(private_key_pem.as_bytes()).map_err(
                |error| AppError::from_code(TokenErrorCode::SignIdTokenFailed).with_source(error),
            )?),
            _ => Box::new(
                ES256
                    .signer_from_pem(private_key_pem.as_bytes())
                    .map_err(|error| {
                        AppError::from_code(TokenErrorCode::SignIdTokenFailed).with_source(error)
                    })?,
            ),
        };
        jwt::encode_with_signer(&payload, &header, &*signer).map_err(|error| {
            AppError::from_code(TokenErrorCode::SignIdTokenFailed).with_source(error)
        })
    }

    pub(super) fn sign_refresh_token(
        &self,
        key_id: &str,
        private_key_pem: &str,
        alg: &str,
        issuer: &url::Url,
        audience: &str,
        user_oid: &Uuid,
    ) -> Result<String, AppError> {
        let mut header = JwsHeader::new();
        header.set_token_type("JWT");
        header.set_key_id(key_id);

        let mut payload = JwtPayload::new();
        let now = std::time::SystemTime::now();
        payload.set_issuer(issuer.as_str());
        payload.set_subject(&user_oid.to_string());
        payload.set_audience(vec![audience]);
        payload.set_issued_at(&now);
        payload.set_expires_at(&(now + std::time::Duration::from_secs(30 * 24 * 60 * 60)));
        payload
            .set_claim(
                JwtClaimNames::TOKEN_USE,
                Some(serde_json::json!(TokenUseValues::REFRESH_TOKEN)),
            )
            .map_err(|error| {
                AppError::from_code(TokenErrorCode::SignRefreshTokenFailed).with_source(error)
            })?;

        let signer: Box<dyn josekit::jws::JwsSigner> = match alg {
            "RS256" => Box::new(RS256.signer_from_pem(private_key_pem.as_bytes()).map_err(
                |error| {
                    AppError::from_code(TokenErrorCode::SignRefreshTokenFailed).with_source(error)
                },
            )?),
            _ => Box::new(
                ES256
                    .signer_from_pem(private_key_pem.as_bytes())
                    .map_err(|error| {
                        AppError::from_code(TokenErrorCode::SignRefreshTokenFailed)
                            .with_source(error)
                    })?,
            ),
        };
        jwt::encode_with_signer(&payload, &header, &*signer).map_err(|error| {
            AppError::from_code(TokenErrorCode::SignRefreshTokenFailed).with_source(error)
        })
    }

    pub(super) async fn store_refresh_token(
        &self,
        client_oid: Uuid,
        token: &str,
        scope: &str,
        user_oid: &str,
        session_oid: &str,
        rotated_from: Option<&str>,
    ) -> Result<(), AppError> {
        let data = serde_json::to_value(RefreshTokenData {
            token: token.to_string(),
            scope: scope.to_string(),
            user_oid: user_oid.to_string(),
            session_oid: session_oid.to_string(),
            rotated_from: rotated_from.map(str::to_string),
        })
        .map_err(|error| {
            AppError::from_code(TokenErrorCode::SerializeRefreshFailed).with_source(error)
        })?;

        self.client_request_repo
            .create(
                client_oid,
                ClientRequestType::RefreshToken,
                data,
                chrono::Utc::now() + chrono::Duration::days(30),
            )
            .await
            .map_err(|error| {
                AppError::from_code(TokenErrorCode::StoreRefreshFailed).with_source(error)
            })?;

        Ok(())
    }

    #[cfg(test)]
    pub(super) async fn build_client_assertion_for_test(&self, client_id: &str) -> String {
        let issuer = self.provider_service.issuer().unwrap();
        let (key_id, private_key, _alg) = self.load_signing_key().await.unwrap();
        let mut header = JwsHeader::new();
        header.set_token_type("JWT");
        header.set_key_id(&key_id);

        let mut payload = JwtPayload::new();
        let now = std::time::SystemTime::now();
        payload.set_issuer(client_id);
        payload.set_subject(client_id);
        payload.set_audience(vec![issuer.as_str()]);
        payload.set_issued_at(&now);
        payload.set_expires_at(&(now + std::time::Duration::from_secs(300)));
        payload.set_jwt_id(&Uuid::new_v4().to_string());

        let signer = RS256.signer_from_pem(private_key.as_bytes()).unwrap();
        jwt::encode_with_signer(&payload, &header, &signer).unwrap()
    }
}
