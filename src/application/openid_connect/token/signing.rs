use super::*;
use identity_domain::auth::SessionOid;
use josekit::jwe::JweHeader;

pub(super) struct StoreRefreshTokenParams<'a> {
    pub client_oid: Uuid,
    pub scope: &'a str,
    pub user_oid: &'a str,
    pub session_oid: SessionOid,
    pub protected_session_id: Option<&'a str>,
    pub auth_time: Option<i64>,
    pub rotated_from: Option<&'a str>,
}

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
            if let KeyData::Asymmetric(data) = &key.data {
                let Some(alg) = self
                    .signing_algorithm_detector
                    .detect(&key)
                    .into_iter()
                    .next()
                else {
                    continue;
                };

                let Some(binding) = self
                    .key_jwk_repo
                    .find_active_by_key_oid_and_algorithm(key.oid, alg.as_str())
                    .await
                    .map_err(|error| {
                        AppError::from_code(TokenErrorCode::KeyListFailed).with_source(error)
                    })?
                else {
                    continue;
                };

                return Ok((
                    Uuid::from(binding.oid).to_string(),
                    data.private_key.clone(),
                    alg.as_str().to_owned(),
                ));
            }
        }

        Err(AppError::from_code(TokenErrorCode::NoSigningKeyAvailable))
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) fn sign_access_token(
        &self,
        token_id: &str,
        key_id: &str,
        private_key_pem: &str,
        alg: &str,
        issuer: &url::Url,
        audience: &str,
        client_id: &str,
        user_oid: &Uuid,
        protected_session_id: &str,
        scope: &str,
        claims: Option<&serde_json::Value>,
    ) -> Result<String, AppError> {
        let mut header = JwsHeader::new();
        header.set_token_type(JwtTokenType::ACCESS_TOKEN);
        header.set_key_id(key_id);

        let mut payload = JwtPayload::new();
        let now = std::time::SystemTime::now();
        payload.set_issuer(issuer.as_str());
        payload.set_subject(user_oid.to_string());
        payload.set_audience(vec![audience]);
        payload.set_issued_at(&now);
        payload.set_expires_at(&(now + std::time::Duration::from_secs(3600)));
        payload.set_jwt_id(token_id);
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
            .set_claim(
                JwtClaimNames::SID,
                Some(serde_json::json!(protected_session_id)),
            )
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

        let signer = build_access_token_signer(private_key_pem, alg)?;
        jwt::encode_with_signer(&payload, &header, &*signer).map_err(|error| {
            AppError::from_code(TokenErrorCode::SignAccessTokenFailed).with_source(error)
        })
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) fn sign_id_token(
        &self,
        key_id: &str,
        private_key_pem: &str,
        alg: &str,
        issuer: &url::Url,
        audience: &str,
        client: &identity_domain::openid_connect::OpenIdConnectClient,
        user: &identity_domain::user::User,
        nonce: Option<&str>,
        auth_time: Option<i64>,
        acr: Option<&str>,
        access_token: Option<&str>,
        protected_session_id: Option<&str>,
        _scope: &str,
    ) -> Result<String, AppError> {
        let mut header = JwsHeader::new();
        header.set_token_type("JWT");
        header.set_key_id(key_id);

        let mut payload = JwtPayload::new();
        let now = std::time::SystemTime::now();
        payload.set_issuer(issuer.as_str());
        payload.set_subject(client.subject_identifier(Uuid::from(user.oid), issuer));
        payload.set_audience(vec![audience]);
        payload.set_issued_at(&now);
        payload.set_expires_at(&(now + std::time::Duration::from_secs(3600)));
        payload
            .set_claim(
                JwtClaimNames::AZP,
                Some(serde_json::json!(client.client().oid.to_string())),
            )
            .map_err(|error| {
                AppError::from_code(TokenErrorCode::SignIdTokenFailed).with_source(error)
            })?;
        payload
            .set_claim(JwtClaimNames::AMR, Some(serde_json::json!(amr_values(acr))))
            .map_err(|error| {
                AppError::from_code(TokenErrorCode::SignIdTokenFailed).with_source(error)
            })?;
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
        if let Some(access_token) = access_token {
            let at_hash = compute_at_hash(access_token, alg);
            payload
                .set_claim(JwtClaimNames::AT_HASH, Some(serde_json::json!(at_hash)))
                .map_err(|error| {
                    AppError::from_code(TokenErrorCode::SignIdTokenFailed).with_source(error)
                })?;
        }
        if let Some(protected_session_id) = protected_session_id {
            payload
                .set_claim(
                    JwtClaimNames::SID,
                    Some(serde_json::json!(protected_session_id)),
                )
                .map_err(|error| {
                    AppError::from_code(TokenErrorCode::SignIdTokenFailed).with_source(error)
                })?;
        }

        if alg == "none" {
            #[cfg(feature = "allow-none-alg")]
            return Self::sign_unsigned_id_token(&header, &payload);

            #[cfg(not(feature = "allow-none-alg"))]
            return Err(AppError::from_code(TokenErrorCode::SignIdTokenFailed));
        }

        let signer: Box<dyn josekit::jws::JwsSigner> = build_id_token_signer(private_key_pem, alg)?;
        jwt::encode_with_signer(&payload, &header, &*signer).map_err(|error| {
            AppError::from_code(TokenErrorCode::SignIdTokenFailed).with_source(error)
        })
    }

    #[cfg(feature = "allow-none-alg")]
    fn sign_unsigned_id_token(
        header: &JwsHeader,
        payload: &JwtPayload,
    ) -> Result<String, AppError> {
        jwt::encode_unsecured(payload, header).map_err(|error| {
            AppError::from_code(TokenErrorCode::SignIdTokenFailed).with_source(error)
        })
    }

    pub(super) async fn encrypt_token(
        &self,
        signed_jwt: &str,
        client: &identity_domain::openid_connect::OpenIdConnectClient,
        encryption_alg: &str,
        content_enc: &str,
    ) -> Result<String, AppError> {
        use josekit::jwe::{
            ECDH_ES, ECDH_ES_A128KW, ECDH_ES_A256KW, JweEncrypter, RSA_OAEP, RSA_OAEP_256,
        };
        use josekit::jwk::Jwk;

        let credential = self
            .credential_repo
            .find_first_encryption_key(client.client().oid)
            .await
            .map_err(|error| {
                AppError::from_code(TokenErrorCode::EncryptionKeyNotFound).with_source(error)
            })?
            .ok_or_else(|| AppError::from_code(TokenErrorCode::EncryptionKeyNotFound))?;

        let public_jwk = match &credential.data {
            identity_domain::openid_connect::OpenIdConnectCredentialData::ClientPublicKey {
                jwk: Some(jwk),
                ..
            } => jwk.clone(),
            _ => return Err(AppError::from_code(TokenErrorCode::EncryptionKeyNotFound)),
        };

        let jwk_value = serde_json::to_value(&public_jwk)
            .map_err(|e| AppError::from_code(TokenErrorCode::EncryptionFailed).with_source(e))?;
        let jwk_json = jwk_value.to_string();
        let josekit_jwk = Jwk::from_bytes(jwk_json.as_bytes())
            .map_err(|e| AppError::from_code(TokenErrorCode::EncryptionFailed).with_source(e))?;

        let encrypter: Box<dyn JweEncrypter> = match encryption_alg {
            "RSA-OAEP" => Box::new(RSA_OAEP.encrypter_from_jwk(&josekit_jwk).map_err(|e| {
                AppError::from_code(TokenErrorCode::EncryptionFailed).with_source(e)
            })?),
            "RSA-OAEP-256" => {
                Box::new(RSA_OAEP_256.encrypter_from_jwk(&josekit_jwk).map_err(|e| {
                    AppError::from_code(TokenErrorCode::EncryptionFailed).with_source(e)
                })?)
            }
            "ECDH-ES" => Box::new(ECDH_ES.encrypter_from_jwk(&josekit_jwk).map_err(|e| {
                AppError::from_code(TokenErrorCode::EncryptionFailed).with_source(e)
            })?),
            "ECDH-ES+A128KW" => Box::new(ECDH_ES_A128KW.encrypter_from_jwk(&josekit_jwk).map_err(
                |e| AppError::from_code(TokenErrorCode::EncryptionFailed).with_source(e),
            )?),
            "ECDH-ES+A256KW" => Box::new(ECDH_ES_A256KW.encrypter_from_jwk(&josekit_jwk).map_err(
                |e| AppError::from_code(TokenErrorCode::EncryptionFailed).with_source(e),
            )?),
            _ => return Err(AppError::from_code(TokenErrorCode::EncryptionFailed)),
        };

        let mut header = JweHeader::new();
        header.set_algorithm(encryption_alg);
        header.set_content_encryption(content_enc);

        josekit::jwe::serialize_compact(signed_jwt.as_bytes(), &header, &*encrypter)
            .map_err(|e| AppError::from_code(TokenErrorCode::EncryptionFailed).with_source(e))
    }
}

fn amr_values(acr: Option<&str>) -> Vec<&'static str> {
    match acr {
        Some(identity_domain::auth::ACR_MFA) => vec!["pwd", "otp"],
        _ => vec!["pwd"],
    }
}

fn build_access_token_signer(
    private_key_pem: &str,
    alg: &str,
) -> Result<Box<dyn josekit::jws::JwsSigner>, AppError> {
    build_jws_signer(private_key_pem, alg, TokenErrorCode::SignAccessTokenFailed)
}

fn build_id_token_signer(
    private_key_pem: &str,
    alg: &str,
) -> Result<Box<dyn josekit::jws::JwsSigner>, AppError> {
    build_jws_signer(private_key_pem, alg, TokenErrorCode::SignIdTokenFailed)
}

fn build_jws_signer(
    private_key_pem: &str,
    alg: &str,
    error_code: TokenErrorCode,
) -> Result<Box<dyn josekit::jws::JwsSigner>, AppError> {
    let jwa: JwaSigningAlgorithm = alg.parse().map_err(|_| AppError::from_code(error_code))?;
    let pem = private_key_pem.as_bytes();
    match jwa {
        JwaSigningAlgorithm::Rs256 => {
            Ok(Box::new(RS256.signer_from_pem(pem).map_err(|error| {
                AppError::from_code(error_code).with_source(error)
            })?))
        }
        JwaSigningAlgorithm::Rs384 => {
            Ok(Box::new(RS384.signer_from_pem(pem).map_err(|error| {
                AppError::from_code(error_code).with_source(error)
            })?))
        }
        JwaSigningAlgorithm::Rs512 => {
            Ok(Box::new(RS512.signer_from_pem(pem).map_err(|error| {
                AppError::from_code(error_code).with_source(error)
            })?))
        }
        JwaSigningAlgorithm::Ps256 => {
            Ok(Box::new(PS256.signer_from_pem(pem).map_err(|error| {
                AppError::from_code(error_code).with_source(error)
            })?))
        }
        JwaSigningAlgorithm::Ps384 => {
            Ok(Box::new(PS384.signer_from_pem(pem).map_err(|error| {
                AppError::from_code(error_code).with_source(error)
            })?))
        }
        JwaSigningAlgorithm::Ps512 => {
            Ok(Box::new(PS512.signer_from_pem(pem).map_err(|error| {
                AppError::from_code(error_code).with_source(error)
            })?))
        }
        JwaSigningAlgorithm::Es256 => {
            Ok(Box::new(ES256.signer_from_pem(pem).map_err(|error| {
                AppError::from_code(error_code).with_source(error)
            })?))
        }
        JwaSigningAlgorithm::Es384 => {
            Ok(Box::new(ES384.signer_from_pem(pem).map_err(|error| {
                AppError::from_code(error_code).with_source(error)
            })?))
        }
        JwaSigningAlgorithm::Es512 => {
            Ok(Box::new(ES512.signer_from_pem(pem).map_err(|error| {
                AppError::from_code(error_code).with_source(error)
            })?))
        }
        JwaSigningAlgorithm::Es256k => {
            Ok(Box::new(ES256K.signer_from_pem(pem).map_err(|error| {
                AppError::from_code(error_code).with_source(error)
            })?))
        }
        JwaSigningAlgorithm::EdDsa => {
            Ok(Box::new(EdDSA.signer_from_pem(pem).map_err(|error| {
                AppError::from_code(error_code).with_source(error)
            })?))
        }
    }
}

fn compute_at_hash(access_token: &str, alg: &str) -> String {
    let jwa: JwaSigningAlgorithm = alg.parse().unwrap_or(JwaSigningAlgorithm::Rs256);
    match jwa.at_hash_bits() {
        384 => {
            let digest = Sha384::digest(access_token.as_bytes());
            URL_SAFE_NO_PAD.encode(&digest[..24])
        }
        512 => {
            let digest = Sha512::digest(access_token.as_bytes());
            URL_SAFE_NO_PAD.encode(&digest[..32])
        }
        _ => {
            let digest = Sha256::digest(access_token.as_bytes());
            URL_SAFE_NO_PAD.encode(&digest[..16])
        }
    }
}

impl TokenService {
    pub(super) async fn store_refresh_token(
        &self,
        params: StoreRefreshTokenParams<'_>,
    ) -> Result<String, AppError> {
        let data = serde_json::to_value(RefreshTokenData {
            scope: params.scope.to_string(),
            user_oid: params.user_oid.to_string(),
            session_oid: params.session_oid,
            protected_session_id: params.protected_session_id.map(str::to_string),
            auth_time: params.auth_time,
            rotated_from: params.rotated_from.map(str::to_string),
        })
        .map_err(|error| {
            AppError::from_code(TokenErrorCode::SerializeRefreshFailed).with_source(error)
        })?;

        let record = self
            .client_authorization_repo
            .create(
                params.client_oid,
                ClientAuthorizationType::RefreshToken,
                data,
                chrono::Utc::now() + chrono::Duration::days(30),
            )
            .await
            .map_err(|error| {
                AppError::from_code(TokenErrorCode::StoreRefreshFailed).with_source(error)
            })?;

        self.data_protector
            .protect("refresh-token", record.oid.as_bytes())
            .await
            .map_err(|error| {
                AppError::from_code(TokenErrorCode::SignRefreshTokenFailed).with_source(error)
            })
    }

    pub(super) async fn create_access_token_record(
        &self,
        client_oid: Uuid,
        scope: &str,
        user_oid: &str,
        session_oid: SessionOid,
        protected_session_id: Option<&str>,
        authorization_code_oid: Option<Uuid>,
    ) -> Result<ClientAuthorization, AppError> {
        let data = serde_json::to_value(AccessTokenData {
            scope: scope.to_string(),
            user_oid: user_oid.to_string(),
            session_oid,
            protected_session_id: protected_session_id.map(str::to_string),
            authorization_code_oid: authorization_code_oid.map(|oid| oid.to_string()),
        })
        .map_err(|error| {
            AppError::from_code(TokenErrorCode::SignAccessTokenFailed).with_source(error)
        })?;

        self.client_authorization_repo
            .create(
                client_oid,
                ClientAuthorizationType::AccessToken,
                data,
                chrono::Utc::now() + chrono::Duration::hours(1),
            )
            .await
            .map_err(|error| {
                AppError::from_code(TokenErrorCode::SignAccessTokenFailed).with_source(error)
            })
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
        payload.set_jwt_id(Uuid::new_v4().to_string());

        let signer = RS256.signer_from_pem(private_key.as_bytes()).unwrap();
        jwt::encode_with_signer(&payload, &header, &signer).unwrap()
    }
}
