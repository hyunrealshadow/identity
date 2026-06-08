use super::*;
use crate::openid_connect::jose::{asymmetric_signer_from_pem, encrypt_compact_with_public_jwk};
use identity_domain::auth::SessionOid;
use identity_domain::openid_connect::ClaimsRequest;
#[cfg(test)]
use josekit::jws::RS256;

pub(super) struct StoreRefreshTokenParams<'a> {
    pub client_oid: Uuid,
    pub scope: &'a str,
    pub user_oid: &'a str,
    pub session_oid: SessionOid,
    pub protected_session_id: Option<&'a str>,
    pub auth_time: Option<i64>,
    pub rotated_from: Option<&'a str>,
}

pub(super) struct SignAccessTokenInput<'a> {
    pub token_id: &'a str,
    pub key_id: &'a str,
    pub private_key_pem: &'a str,
    pub alg: &'a str,
    pub issuer: &'a url::Url,
    pub audience: &'a str,
    pub client_id: &'a str,
    pub user_oid: &'a Uuid,
    pub protected_session_id: &'a str,
    pub scope: &'a str,
    pub claims: Option<&'a ClaimsRequest>,
}

pub(super) struct SignIdTokenInput<'a> {
    pub key_id: &'a str,
    pub private_key_pem: &'a str,
    pub alg: &'a str,
    pub issuer: &'a url::Url,
    pub audience: &'a str,
    pub client: &'a identity_domain::openid_connect::OpenIdConnectClient,
    pub user: &'a identity_domain::user::User,
    pub nonce: Option<&'a str>,
    pub auth_time: Option<i64>,
    pub acr: Option<&'a str>,
    pub access_token: Option<&'a str>,
    pub protected_session_id: Option<&'a str>,
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

    pub(super) fn sign_access_token(
        &self,
        input: SignAccessTokenInput<'_>,
    ) -> Result<String, AppError> {
        let mut header = JwsHeader::new();
        header.set_token_type(JwtTokenType::ACCESS_TOKEN);
        header.set_key_id(input.key_id);

        let mut payload = JwtPayload::new();
        let now = std::time::SystemTime::now();
        payload.set_issuer(input.issuer.as_str());
        payload.set_subject(input.user_oid.to_string());
        payload.set_audience(vec![input.audience]);
        payload.set_issued_at(&now);
        payload.set_expires_at(&(now + std::time::Duration::from_secs(3600)));
        payload.set_jwt_id(input.token_id);
        payload
            .set_claim(
                JwtClaimNames::CLIENT_ID,
                Some(serde_json::json!(input.client_id)),
            )
            .map_err(|error| {
                AppError::from_code(TokenErrorCode::SignAccessTokenFailed).with_source(error)
            })?;
        payload
            .set_claim(JwtClaimNames::SCOPE, Some(serde_json::json!(input.scope)))
            .map_err(|error| {
                AppError::from_code(TokenErrorCode::SignAccessTokenFailed).with_source(error)
            })?;
        payload
            .set_claim(
                JwtClaimNames::SID,
                Some(serde_json::json!(input.protected_session_id)),
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
        if let Some(claims_value) = input.claims {
            payload
                .set_claim(
                    "claims",
                    Some(serde_json::to_value(claims_value).map_err(|error| {
                        AppError::from_code(TokenErrorCode::SignAccessTokenFailed)
                            .with_source(error)
                    })?),
                )
                .map_err(|error| {
                    AppError::from_code(TokenErrorCode::SignAccessTokenFailed).with_source(error)
                })?;
        }

        let signer = build_access_token_signer(input.private_key_pem, input.alg)?;
        jwt::encode_with_signer(&payload, &header, &*signer).map_err(|error| {
            AppError::from_code(TokenErrorCode::SignAccessTokenFailed).with_source(error)
        })
    }

    pub(super) fn sign_id_token(&self, input: SignIdTokenInput<'_>) -> Result<String, AppError> {
        let mut header = JwsHeader::new();
        header.set_token_type("JWT");
        header.set_key_id(input.key_id);

        let mut payload = JwtPayload::new();
        let now = std::time::SystemTime::now();
        payload.set_issuer(input.issuer.as_str());
        payload.set_subject(
            input
                .client
                .subject_identifier(Uuid::from(input.user.oid), input.issuer),
        );
        payload.set_audience(vec![input.audience]);
        payload.set_issued_at(&now);
        payload.set_expires_at(&(now + std::time::Duration::from_secs(3600)));
        payload
            .set_claim(
                JwtClaimNames::AZP,
                Some(serde_json::json!(input.client.client().oid.to_string())),
            )
            .map_err(|error| {
                AppError::from_code(TokenErrorCode::SignIdTokenFailed).with_source(error)
            })?;
        payload
            .set_claim(
                JwtClaimNames::AMR,
                Some(serde_json::json!(amr_values(input.acr))),
            )
            .map_err(|error| {
                AppError::from_code(TokenErrorCode::SignIdTokenFailed).with_source(error)
            })?;
        if let Some(nonce) = input.nonce {
            payload
                .set_claim(JwtClaimNames::NONCE, Some(serde_json::json!(nonce)))
                .map_err(|error| {
                    AppError::from_code(TokenErrorCode::SignIdTokenFailed).with_source(error)
                })?;
        }
        if let Some(auth_time) = input.auth_time {
            payload
                .set_claim(JwtClaimNames::AUTH_TIME, Some(serde_json::json!(auth_time)))
                .map_err(|error| {
                    AppError::from_code(TokenErrorCode::SignIdTokenFailed).with_source(error)
                })?;
        }
        if let Some(acr) = input.acr {
            payload
                .set_claim(JwtClaimNames::ACR, Some(serde_json::json!(acr)))
                .map_err(|error| {
                    AppError::from_code(TokenErrorCode::SignIdTokenFailed).with_source(error)
                })?;
        }
        if let Some(access_token) = input.access_token {
            let at_hash = compute_at_hash(access_token, input.alg);
            payload
                .set_claim(JwtClaimNames::AT_HASH, Some(serde_json::json!(at_hash)))
                .map_err(|error| {
                    AppError::from_code(TokenErrorCode::SignIdTokenFailed).with_source(error)
                })?;
        }
        if let Some(protected_session_id) = input.protected_session_id {
            payload
                .set_claim(
                    JwtClaimNames::SID,
                    Some(serde_json::json!(protected_session_id)),
                )
                .map_err(|error| {
                    AppError::from_code(TokenErrorCode::SignIdTokenFailed).with_source(error)
                })?;
        }

        if input.alg == "none" {
            #[cfg(feature = "allow-none-alg")]
            return Self::sign_unsigned_id_token(&header, &payload);

            #[cfg(not(feature = "allow-none-alg"))]
            return Err(AppError::from_code(TokenErrorCode::SignIdTokenFailed));
        }

        let signer: Box<dyn josekit::jws::JwsSigner> =
            build_id_token_signer(input.private_key_pem, input.alg)?;
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
            } => jwk,
            _ => return Err(AppError::from_code(TokenErrorCode::EncryptionKeyNotFound)),
        };

        encrypt_compact_with_public_jwk(
            signed_jwt.as_bytes(),
            public_jwk,
            encryption_alg,
            content_enc,
        )
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
    asymmetric_signer_from_pem(alg, private_key_pem.as_bytes())
        .map_err(|error| AppError::from_code(error_code).with_source(error))
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
        let data = ClientAuthorizationData::RefreshToken(RefreshTokenData {
            scope: params.scope.to_string(),
            user_oid: params.user_oid.to_string(),
            session_oid: params.session_oid,
            protected_session_id: params.protected_session_id.map(str::to_string),
            auth_time: params.auth_time,
            rotated_from: params.rotated_from.map(str::to_string),
        });

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
        let data = ClientAuthorizationData::AccessToken(AccessTokenData {
            scope: scope.to_string(),
            user_oid: user_oid.to_string(),
            session_oid,
            protected_session_id: protected_session_id.map(str::to_string),
            authorization_code_oid: authorization_code_oid.map(|oid| oid.to_string()),
        });

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
