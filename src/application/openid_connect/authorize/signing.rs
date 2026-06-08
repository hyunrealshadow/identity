use super::*;
use josekit::{jws::JwsHeader, jwt, jwt::JwtPayload};
use std::time::Duration;
use uuid::Uuid;

use crate::openid_connect::dto::UserInfoClaims;
use crate::openid_connect::jose::{
    asymmetric_signer_from_pem, encrypt_compact_with_public_jwk, front_channel_hash,
};
use identity_domain::openid_connect::{
    ClaimsRequest,
    model::claim::{JwtTokenType, TokenUseValues},
};

pub(super) struct SignImplicitIdTokenInput<'a> {
    pub key_id: &'a str,
    pub private_key_pem: &'a str,
    pub alg: &'a str,
    pub issuer: &'a Url,
    pub audience: &'a str,
    pub user: &'a identity_domain::user::User,
    pub nonce: &'a str,
    pub auth_time: i64,
    pub acr: Option<&'a str>,
    pub access_token: Option<&'a str>,
    pub code: Option<&'a str>,
    pub protected_session_id: Option<&'a str>,
    pub scope: &'a ScopeSet,
    pub claims_request: Option<&'a ClaimsRequest>,
}

pub(super) struct SignImplicitAccessTokenInput<'a> {
    pub key_id: &'a str,
    pub private_key_pem: &'a str,
    pub alg: &'a str,
    pub issuer: &'a Url,
    pub audience: &'a str,
    pub client_id: &'a str,
    pub user_oid: &'a str,
    pub protected_session_id: &'a str,
    pub scope: &'a str,
    pub token_id: &'a str,
    pub claims: Option<&'a ClaimsRequest>,
}

impl AuthorizeService {
    pub(super) async fn load_signing_key_impl(&self) -> Result<(String, String, String), AppError> {
        let keys = self
            .key_repo
            .list_available_asymmetric()
            .await
            .map_err(|error| {
                AppError::from_code(AuthorizeErrorCode::LoadRequestFailed).with_source(error)
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
                        AppError::from_code(AuthorizeErrorCode::LoadRequestFailed)
                            .with_source(error)
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

        Err(AppError::from_code(AuthorizeErrorCode::StoreCodeFailed))
    }

    pub(super) fn sign_implicit_id_token(
        &self,
        input: SignImplicitIdTokenInput<'_>,
    ) -> Result<String, AppError> {
        let mut header = JwsHeader::new();
        header.set_token_type("JWT");
        header.set_key_id(input.key_id);

        let mut payload = JwtPayload::new();
        let now = std::time::SystemTime::now();
        payload.set_issuer(input.issuer.as_str());
        payload.set_subject(Uuid::from(input.user.oid).to_string());
        payload.set_audience(vec![input.audience]);
        payload.set_issued_at(&now);
        payload.set_expires_at(&(now + Duration::from_secs(3600)));
        payload
            .set_claim(JwtClaimNames::AZP, Some(serde_json::json!(input.audience)))
            .map_err(|error| {
                AppError::from_code(AuthorizeErrorCode::SerializeCodeFailed).with_source(error)
            })?;
        payload
            .set_claim(
                JwtClaimNames::AMR,
                Some(serde_json::json!(amr_values(input.acr))),
            )
            .map_err(|error| {
                AppError::from_code(AuthorizeErrorCode::SerializeCodeFailed).with_source(error)
            })?;

        payload
            .set_claim(JwtClaimNames::NONCE, Some(serde_json::json!(input.nonce)))
            .map_err(|error| {
                AppError::from_code(AuthorizeErrorCode::SerializeCodeFailed).with_source(error)
            })?;
        payload
            .set_claim(
                JwtClaimNames::AUTH_TIME,
                Some(serde_json::json!(input.auth_time)),
            )
            .map_err(|error| {
                AppError::from_code(AuthorizeErrorCode::SerializeCodeFailed).with_source(error)
            })?;

        if let Some(acr) = input.acr {
            payload
                .set_claim(JwtClaimNames::ACR, Some(serde_json::json!(acr)))
                .map_err(|error| {
                    AppError::from_code(AuthorizeErrorCode::SerializeCodeFailed).with_source(error)
                })?;
        }

        if let Some(access_token) = input.access_token {
            let at_hash = front_channel_hash(access_token, input.alg).map_err(|error| {
                AppError::from_code(AuthorizeErrorCode::SerializeCodeFailed).with_source(error)
            })?;
            payload
                .set_claim(JwtClaimNames::AT_HASH, Some(serde_json::json!(at_hash)))
                .map_err(|error| {
                    AppError::from_code(AuthorizeErrorCode::SerializeCodeFailed).with_source(error)
                })?;
        }
        if let Some(code) = input.code {
            let c_hash = front_channel_hash(code, input.alg).map_err(|error| {
                AppError::from_code(AuthorizeErrorCode::SerializeCodeFailed).with_source(error)
            })?;
            payload
                .set_claim(JwtClaimNames::C_HASH, Some(serde_json::json!(c_hash)))
                .map_err(|error| {
                    AppError::from_code(AuthorizeErrorCode::SerializeCodeFailed).with_source(error)
                })?;
        }
        if let Some(protected_session_id) = input.protected_session_id {
            payload
                .set_claim(
                    JwtClaimNames::SID,
                    Some(serde_json::json!(protected_session_id)),
                )
                .map_err(|error| {
                    AppError::from_code(AuthorizeErrorCode::SerializeCodeFailed).with_source(error)
                })?;
        }

        let id_token_scope = if input.access_token.is_some() || input.code.is_some() {
            ScopeSet {
                openid: true,
                ..Default::default()
            }
        } else {
            input.scope.clone()
        };
        let mut standard_claims =
            UserInfoClaims::from_user_with_profile_base(input.user, input.issuer.as_str());
        standard_claims.apply_scope_filter_for_id_token(&id_token_scope, input.claims_request);
        let standard_claims_value = serde_json::to_value(standard_claims).map_err(|error| {
            AppError::from_code(AuthorizeErrorCode::SerializeCodeFailed).with_source(error)
        })?;
        if let Some(claims) = standard_claims_value.as_object() {
            for (name, value) in claims {
                if name == JwtClaimNames::SUB {
                    continue;
                }
                payload
                    .set_claim(name, Some(value.clone()))
                    .map_err(|error| {
                        AppError::from_code(AuthorizeErrorCode::SerializeCodeFailed)
                            .with_source(error)
                    })?;
            }
        }

        if input.alg == "none" {
            #[cfg(feature = "allow-none-alg")]
            return Self::sign_unsigned_implicit_id_token(&header, &payload);

            #[cfg(not(feature = "allow-none-alg"))]
            return Err(AppError::from_code(AuthorizeErrorCode::SerializeCodeFailed));
        }

        let signer: Box<dyn josekit::jws::JwsSigner> =
            build_signer_for_alg(input.private_key_pem, input.alg)?;
        jwt::encode_with_signer(&payload, &header, &*signer).map_err(|error| {
            AppError::from_code(AuthorizeErrorCode::SerializeCodeFailed).with_source(error)
        })
    }

    #[cfg(feature = "allow-none-alg")]
    fn sign_unsigned_implicit_id_token(
        header: &JwsHeader,
        payload: &JwtPayload,
    ) -> Result<String, AppError> {
        jwt::encode_unsecured(payload, header).map_err(|error| {
            AppError::from_code(AuthorizeErrorCode::SerializeCodeFailed).with_source(error)
        })
    }

    pub(super) fn sign_implicit_access_token(
        &self,
        input: SignImplicitAccessTokenInput<'_>,
    ) -> Result<String, AppError> {
        let mut header = JwsHeader::new();
        header.set_token_type(JwtTokenType::ACCESS_TOKEN);
        header.set_key_id(input.key_id);

        let mut payload = JwtPayload::new();
        let now = std::time::SystemTime::now();
        payload.set_issuer(input.issuer.as_str());
        payload.set_subject(input.user_oid);
        payload.set_audience(vec![input.audience]);
        payload.set_issued_at(&now);
        payload.set_expires_at(&(now + Duration::from_secs(3600)));
        payload.set_jwt_id(input.token_id);
        payload
            .set_claim(
                JwtClaimNames::CLIENT_ID,
                Some(serde_json::json!(input.client_id)),
            )
            .map_err(|error| {
                AppError::from_code(AuthorizeErrorCode::SerializeCodeFailed).with_source(error)
            })?;
        payload
            .set_claim(JwtClaimNames::SCOPE, Some(serde_json::json!(input.scope)))
            .map_err(|error| {
                AppError::from_code(AuthorizeErrorCode::SerializeCodeFailed).with_source(error)
            })?;
        payload
            .set_claim(
                JwtClaimNames::SID,
                Some(serde_json::json!(input.protected_session_id)),
            )
            .map_err(|error| {
                AppError::from_code(AuthorizeErrorCode::SerializeCodeFailed).with_source(error)
            })?;
        payload
            .set_claim(
                JwtClaimNames::TOKEN_USE,
                Some(serde_json::json!(TokenUseValues::ACCESS_TOKEN)),
            )
            .map_err(|error| {
                AppError::from_code(AuthorizeErrorCode::SerializeCodeFailed).with_source(error)
            })?;
        if let Some(claims_value) = input.claims {
            payload
                .set_claim(
                    "claims",
                    Some(serde_json::to_value(claims_value).map_err(|error| {
                        AppError::from_code(AuthorizeErrorCode::SerializeCodeFailed)
                            .with_source(error)
                    })?),
                )
                .map_err(|error| {
                    AppError::from_code(AuthorizeErrorCode::SerializeCodeFailed).with_source(error)
                })?;
        }

        let signer: Box<dyn josekit::jws::JwsSigner> =
            build_signer_for_alg(input.private_key_pem, input.alg)?;
        jwt::encode_with_signer(&payload, &header, &*signer).map_err(|error| {
            AppError::from_code(AuthorizeErrorCode::SerializeCodeFailed).with_source(error)
        })
    }

    pub(super) async fn encrypt_id_token(
        &self,
        signed_jwt: &str,
        client: &OpenIdConnectClient,
        encryption_alg: &str,
        content_enc: &str,
    ) -> Result<String, AppError> {
        let credential = self
            .credential_repo
            .find_first_encryption_key(client.client().oid)
            .await
            .map_err(|error| {
                AppError::from_code(AuthorizeErrorCode::EncryptionKeyNotFound).with_source(error)
            })?
            .ok_or_else(|| AppError::from_code(AuthorizeErrorCode::EncryptionKeyNotFound))?;

        let public_jwk = match &credential.data {
            OpenIdConnectCredentialData::ClientPublicKey { jwk: Some(jwk), .. } => jwk,
            _ => {
                return Err(AppError::from_code(
                    AuthorizeErrorCode::EncryptionKeyNotFound,
                ));
            }
        };

        encrypt_compact_with_public_jwk(
            signed_jwt.as_bytes(),
            public_jwk,
            encryption_alg,
            content_enc,
        )
        .map_err(|error| {
            AppError::from_code(AuthorizeErrorCode::EncryptionFailed).with_source(error)
        })
    }
}

fn amr_values(acr: Option<&str>) -> Vec<&'static str> {
    match acr {
        Some(identity_domain::auth::ACR_MFA) => vec!["pwd", "otp"],
        _ => vec!["pwd"],
    }
}

fn build_signer_for_alg(
    private_key_pem: &str,
    alg: &str,
) -> Result<Box<dyn josekit::jws::JwsSigner>, AppError> {
    asymmetric_signer_from_pem(alg, private_key_pem.as_bytes()).map_err(|error| {
        AppError::from_code(AuthorizeErrorCode::SerializeCodeFailed).with_source(error)
    })
}
