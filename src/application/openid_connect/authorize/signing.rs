use super::*;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use josekit::{
    jws::{
        ES256, ES256K, ES384, ES512, EdDSA, JwsHeader, PS256, PS384, PS512, RS256, RS384, RS512,
    },
    jwt,
    jwt::JwtPayload,
};
use sha2::{Digest, Sha256, Sha384, Sha512};
use std::time::Duration;
use uuid::Uuid;

use crate::application::error::codes::common::CommonErrorCode;
use crate::application::openid_connect::dto::UserInfoClaims;
use crate::domain::openid_connect::model::claim::{JwtTokenType, TokenUseValues};

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
                return Ok((
                    Uuid::from(key.oid).to_string(),
                    data.private_key.clone(),
                    alg.as_str().to_owned(),
                ));
            }
        }

        Err(AppError::from_code(AuthorizeErrorCode::StoreCodeFailed))
    }

    pub(super) fn sign_implicit_id_token(
        &self,
        key_id: &str,
        private_key_pem: &str,
        alg: &str,
        issuer: &Url,
        audience: &str,
        user: &crate::domain::user::User,
        nonce: &str,
        auth_time: i64,
        acr: Option<&str>,
        access_token: Option<&str>,
        scope: &ScopeSet,
        claims_request: Option<&serde_json::Value>,
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
        payload.set_expires_at(&(now + Duration::from_secs(3600)));

        payload
            .set_claim(JwtClaimNames::NONCE, Some(serde_json::json!(nonce)))
            .map_err(|error| {
                AppError::from_code(AuthorizeErrorCode::SerializeCodeFailed).with_source(error)
            })?;
        payload
            .set_claim(JwtClaimNames::AUTH_TIME, Some(serde_json::json!(auth_time)))
            .map_err(|error| {
                AppError::from_code(AuthorizeErrorCode::SerializeCodeFailed).with_source(error)
            })?;

        if let Some(acr) = acr {
            payload
                .set_claim(JwtClaimNames::ACR, Some(serde_json::json!(acr)))
                .map_err(|error| {
                    AppError::from_code(AuthorizeErrorCode::SerializeCodeFailed).with_source(error)
                })?;
        }

        if let Some(access_token) = access_token {
            let at_hash = compute_at_hash_for_alg(access_token, alg);
            payload
                .set_claim(JwtClaimNames::AT_HASH, Some(serde_json::json!(at_hash)))
                .map_err(|error| {
                    AppError::from_code(AuthorizeErrorCode::SerializeCodeFailed).with_source(error)
                })?;
        }

        let id_token_scope = if access_token.is_some() {
            ScopeSet {
                openid: true,
                ..Default::default()
            }
        } else {
            scope.clone()
        };
        let mut standard_claims =
            UserInfoClaims::from_user_with_profile_base(user, issuer.as_str());
        standard_claims.apply_scope_filter_for_id_token(&id_token_scope, claims_request);
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

        let signer: Box<dyn josekit::jws::JwsSigner> = build_signer_for_alg(private_key_pem, alg)?;
        jwt::encode_with_signer(&payload, &header, &*signer).map_err(|error| {
            AppError::from_code(AuthorizeErrorCode::SerializeCodeFailed).with_source(error)
        })
    }

    pub(super) fn sign_implicit_access_token(
        &self,
        key_id: &str,
        private_key_pem: &str,
        alg: &str,
        issuer: &Url,
        audience: &str,
        client_id: &str,
        user_oid: &str,
        session_oid: &str,
        scope: &str,
        token_id: &str,
        claims: Option<&serde_json::Value>,
    ) -> Result<String, AppError> {
        let mut header = JwsHeader::new();
        header.set_token_type(JwtTokenType::ACCESS_TOKEN);
        header.set_key_id(key_id);

        let mut payload = JwtPayload::new();
        let now = std::time::SystemTime::now();
        payload.set_issuer(issuer.as_str());
        payload.set_subject(user_oid);
        payload.set_audience(vec![audience]);
        payload.set_issued_at(&now);
        payload.set_expires_at(&(now + Duration::from_secs(3600)));
        payload.set_jwt_id(token_id);
        payload
            .set_claim(JwtClaimNames::CLIENT_ID, Some(serde_json::json!(client_id)))
            .map_err(|error| {
                AppError::from_code(AuthorizeErrorCode::SerializeCodeFailed).with_source(error)
            })?;
        payload
            .set_claim(JwtClaimNames::SCOPE, Some(serde_json::json!(scope)))
            .map_err(|error| {
                AppError::from_code(AuthorizeErrorCode::SerializeCodeFailed).with_source(error)
            })?;
        payload
            .set_claim(JwtClaimNames::SID, Some(serde_json::json!(session_oid)))
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
        if let Some(claims_value) = claims {
            payload
                .set_claim("claims", Some(claims_value.clone()))
                .map_err(|error| {
                    AppError::from_code(AuthorizeErrorCode::SerializeCodeFailed).with_source(error)
                })?;
        }

        let signer: Box<dyn josekit::jws::JwsSigner> = build_signer_for_alg(private_key_pem, alg)?;
        jwt::encode_with_signer(&payload, &header, &*signer).map_err(|error| {
            AppError::from_code(AuthorizeErrorCode::SerializeCodeFailed).with_source(error)
        })
    }
}

fn build_signer_for_alg(
    private_key_pem: &str,
    alg: &str,
) -> Result<Box<dyn josekit::jws::JwsSigner>, AppError> {
    let jwa: JwaSigningAlgorithm = alg
        .parse()
        .map_err(|_| AppError::from_code(CommonErrorCode::InternalError))?;
    let pem = private_key_pem.as_bytes();
    let err =
        |e: josekit::JoseError| AppError::from_code(CommonErrorCode::InternalError).with_source(e);
    match jwa {
        JwaSigningAlgorithm::Rs256 => Ok(Box::new(RS256.signer_from_pem(pem).map_err(err)?)),
        JwaSigningAlgorithm::Rs384 => Ok(Box::new(RS384.signer_from_pem(pem).map_err(err)?)),
        JwaSigningAlgorithm::Rs512 => Ok(Box::new(RS512.signer_from_pem(pem).map_err(err)?)),
        JwaSigningAlgorithm::Ps256 => Ok(Box::new(PS256.signer_from_pem(pem).map_err(err)?)),
        JwaSigningAlgorithm::Ps384 => Ok(Box::new(PS384.signer_from_pem(pem).map_err(err)?)),
        JwaSigningAlgorithm::Ps512 => Ok(Box::new(PS512.signer_from_pem(pem).map_err(err)?)),
        JwaSigningAlgorithm::Es256 => Ok(Box::new(ES256.signer_from_pem(pem).map_err(err)?)),
        JwaSigningAlgorithm::Es384 => Ok(Box::new(ES384.signer_from_pem(pem).map_err(err)?)),
        JwaSigningAlgorithm::Es512 => Ok(Box::new(ES512.signer_from_pem(pem).map_err(err)?)),
        JwaSigningAlgorithm::Es256k => Ok(Box::new(ES256K.signer_from_pem(pem).map_err(err)?)),
        JwaSigningAlgorithm::EdDsa => Ok(Box::new(EdDSA.signer_from_pem(pem).map_err(err)?)),
    }
}

fn compute_at_hash_for_alg(access_token: &str, alg: &str) -> String {
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
