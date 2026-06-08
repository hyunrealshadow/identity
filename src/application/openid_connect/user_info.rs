use std::sync::Arc;

use crate::{
    application::{
        error::{
            AppError,
            codes::{common::CommonErrorCode, openid_connect::OpenIdConnectErrorCode},
        },
        key::asymmetric::AsymmetricKeyService,
        openid_connect::{
            dto::UserInfoClaims,
            jose::{
                asymmetric_signer_from_pem, asymmetric_verifier_from_pem,
                encrypt_compact_with_public_jwk,
            },
            provider::OpenIdProviderService,
        },
    },
    domain::{
        client_authorization::{ClientAuthorizationRepository, ClientAuthorizationType},
        key::KeyData,
        openid_connect::{
            OpenIdConnectClientRepository, OpenIdConnectCredentialRepository, ScopeSet,
            model::claim::{JwtClaimNames, JwtTokenType, TokenUseValues},
            model::credential::OpenIdConnectCredentialData,
        },
        user::{UserOid, repository::UserRepository},
    },
};
use josekit::{
    jws::{JwsHeader, JwsSigner},
    jwt,
};
use uuid::Uuid;

pub struct UserInfoService {
    user_repo: Arc<dyn UserRepository>,
    client_repo: Arc<dyn OpenIdConnectClientRepository>,
    credential_repo: Arc<dyn OpenIdConnectCredentialRepository>,
    client_authorization_repo: Arc<dyn ClientAuthorizationRepository>,
    key_service: Arc<AsymmetricKeyService>,
    provider_service: Arc<OpenIdProviderService>,
}

pub struct TokenClaims {
    pub user_oid: UserOid,
    pub client_oid: Uuid,
    pub scope: ScopeSet,
    pub claims: Option<serde_json::Value>,
}

impl UserInfoService {
    pub fn new(
        user_repo: Arc<dyn UserRepository>,
        client_repo: Arc<dyn OpenIdConnectClientRepository>,
        credential_repo: Arc<dyn OpenIdConnectCredentialRepository>,
        client_authorization_repo: Arc<dyn ClientAuthorizationRepository>,
        key_service: Arc<AsymmetricKeyService>,
        provider_service: Arc<OpenIdProviderService>,
    ) -> Self {
        Self {
            user_repo,
            client_repo,
            credential_repo,
            client_authorization_repo,
            key_service,
            provider_service,
        }
    }

    pub async fn get_user_info(
        &self,
        user_oid: UserOid,
        client_oid: Uuid,
        scope: &ScopeSet,
        claims_request: Option<&serde_json::Value>,
    ) -> Result<UserInfoClaims, AppError> {
        let user = self
            .user_repo
            .find_by_oid(user_oid)
            .await?
            .ok_or_else(|| AppError::from_code(OpenIdConnectErrorCode::UserNotFound))?;

        let issuer = self.provider_service.issuer()?;
        let mut claims = UserInfoClaims::from_user_with_profile_base(&user, issuer.as_str());
        let client = self
            .client_repo
            .find_by_oid(client_oid)
            .await
            .map_err(|error| {
                AppError::from_code(OpenIdConnectErrorCode::InvalidToken).with_source(error)
            })?
            .ok_or_else(|| AppError::from_code(OpenIdConnectErrorCode::InvalidToken))?;
        claims.sub = client.subject_identifier(Uuid::from(user.oid), &issuer);
        claims.apply_scope_filter(scope, claims_request);
        Ok(claims)
    }

    pub async fn sign_user_info(
        &self,
        client_oid: Uuid,
        claims: &UserInfoClaims,
    ) -> Result<Option<String>, AppError> {
        let client = self
            .client_repo
            .find_by_oid(client_oid)
            .await
            .map_err(|error| {
                AppError::from_code(OpenIdConnectErrorCode::InvalidToken).with_source(error)
            })?
            .ok_or_else(|| AppError::from_code(OpenIdConnectErrorCode::InvalidToken))?;

        let Some(alg) = client.metadata().userinfo_signed_response_alg.as_deref() else {
            return Ok(None);
        };
        if alg == "none" {
            return Err(AppError::from_code(CommonErrorCode::InternalError));
        }

        let (key_id, private_key) = self.load_signing_key_for_alg(alg).await?;
        let mut header = JwsHeader::new();
        header.set_token_type("JWT");
        header.set_key_id(&key_id);

        let mut payload = user_info_payload(claims)?;
        let issuer = self.provider_service.issuer()?;
        let now = std::time::SystemTime::now();
        payload.set_issuer(issuer.as_str());
        payload.set_audience(vec![client.client().oid.to_string()]);
        payload.set_issued_at(&now);

        let signer = build_user_info_signer(&private_key, alg)?;
        let token = jwt::encode_with_signer(&payload, &header, &*signer).map_err(|error| {
            AppError::from_code(CommonErrorCode::InternalError).with_source(error)
        })?;

        Ok(Some(token))
    }

    pub async fn encrypt_user_info(
        &self,
        client_oid: Uuid,
        claims: &UserInfoClaims,
    ) -> Result<Option<String>, AppError> {
        let client = self
            .client_repo
            .find_by_oid(client_oid)
            .await
            .map_err(|error| {
                AppError::from_code(OpenIdConnectErrorCode::InvalidToken).with_source(error)
            })?
            .ok_or_else(|| AppError::from_code(OpenIdConnectErrorCode::InvalidToken))?;

        let Some(alg) = client.metadata().userinfo_encrypted_response_alg.as_deref() else {
            return Ok(None);
        };
        let enc = client
            .metadata()
            .userinfo_encrypted_response_enc
            .as_deref()
            .unwrap_or("A128CBC-HS256");

        let credential = self
            .credential_repo
            .find_first_encryption_key(client.client().oid)
            .await
            .map_err(|error| {
                AppError::from_code(CommonErrorCode::InternalError).with_source(error)
            })?
            .ok_or_else(|| AppError::from_code(CommonErrorCode::InternalError))?;

        let public_jwk = match &credential.data {
            OpenIdConnectCredentialData::ClientPublicKey { jwk: Some(jwk), .. } => jwk,
            _ => return Err(AppError::from_code(CommonErrorCode::InternalError)),
        };

        let json_body = serde_json::to_string(claims).map_err(|error| {
            AppError::from_code(CommonErrorCode::InternalError).with_source(error)
        })?;
        let encrypted = encrypt_compact_with_public_jwk(json_body.as_bytes(), public_jwk, alg, enc)
            .map_err(|error| {
                AppError::from_code(CommonErrorCode::InternalError).with_source(error)
            })?;

        Ok(Some(encrypted))
    }

    pub async fn validate_access_token(&self, raw_token: &str) -> Result<TokenClaims, AppError> {
        let header = jwt::decode_header(raw_token).map_err(|error| {
            AppError::from_code(OpenIdConnectErrorCode::InvalidToken).with_source(error)
        })?;

        let alg = header
            .claim(JwtClaimNames::ALG)
            .and_then(|v| v.as_str())
            .ok_or_else(|| AppError::from_code(OpenIdConnectErrorCode::InvalidToken))?;

        let kid = header
            .claim(JwtClaimNames::KID)
            .and_then(|v| v.as_str())
            .map(|s| s.to_owned());
        let keys = self.key_service.list_available().await?;

        let mut verified_result = None;

        if let Some(kid_str) = kid.as_deref()
            && let Ok(kid_uuid) = Uuid::parse_str(kid_str)
            && let Some(key) = keys.iter().find(|k| Uuid::from(k.oid) == kid_uuid)
            && let Ok(result) = self.verify_jwt_with_key_and_alg(raw_token, key, alg)
        {
            verified_result = Some(result);
        }

        if verified_result.is_none() {
            for key in &keys {
                if let Ok(result) = self.verify_jwt_with_key_and_alg(raw_token, key, alg) {
                    verified_result = Some(result);
                    break;
                }
            }
        }

        let (payload, header) = verified_result
            .ok_or_else(|| AppError::from_code(OpenIdConnectErrorCode::InvalidToken))?;

        let typ = header
            .claim(JwtClaimNames::TYP)
            .and_then(|v| v.as_str())
            .ok_or_else(|| AppError::from_code(OpenIdConnectErrorCode::InvalidToken))?;
        if typ != JwtTokenType::ACCESS_TOKEN && typ != JwtTokenType::ACCESS_TOKEN_FULL {
            return Err(AppError::from_code(OpenIdConnectErrorCode::InvalidToken));
        }

        let now = chrono::Utc::now().timestamp();
        if let Some(exp) = payload.claim(JwtClaimNames::EXP).and_then(|v| v.as_i64())
            && exp <= now
        {
            return Err(AppError::from_code(OpenIdConnectErrorCode::InvalidToken));
        }

        let sub = payload
            .claim(JwtClaimNames::SUB)
            .and_then(|v| v.as_str())
            .ok_or_else(|| AppError::from_code(OpenIdConnectErrorCode::InvalidToken))?;

        let user_oid = Uuid::parse_str(sub)
            .map_err(|_| AppError::from_code(OpenIdConnectErrorCode::InvalidToken))?;

        let token_use = payload
            .claim(JwtClaimNames::TOKEN_USE)
            .and_then(|v| v.as_str())
            .ok_or_else(|| AppError::from_code(OpenIdConnectErrorCode::InvalidToken))?;

        if token_use != TokenUseValues::ACCESS_TOKEN {
            return Err(AppError::from_code(OpenIdConnectErrorCode::InvalidToken));
        }

        let jti = payload
            .jwt_id()
            .ok_or_else(|| AppError::from_code(OpenIdConnectErrorCode::InvalidToken))?;
        let access_token_oid = Uuid::parse_str(jti)
            .map_err(|_| AppError::from_code(OpenIdConnectErrorCode::InvalidToken))?;
        let access_token_record = self
            .client_authorization_repo
            .find_by_oid(access_token_oid)
            .await
            .map_err(|error| {
                AppError::from_code(OpenIdConnectErrorCode::InvalidToken).with_source(error)
            })?
            .ok_or_else(|| AppError::from_code(OpenIdConnectErrorCode::InvalidToken))?;
        if access_token_record.type_ != ClientAuthorizationType::AccessToken
            || access_token_record.revoked_at.is_some()
            || access_token_record.expires_at <= chrono::Utc::now()
        {
            return Err(AppError::from_code(OpenIdConnectErrorCode::InvalidToken));
        }

        let scope_str = payload
            .claim(JwtClaimNames::SCOPE)
            .and_then(|v| v.as_str())
            .unwrap_or("");
        let scope = ScopeSet::parse(scope_str)
            .map_err(|_| AppError::from_code(OpenIdConnectErrorCode::InvalidToken))?;

        if !scope.openid {
            return Err(AppError::from_code(
                OpenIdConnectErrorCode::InsufficientScope,
            ));
        }

        let claims = payload.claim("claims").cloned();

        Ok(TokenClaims {
            user_oid: UserOid::from(user_oid),
            client_oid: access_token_record.client_oid,
            scope,
            claims,
        })
    }

    fn verify_jwt_with_key_and_alg(
        &self,
        token: &str,
        key: &identity_domain::key::Key,
        alg: &str,
    ) -> Result<(jwt::JwtPayload, JwsHeader), AppError> {
        let public_key = match &key.data {
            KeyData::Asymmetric(data) => data.public_key.as_bytes(),
            _ => return Err(AppError::from_code(CommonErrorCode::InternalError)),
        };

        let verifier = asymmetric_verifier_from_pem(alg, public_key)
            .map_err(|_| AppError::from_code(OpenIdConnectErrorCode::InvalidToken))?;
        let (payload, header) = jwt::decode_with_verifier(token, verifier.as_ref())
            .map_err(|_| AppError::from_code(OpenIdConnectErrorCode::InvalidToken))?;

        Ok((payload, header))
    }

    async fn load_signing_key_for_alg(&self, alg: &str) -> Result<(String, String), AppError> {
        let keys = self.key_service.list_available().await?;
        let bindings = self.key_service.list_available_jwks().await?;

        for binding in bindings.iter().filter(|binding| binding.algorithm == alg) {
            let Some(key) = keys.iter().find(|key| key.oid == binding.key_oid) else {
                continue;
            };
            let KeyData::Asymmetric(data) = &key.data else {
                continue;
            };
            let key_id = binding
                .jwk
                .key_id()
                .map(str::to_owned)
                .unwrap_or_else(|| Uuid::from(binding.oid).to_string());
            return Ok((key_id, data.private_key.clone()));
        }

        for key in keys {
            let KeyData::Asymmetric(data) = key.data else {
                continue;
            };
            if build_user_info_signer(&data.private_key, alg).is_ok() {
                return Ok((Uuid::from(key.oid).to_string(), data.private_key));
            }
        }

        Err(AppError::from_code(CommonErrorCode::InternalError))
    }
}

fn user_info_payload(claims: &UserInfoClaims) -> Result<jwt::JwtPayload, AppError> {
    let value = serde_json::to_value(claims)
        .map_err(|error| AppError::from_code(CommonErrorCode::InternalError).with_source(error))?;
    let object = value
        .as_object()
        .ok_or_else(|| AppError::from_code(CommonErrorCode::InternalError))?;
    let mut payload = jwt::JwtPayload::new();
    for (name, value) in object {
        payload
            .set_claim(name, Some(value.clone()))
            .map_err(|error| {
                AppError::from_code(CommonErrorCode::InternalError).with_source(error)
            })?;
    }
    Ok(payload)
}

fn build_user_info_signer(
    private_key_pem: &str,
    alg: &str,
) -> Result<Box<dyn JwsSigner>, AppError> {
    asymmetric_signer_from_pem(alg, private_key_pem.as_bytes())
        .map_err(|error| AppError::from_code(CommonErrorCode::InternalError).with_source(error))
}
