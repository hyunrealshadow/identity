use std::sync::Arc;

use crate::{
    application::{
        error::{
            AppError,
            codes::{common::CommonErrorCode, openid_connect::OpenIdConnectErrorCode},
        },
        key::asymmetric::AsymmetricKeyService,
        openid_connect::{dto::UserInfoClaims, provider::OpenIdProviderService},
    },
    domain::{
        client_authorization::{ClientAuthorizationRepository, ClientAuthorizationType},
        key::KeyData,
        openid_connect::{
            ScopeSet,
            model::claim::{JwtClaimNames, JwtTokenType, TokenUseValues},
        },
        user::{UserOid, repository::UserRepository},
    },
};
use josekit::{
    jws::{ES256, JwsHeader, RS256},
    jwt,
};
use uuid::Uuid;

pub struct UserInfoService {
    user_repo: Arc<dyn UserRepository>,
    client_authorization_repo: Arc<dyn ClientAuthorizationRepository>,
    key_service: Arc<AsymmetricKeyService>,
    provider_service: Arc<OpenIdProviderService>,
}

pub struct TokenClaims {
    pub user_oid: UserOid,
    pub scope: ScopeSet,
    pub claims: Option<serde_json::Value>,
}

impl UserInfoService {
    pub fn new(
        user_repo: Arc<dyn UserRepository>,
        client_authorization_repo: Arc<dyn ClientAuthorizationRepository>,
        key_service: Arc<AsymmetricKeyService>,
        provider_service: Arc<OpenIdProviderService>,
    ) -> Self {
        Self {
            user_repo,
            client_authorization_repo,
            key_service,
            provider_service,
        }
    }

    pub async fn get_user_info(
        &self,
        user_oid: UserOid,
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
        claims.apply_scope_filter(scope, claims_request);
        Ok(claims)
    }

    pub async fn validate_access_token(&self, raw_token: &str) -> Result<TokenClaims, AppError> {
        let keys = self.key_service.list_available().await?;

        let mut verified_result = None;
        for key in keys {
            if let Ok(result) = self.verify_jwt_with_key(raw_token, &key) {
                verified_result = Some(result);
                break;
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
        if let Some(exp) = payload.claim(JwtClaimNames::EXP).and_then(|v| v.as_i64()) {
            if exp <= now {
                return Err(AppError::from_code(OpenIdConnectErrorCode::InvalidToken));
            }
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
            scope,
            claims,
        })
    }

    fn verify_jwt_with_key(
        &self,
        token: &str,
        key: &crate::domain::key::Key,
    ) -> Result<(josekit::jwt::JwtPayload, JwsHeader), AppError> {
        let public_key = match &key.data {
            KeyData::Asymmetric(data) => data.public_key.as_bytes(),
            _ => return Err(AppError::from_code(CommonErrorCode::InternalError)),
        };

        let result = RS256
            .verifier_from_pem(public_key)
            .ok()
            .and_then(|v| jwt::decode_with_verifier(token, &v).ok())
            .or_else(|| {
                ES256
                    .verifier_from_pem(public_key)
                    .ok()
                    .and_then(|v| jwt::decode_with_verifier(token, &v).ok())
            });

        let (payload, header) =
            result.ok_or_else(|| AppError::from_code(OpenIdConnectErrorCode::InvalidToken))?;

        Ok((payload, header))
    }
}
