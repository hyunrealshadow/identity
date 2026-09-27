use josekit::jwt;
use uuid::Uuid;

use super::{TokenRevocationParams, TokenService, resolve_client_id};
use crate::application::error::{AppError, codes::token::TokenErrorCode};
use crate::domain::client_authorization::ClientAuthorizationType;
use crate::domain::key::{JwaSigningAlgorithm, JwkAlgorithm, KeyData};
use crate::domain::openid_connect::{
    TokenEndpointAuthMethod,
    model::claim::{JwtClaimNames, JwtTokenType, TokenUse},
};
use crate::openid_connect::jose::asymmetric_verifier_from_pem;

impl TokenService {
    /// RFC 7009: an unknown token is a successful no-op after client authentication.
    #[tracing::instrument(skip_all, name = "token.revoke")]
    pub async fn revoke_token(&self, params: TokenRevocationParams) -> Result<(), AppError> {
        let client_id = resolve_client_id(
            params.client_id,
            params.client_assertion_type,
            params.client_assertion.as_deref(),
        )?;
        let client = self
            .client_authentication
            .authenticate_client_request(
                &client_id,
                params.client_secret.as_deref(),
                params.client_assertion_type,
                params.client_assertion.as_deref(),
            )
            .await?;
        let method = client
            .metadata()
            .token_endpoint_auth_method
            .unwrap_or(TokenEndpointAuthMethod::ClientSecretBasic);
        let valid_proof = match method {
            TokenEndpointAuthMethod::ClientSecretBasic => {
                params.client_secret_basic
                    && params.client_secret.is_some()
                    && params.client_assertion.is_none()
            }
            TokenEndpointAuthMethod::ClientSecretPost => {
                !params.client_secret_basic
                    && params.client_secret.is_some()
                    && params.client_assertion.is_none()
            }
            TokenEndpointAuthMethod::ClientSecretJwt | TokenEndpointAuthMethod::PrivateKeyJwt => {
                params.client_secret.is_none()
                    && params.client_assertion.is_some()
                    && params.client_assertion_type.is_some()
            }
            TokenEndpointAuthMethod::None => {
                params.client_secret.is_none() && params.client_assertion.is_none()
            }
        };
        if !valid_proof {
            return Err(AppError::from_code(TokenErrorCode::ClientAuthRequired));
        }

        let client_oid = client.client().oid;
        if let Ok(bytes) = self
            .data_protector
            .unprotect("refresh-token", &params.token)
            .await
            && let Ok(oid) = Uuid::from_slice(&bytes)
        {
            let record = self
                .client_authorization_repo
                .find_by_oid(oid)
                .await
                .map_err(|error| {
                    AppError::from_code(TokenErrorCode::RefreshTokenLookupFailed).with_source(error)
                })?;
            if let Some(record) =
                record.filter(|record| record.type_ == ClientAuthorizationType::RefreshToken)
            {
                if record.client_oid != client_oid {
                    return Err(AppError::from_code(
                        TokenErrorCode::RefreshTokenClientMismatch,
                    ));
                }
                self.client_authorization_repo
                    .revoke_refresh_grant_for_client(oid, client_oid, chrono::Utc::now())
                    .await
                    .map_err(|error| {
                        AppError::from_code(TokenErrorCode::RevokeRefreshFailed).with_source(error)
                    })?;
                return Ok(());
            }
        }

        if let Some((oid, token_client_oid)) = self.verified_access_token_oid(&params.token).await?
        {
            let record = self
                .client_authorization_repo
                .find_by_oid(oid)
                .await
                .map_err(|error| {
                    AppError::from_code(TokenErrorCode::RefreshTokenLookupFailed).with_source(error)
                })?;
            if let Some(record) = record.filter(|record| {
                record.type_ == ClientAuthorizationType::AccessToken
                    && record.client_oid == token_client_oid
            }) {
                if record.client_oid != client_oid {
                    return Err(AppError::from_code(
                        TokenErrorCode::RefreshTokenClientMismatch,
                    ));
                }
                self.client_authorization_repo
                    .revoke_access_token_for_client(oid, client_oid, chrono::Utc::now())
                    .await
                    .map_err(|error| {
                        AppError::from_code(TokenErrorCode::RevokeRefreshFailed).with_source(error)
                    })?;
            }
        }
        Ok(())
    }

    async fn verified_access_token_oid(
        &self,
        token: &str,
    ) -> Result<Option<(Uuid, Uuid)>, AppError> {
        let Ok(header) = jwt::decode_header(token) else {
            return Ok(None);
        };
        let Some(alg) = header
            .claim(JwtClaimNames::ALG)
            .and_then(|value| value.as_str())
            .and_then(|value| value.parse::<JwaSigningAlgorithm>().ok())
        else {
            return Ok(None);
        };
        let Some(kid) = header
            .claim(JwtClaimNames::KID)
            .and_then(|value| value.as_str())
            .and_then(|value| Uuid::parse_str(value).ok())
        else {
            return Ok(None);
        };
        let bindings = self.key_jwk_repo.list_active().await.map_err(|error| {
            AppError::from_code(TokenErrorCode::KeyListFailed).with_source(error)
        })?;
        let Some(binding) = bindings.iter().find(|binding| {
            Uuid::from(binding.oid) == kid && binding.algorithm == JwkAlgorithm::Signing(alg)
        }) else {
            return Ok(None);
        };
        let key = self
            .key_repo
            .find_by_oid(binding.key_oid)
            .await
            .map_err(|error| {
                AppError::from_code(TokenErrorCode::KeyListFailed).with_source(error)
            })?;
        let Some(key) = key else {
            return Ok(None);
        };
        let KeyData::Asymmetric(data) = key.data else {
            return Ok(None);
        };
        let Ok(verifier) = asymmetric_verifier_from_pem(alg.as_str(), data.public_key.as_bytes())
        else {
            return Ok(None);
        };
        let Ok((payload, verified_header)) = jwt::decode_with_verifier(token, verifier.as_ref())
        else {
            return Ok(None);
        };
        if !matches!(
            verified_header
                .claim(JwtClaimNames::TYP)
                .and_then(|value| value.as_str()),
            Some(JwtTokenType::ACCESS_TOKEN | JwtTokenType::ACCESS_TOKEN_FULL)
        ) || payload.issuer() != Some(self.provider_service.issuer()?.as_str())
            || payload
                .claim(JwtClaimNames::TOKEN_USE)
                .and_then(|value| value.as_str())
                .and_then(|value| value.parse::<TokenUse>().ok())
                != Some(TokenUse::AccessToken)
        {
            return Ok(None);
        }
        Ok(payload
            .jwt_id()
            .and_then(|value| Uuid::parse_str(value).ok())
            .zip(
                payload
                    .claim(JwtClaimNames::CLIENT_ID)
                    .and_then(|value| value.as_str())
                    .and_then(|value| Uuid::parse_str(value).ok()),
            ))
    }
}
