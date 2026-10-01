use chrono::Utc;
use serde_json::{Value, json};
use uuid::Uuid;

use super::{TokenIntrospectionParams, TokenService, resolve_client_id};
use crate::domain::client_authorization::{ClientAuthorizationData, ClientAuthorizationType};
use crate::error::{AppError, codes::token::TokenErrorCode};

impl TokenService {
    /// RFC 7662. Disclosure is restricted to the authenticated issuing client.
    /// A hint is intentionally ignored: both token formats are always checked.
    #[tracing::instrument(skip_all, name = "token.introspect")]
    pub async fn introspect_token(
        &self,
        params: TokenIntrospectionParams,
    ) -> Result<Value, AppError> {
        if params.client_secret.is_none() && params.client_assertion.is_none() {
            return Err(AppError::from_code(TokenErrorCode::ClientAuthRequired));
        }
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
                params.client_secret_basic,
                params.client_assertion_type,
                params.client_assertion.as_deref(),
            )
            .await?;
        let mut access = false;
        let mut jwt_payload = None;
        let oid = if let Ok(bytes) = self
            .data_protector
            .unprotect("refresh-token", &params.token)
            .await
            && let Ok(oid) = Uuid::from_slice(&bytes)
        {
            oid
        } else if let Some(payload) = self.verified_access_token_payload(&params.token).await? {
            if crate::openid_connect::jwt_checks::validate_required_exp_and_optional_window(
                &payload,
                Utc::now().timestamp(),
            )
            .is_err()
            {
                return Ok(json!({"active": false}));
            }
            let owner = payload
                .claim("client_id")
                .and_then(Value::as_str)
                .and_then(|id| Uuid::parse_str(id).ok());
            let oid = payload.jwt_id().and_then(|id| Uuid::parse_str(id).ok());
            if owner != Some(client.client().oid) || oid.is_none() {
                return Ok(json!({"active": false}));
            }
            access = true;
            jwt_payload = Some(payload);
            oid.unwrap()
        } else {
            return Ok(json!({"active": false}));
        };
        let record = self
            .client_authorization_repo
            .find_by_oid(oid)
            .await
            .map_err(|error| {
                AppError::from_code(TokenErrorCode::RefreshTokenLookupFailed).with_source(error)
            })?;
        let Some(record) = record else {
            return Ok(json!({"active": false}));
        };
        let now = Utc::now();
        if record.client_oid != client.client().oid
            || record.revoked_at.is_some()
            || record.expires_at <= now
            || record.created_at > now
            || (access && record.type_ != ClientAuthorizationType::AccessToken)
            || (!access
                && (record.type_ != ClientAuthorizationType::RefreshToken
                    || record.completed_at.is_some()))
        {
            return Ok(json!({"active": false}));
        }
        let (scope, subject, session, device) = match &record.data {
            ClientAuthorizationData::AccessToken(data) if access => (
                &data.scope,
                &data.user_oid,
                data.session_oid,
                data.device_authorization_oid.as_deref(),
            ),
            ClientAuthorizationData::RefreshToken(data) if !access => (
                &data.scope,
                &data.user_oid,
                data.session_oid,
                data.device_authorization_oid.as_deref(),
            ),
            _ => return Ok(json!({"active": false})),
        };
        if let Some(device) = device {
            let Ok(device) = Uuid::parse_str(device) else {
                return Ok(json!({"active": false}));
            };
            let active = self
                .device_repo
                .find_device_authorization_by_oid(device)
                .await
                .map_err(|error| {
                    AppError::from_code(TokenErrorCode::DeviceRelationLookupFailed)
                        .with_source(error)
                })?
                .is_some_and(|relation| relation.revoked_at.is_none() && relation.expires_at > now);
            if !active {
                return Ok(json!({"active": false}));
            }
        }
        if let (Some(repo), Some(session)) = (&self.session_repo, session) {
            let active = repo
                .find_by_oid(session)
                .await
                .map_err(|error| {
                    AppError::from_code(TokenErrorCode::RefreshTokenLookupFailed).with_source(error)
                })?
                .is_some_and(|session| {
                    session.revoked_at.is_none()
                        && session.status == crate::domain::auth::SessionStatus::ACTIVE
                        && session.expires_at.is_none_or(|expiry| expiry > now)
                        && session.user_oid.to_string() == *subject
                });
            if !active {
                return Ok(json!({"active": false}));
            }
        }
        let mut response = json!({
            "active": true, "scope": scope, "client_id": record.client_oid.to_string(),
            "sub": subject, "iss": self.provider_service.issuer()?.as_str(),
            "exp": record.expires_at.timestamp(), "iat": record.created_at.timestamp(),
            "jti": record.oid.to_string()
        });
        if access {
            response["token_type"] = json!("Bearer");
        }
        if let Some(payload) = jwt_payload {
            for name in ["sub", "aud", "exp", "iat", "nbf"] {
                if let Some(value) = payload.claim(name) {
                    response[name] = value.clone();
                }
            }
        }
        Ok(response)
    }
}
