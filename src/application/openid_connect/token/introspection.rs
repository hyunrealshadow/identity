use chrono::Utc;
use identity_domain::{
    client_authorization::{
        AccessTokenPrincipal, ClientAuthorizationData, ClientAuthorizationType,
    },
    openid_connect::{ScopeSet, resource::valid_resource_uri},
    user::UserOid,
};
use serde_json::{Value, json};
use uuid::Uuid;

use super::{TokenIntrospectionParams, TokenService, resolve_client_id};
use crate::{
    domain::auth::SessionStatus,
    error::{AppError, codes::token::TokenErrorCode},
    openid_connect::{
        jwt_checks::validate_required_exp_and_optional_window,
        management::{ManagementLivePorts, validate_management_authorization},
        rbac as shared,
    },
};

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
            if validate_required_exp_and_optional_window(&payload, Utc::now().timestamp()).is_err()
            {
                return Ok(json!({"active": false}));
            }
            let owner = payload
                .claim("client_id")
                .and_then(Value::as_str)
                .and_then(|id| {
                    identity_domain::openid_connect::identifier::parse_client_id(id).ok()
                });
            let oid = payload.jwt_id().and_then(|id| {
                identity_domain::openid_connect::identifier::parse_access_token_id(id).ok()
            });
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
            .map_err(AppError::map_source(
                TokenErrorCode::RefreshTokenLookupFailed,
            ))?;
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
        let (scope, subject, session, device, issuance, principal, user_oid) = match &record.data {
            ClientAuthorizationData::AccessToken(data) if access => {
                let (subject, user_oid) = match data.principal {
                    AccessTokenPrincipal::User => {
                        let Some(user_oid) = &data.user_oid else {
                            return Ok(json!({"active": false}));
                        };
                        let Some(parsed) = Uuid::parse_str(user_oid).ok() else {
                            return Ok(json!({"active": false}));
                        };
                        (
                            identity_domain::openid_connect::identifier::user_subject(parsed),
                            Some(parsed),
                        )
                    }
                    AccessTokenPrincipal::Client => {
                        // Machine tokens never expose a user subject or session.
                        if data.user_oid.is_some()
                            || data.session_oid.is_some()
                            || data.protected_session_id.is_some()
                        {
                            return Ok(json!({"active": false}));
                        }
                        (
                            identity_domain::openid_connect::identifier::client_id(
                                record.client_oid,
                            ),
                            None,
                        )
                    }
                };
                (
                    &data.scope,
                    subject,
                    data.session_oid,
                    data.device_authorization_oid.as_deref(),
                    data.management.as_ref(),
                    data.principal,
                    user_oid,
                )
            }
            ClientAuthorizationData::RefreshToken(data) if !access => {
                let Some(user_oid) = Uuid::parse_str(&data.user_oid).ok() else {
                    return Ok(json!({"active": false}));
                };
                (
                    &data.scope,
                    identity_domain::openid_connect::identifier::user_subject(user_oid),
                    data.session_oid,
                    data.device_authorization_oid.as_deref(),
                    data.management.as_ref(),
                    AccessTokenPrincipal::User,
                    Some(user_oid),
                )
            }
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
                .map_err(AppError::map_source(
                    TokenErrorCode::DeviceRelationLookupFailed,
                ))?
                .is_some_and(|relation| relation.revoked_at.is_none() && relation.expires_at > now);
            if !active {
                return Ok(json!({"active": false}));
            }
        }
        if let (Some(repo), Some(session)) = (&self.session_repo, session) {
            let active = repo
                .find_by_oid(session)
                .await
                .map_err(AppError::map_source(
                    TokenErrorCode::RefreshTokenLookupFailed,
                ))?
                .is_some_and(|session| {
                    session.revoked_at.is_none()
                        && session.status == SessionStatus::ACTIVE
                        && session.expires_at.is_none_or(|expiry| expiry > now)
                        && Some(Uuid::from(session.user_oid)) == user_oid
                });
            if !active {
                return Ok(json!({"active": false}));
            }
        }
        if let Some(user_oid) = user_oid {
            let user = self
                .user_repo
                .find_by_oid(UserOid(user_oid))
                .await
                .map_err(AppError::map_source(
                    TokenErrorCode::RefreshTokenLookupFailed,
                ))?;
            if !user.is_some_and(|user| user.enabled && !user.locked) {
                return Ok(json!({"active": false}));
            }
        }
        if principal == AccessTokenPrincipal::User && session.is_none() && device.is_none() {
            return Ok(json!({"active": false}));
        }

        let scope_set = match ScopeSet::parse(scope) {
            Ok(scope_set) => scope_set,
            Err(_) => return Ok(json!({"active": false})),
        };
        let persisted_management = shared::management_snapshot(issuance);
        let persisted_business = shared::business_snapshot(issuance);
        if principal == AccessTokenPrincipal::Client
            && scope_set.has_management_scopes()
            && persisted_business.is_none()
        {
            return Ok(json!({"active": false}));
        }
        let management_requested = persisted_management.is_some()
            || (principal == AccessTokenPrincipal::User && scope_set.has_management_scopes());
        if management_requested {
            let Some(persisted) = persisted_management else {
                return Ok(json!({"active": false}));
            };
            let live_client = self
                .client_repo
                .find_by_oid(client.client().oid)
                .await
                .map_err(AppError::map_source(TokenErrorCode::ClientLookupFailed))?;
            let Some(live_client) = live_client else {
                return Ok(json!({"active": false}));
            };
            if validate_management_authorization(
                ManagementLivePorts {
                    binding_repo: self.management_authority_repo.as_ref(),
                    provider_service: &self.provider_service,
                },
                &live_client,
                persisted,
                scope,
                &scope_set,
                principal,
            )
            .await
            .is_err()
            {
                return Ok(json!({"active": false}));
            }
        }

        let audience = if let Some(payload) = jwt_payload.as_ref() {
            payload
                .audience()
                .unwrap_or_default()
                .into_iter()
                .map(str::to_owned)
                .collect::<Vec<_>>()
        } else {
            match &record.data {
                ClientAuthorizationData::RefreshToken(data) => data.resources.clone(),
                _ => Vec::new(),
            }
        };
        let resource_audience = audience
            .iter()
            .filter(|uri| valid_resource_uri(uri))
            .cloned()
            .collect::<Vec<_>>();
        let resource_is_rbac = !resource_audience.is_empty()
            && self
                .provider_service
                .has_rbac_resource(&resource_audience)
                .await
                .map_err(AppError::map_source(TokenErrorCode::ClientLookupFailed))?;
        if let Some(persisted) = persisted_business {
            let live_client = self
                .client_repo
                .find_by_oid(client.client().oid)
                .await
                .map_err(AppError::map_source(TokenErrorCode::ClientLookupFailed))?;
            let Some(live_client) = live_client else {
                return Ok(json!({"active": false}));
            };
            if shared::validate_business_authorization(
                shared::BusinessLivePorts {
                    repository: self.rbac_authorization_repo.as_ref(),
                    provider_service: &self.provider_service,
                },
                shared::BusinessTokenAuthorization {
                    live_client: &live_client,
                    persisted,
                    persisted_scope: scope,
                    scope: &scope_set,
                    principal,
                    subject_user_oid: user_oid.map(UserOid),
                    audience: &audience,
                },
            )
            .await
            .is_err()
            {
                return Ok(json!({"active": false}));
            }
        } else if resource_is_rbac {
            // A legacy token for a resource that now uses RBAC has no original
            // business snapshot and must not remain active.
            return Ok(json!({"active": false}));
        }
        let mut response = json!({
            "active": true, "scope": scope, "client_id": identity_domain::openid_connect::identifier::client_id(record.client_oid),
            "sub": subject, "iss": self.provider_service.issuer()?.as_str(),
            "exp": record.expires_at.timestamp(), "iat": record.created_at.timestamp(),
            "jti": identity_domain::openid_connect::identifier::access_token_id(record.oid)
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
