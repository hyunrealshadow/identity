use chrono::{DateTime, Duration, Utc};
use identity_domain::{
    client_authorization::ClientAuthenticationMode,
    openid_connect::{API_RESOURCE, ScopeSet, TokenEndpointAuthMethod},
};

use super::{
    exchange::{issuance_result, resolve_client_id},
    signing::{SignAccessTokenInput, SignIdTokenInput, validate_id_token_auth_time},
};
use crate::{
    domain::auth::SessionStatus,
    observability::{BusinessEvent, EventValue},
};

use super::*;

impl TokenService {
    #[tracing::instrument(skip_all, name = "token.refresh")]
    pub async fn exchange_refresh_token(
        &self,
        params: RefreshTokenGrantParams,
    ) -> Result<TokenResponse, AppError> {
        let mut event = BusinessEvent::business("token.refresh.result");
        let result = self.exchange_refresh_token_inner(params, &mut event).await;
        if let Err(error) = &result {
            let (outcome, reason) = issuance_result(error);
            self.events.emit(
                event
                    .outcome(outcome)
                    .reason(reason)
                    .attribute("error_code", EventValue::Integer(i64::from(error.code()))),
            );
        }
        result
    }

    async fn exchange_refresh_token_inner(
        &self,
        params: RefreshTokenGrantParams,
        event: &mut BusinessEvent,
    ) -> Result<TokenResponse, AppError> {
        let client_authentication_mode = ClientAuthenticationMode::from_credentials(
            params.client_secret.is_some() || params.client_assertion.is_some(),
        );
        let client_id = resolve_client_id(
            params.client_id,
            params.client_assertion_type,
            params.client_assertion.as_deref(),
        )?;
        let authenticated_client_oid = self
            .client_authentication
            .authenticate_client(
                &client_id,
                params.client_secret.as_deref(),
                params.client_secret_basic,
                params.client_assertion_type,
                params.client_assertion.as_deref(),
            )
            .await?;
        event.attributes.push((
            "client_oid",
            EventValue::Text(authenticated_client_oid.to_string()),
        ));
        let authenticated_client = self
            .client_repo
            .find_by_oid(authenticated_client_oid)
            .await
            .map_err(AppError::map_source(TokenErrorCode::ClientLookupFailed))?
            .ok_or_else(|| AppError::from_code(TokenErrorCode::ClientNotFound))?;

        if !authenticated_client.allows_grant(GrantType::RefreshToken) {
            return Err(AppError::from_code(TokenErrorCode::ClientGrantNotAllowed)
                .with_param("grant_type", GrantType::RefreshToken.as_str()));
        }

        let refresh_oid_bytes = self
            .data_protector
            .unprotect("refresh-token", &params.refresh_token)
            .await
            .map_err(AppError::map_source(TokenErrorCode::RefreshTokenNotFound))?;
        let refresh_oid = Uuid::from_slice(&refresh_oid_bytes)
            .map_err(AppError::map_source(TokenErrorCode::RefreshTokenNotFound))?;
        event.attributes.push((
            "refresh_token_oid",
            EventValue::Text(refresh_oid.to_string()),
        ));

        let refresh_record = self
            .client_authorization_repo
            .find_by_oid(refresh_oid)
            .await
            .map_err(AppError::map_source(
                TokenErrorCode::RefreshTokenLookupFailed,
            ))?
            .ok_or_else(|| AppError::from_code(TokenErrorCode::RefreshTokenNotFound))?;
        if refresh_record.type_ != ClientAuthorizationType::RefreshToken {
            return Err(AppError::from_code(TokenErrorCode::RefreshTokenNotFound));
        }
        let now = Utc::now();
        if refresh_record.client_oid != authenticated_client_oid {
            return Err(AppError::from_code(
                TokenErrorCode::RefreshTokenClientMismatch,
            ));
        }
        if refresh_record.revoked_at.is_some() {
            self.revoke_replayed_refresh_token(refresh_record.oid, authenticated_client_oid, now)
                .await?;
            return Err(AppError::from_code(TokenErrorCode::RefreshTokenInvalid));
        }
        if refresh_record.expires_at <= now {
            return Err(AppError::from_code(TokenErrorCode::RefreshTokenInvalid));
        }
        let refresh_data = match refresh_record.data {
            ClientAuthorizationData::RefreshToken(data) => data,
            _ => {
                return Err(AppError::from_code(
                    TokenErrorCode::DeserializeRefreshFailed,
                ));
            }
        };
        let issued_mode = refresh_data.client_authentication_mode.unwrap_or_else(|| {
            if authenticated_client
                .metadata()
                .effective_token_endpoint_auth_methods()
                == [TokenEndpointAuthMethod::None]
            {
                ClientAuthenticationMode::Public
            } else {
                ClientAuthenticationMode::Confidential
            }
        });
        if issued_mode != client_authentication_mode {
            return Err(AppError::from_code(
                TokenErrorCode::RefreshTokenClientMismatch,
            ));
        }
        // A device issued refresh token follows its device authorization
        // relation instead of a browser session: revoking the relation stops
        // refreshing immediately, while a browser logout does not.
        if let Some(device_authorization_oid) = refresh_data
            .device_authorization_oid
            .as_deref()
            .and_then(|oid| Uuid::parse_str(oid).ok())
        {
            let active = self
                .device_repo
                .find_device_authorization_by_oid(device_authorization_oid)
                .await
                .map_err(AppError::map_source(
                    TokenErrorCode::DeviceRelationLookupFailed,
                ))?
                .is_some_and(|relation| relation.revoked_at.is_none() && relation.expires_at > now);
            if !active {
                return Err(AppError::from_code(TokenErrorCode::RefreshTokenInvalid));
            }
        }

        let (session_acr, session_amr) = if let (Some(session_repo), Some(refresh_session_oid)) =
            (&self.session_repo, refresh_data.session_oid)
        {
            let session = session_repo
                .find_by_oid(refresh_session_oid)
                .await
                .map_err(AppError::map_source(TokenErrorCode::RefreshTokenInvalid))?
                .ok_or_else(|| AppError::from_code(TokenErrorCode::RefreshTokenInvalid))?;
            let session_is_active = session.status == SessionStatus::ACTIVE
                && session.revoked_at.is_none()
                && session.expires_at.is_none_or(|expires_at| expires_at > now)
                && session.user_oid.to_string() == refresh_data.user_oid;
            if !session_is_active {
                return Err(AppError::from_code(TokenErrorCode::RefreshTokenInvalid));
            }
            (session.effective_acr(now).map(str::to_owned), session.amr)
        } else {
            (refresh_data.acr.clone(), refresh_data.amr.clone())
        };
        let protected_session_id = match refresh_data.session_oid {
            Some(session_oid) => Some(
                self.protected_session_id(
                    session_oid,
                    refresh_data.protected_session_id.as_deref(),
                )
                .await?,
            ),
            None => None,
        };
        if authenticated_client_oid.to_string() != client_id {
            return Err(AppError::from_code(
                TokenErrorCode::RefreshTokenClientMismatch,
            ));
        }

        let granted_scope = ScopeSet::parse(&refresh_data.scope).map_err(AppError::map_source(
            TokenErrorCode::DeserializeRefreshFailed,
        ))?;
        let requested_scope = refresh_scope(&granted_scope, params.scope.as_deref())?;
        let grant_scope = requested_scope.to_scope_string();
        let selection = self
            .provider_service
            .select_resources(&params.resources, &refresh_data.resources, &grant_scope)
            .await?;
        let refresh_resources = if refresh_data.resources.is_empty() {
            &selection.resources
        } else {
            &refresh_data.resources
        };
        let scope = selection.scope.clone();
        let issue_id_token = requested_scope.contains_openid();
        if issue_id_token {
            validate_id_token_auth_time(&authenticated_client, refresh_data.auth_time)?;
        }
        let configured_signing_key = self
            .load_configured_signing_key(
                authenticated_client
                    .metadata()
                    .id_token_signed_response_algs
                    .as_deref(),
            )
            .await?;

        let claimed = self
            .client_authorization_repo
            .revoke_if_active(
                refresh_record.oid,
                ClientAuthorizationType::RefreshToken,
                now,
            )
            .await
            .map_err(AppError::map_source(TokenErrorCode::RevokeRefreshFailed))?;
        if !claimed {
            self.revoke_replayed_refresh_token(refresh_record.oid, authenticated_client_oid, now)
                .await?;
            return Err(AppError::from_code(TokenErrorCode::RefreshTokenInvalid));
        }

        let user_oid = Uuid::parse_str(&refresh_data.user_oid)
            .map_err(AppError::map_source(TokenErrorCode::RefreshTokenSubInvalid))?;
        let user = self
            .user_repo
            .find_by_oid(UserOid(user_oid))
            .await
            .map_err(AppError::map_source(TokenErrorCode::UserLookupFailed))?
            .ok_or_else(|| AppError::from_code(TokenErrorCode::RefreshTokenUserNotFound))?;

        let issuer = self.provider_service.issuer()?;
        let (signing_key_id, signing_key_pem, signing_alg) = self
            .load_access_token_signing_key(&configured_signing_key)
            .await?;
        let access_token_audience = if ScopeSet::parse(&scope)
            .map(|scope| scope.has_api_scopes())
            .unwrap_or(false)
        {
            API_RESOURCE
        } else {
            client_id.as_str()
        };
        let access_token_record = self
            .client_authorization_repo
            .create(
                authenticated_client_oid,
                ClientAuthorizationData::AccessToken(AccessTokenData {
                    scope: scope.clone(),
                    user_oid: refresh_data.user_oid.clone(),
                    session_oid: refresh_data.session_oid,
                    protected_session_id: protected_session_id.clone(),
                    authorization_code_oid: refresh_data
                        .authorization_code_oid
                        .as_deref()
                        .and_then(|oid| oid.parse::<Uuid>().ok())
                        .map(|oid| oid.to_string()),
                    device_authorization_oid: refresh_data
                        .device_authorization_oid
                        .as_deref()
                        .and_then(|oid| oid.parse::<Uuid>().ok())
                        .map(|oid| oid.to_string()),
                    refresh_token_oid: Some(refresh_record.oid.to_string()),
                    client_authentication_mode: Some(issued_mode),
                }),
                Utc::now() + Duration::hours(1),
            )
            .await
            .map_err(AppError::map_source(TokenErrorCode::SignAccessTokenFailed))?;
        event.attributes.push((
            "access_token_oid",
            EventValue::Text(access_token_record.oid.to_string()),
        ));
        let access_token = self
            .sign_access_token(SignAccessTokenInput {
                resources: &selection.resources,
                token_id: &access_token_record.oid.to_string(),
                key_id: &signing_key_id,
                private_key_pem: &signing_key_pem,
                alg: signing_alg,
                issuer: &issuer,
                audience: access_token_audience,
                client_id: &client_id,
                user_oid: &user_oid,
                client: &authenticated_client,
                user: Some(&user),
                protected_session_id: protected_session_id.as_deref(),
                scope: &scope,
                claims: None,
                auth_time: refresh_data.auth_time,
                acr: session_acr.as_deref(),
                amr: &session_amr,
            })
            .await?;
        // A refresh never turns a plain OAuth grant into an OIDC one: the
        // original authorization decides, exactly like the first exchange.
        let id_token = if issue_id_token {
            let (id_key_id, id_key_pem, id_token_alg) = &configured_signing_key;
            let signed = self
                .sign_id_token(SignIdTokenInput {
                    key_id: id_key_id,
                    private_key_pem: id_key_pem,
                    alg: *id_token_alg,
                    issuer: &issuer,
                    audience: &client_id,
                    client: &authenticated_client,
                    user: &user,
                    scope: &grant_scope,
                    nonce: None,
                    auth_time: refresh_data.auth_time,
                    acr: session_acr.as_deref(),
                    amr: &session_amr,
                    access_token: Some(&access_token),
                    protected_session_id: protected_session_id.as_deref(),
                })
                .await?;

            Some(
                self.encrypt_token_for_client(&signed, &authenticated_client)
                    .await?,
            )
        } else {
            None
        };
        let rotated_from = refresh_record.oid.to_string();
        let (rotated_refresh_oid, refresh_token) = self
            .store_refresh_token(
                authenticated_client_oid,
                RefreshTokenData {
                    scope: grant_scope,
                    resources: refresh_resources.to_vec(),
                    user_oid: refresh_data.user_oid.clone(),
                    session_oid: refresh_data.session_oid,
                    protected_session_id,
                    auth_time: refresh_data.auth_time,
                    acr: session_acr,
                    amr: session_amr,
                    rotated_from: Some(rotated_from),
                    authorization_code_oid: refresh_data
                        .authorization_code_oid
                        .as_deref()
                        .and_then(|oid| oid.parse::<Uuid>().ok())
                        .map(|oid| oid.to_string()),
                    device_authorization_oid: refresh_data
                        .device_authorization_oid
                        .as_deref()
                        .and_then(|oid| oid.parse::<Uuid>().ok())
                        .map(|oid| oid.to_string()),
                    client_authentication_mode: Some(issued_mode),
                },
                event,
            )
            .await?;

        self.events.emit(
            BusinessEvent::business("token.refresh.result")
                .outcome("success")
                .attribute(
                    "refresh_token_oid",
                    EventValue::Text(refresh_record.oid.to_string()),
                )
                .attribute(
                    "rotated_refresh_token_oid",
                    EventValue::Text(rotated_refresh_oid.to_string()),
                )
                .attribute(
                    "access_token_oid",
                    EventValue::Text(access_token_record.oid.to_string()),
                )
                .attribute(
                    "client_oid",
                    EventValue::Text(authenticated_client_oid.to_string()),
                )
                .attribute(
                    "user_oid",
                    EventValue::Pseudonymized {
                        purpose: "user_oid",
                        value: refresh_data.user_oid.clone(),
                    },
                )
                .attribute(
                    "session_oid",
                    EventValue::Pseudonymized {
                        purpose: "session_oid",
                        value: refresh_data
                            .session_oid
                            .map(|oid| oid.0.to_string())
                            .unwrap_or_default(),
                    },
                ),
        );
        self.events.emit(
            BusinessEvent::business("refresh_token.rotated")
                .outcome("success")
                .attribute(
                    "refresh_token_oid",
                    EventValue::Text(refresh_record.oid.to_string()),
                )
                .attribute(
                    "rotated_refresh_token_oid",
                    EventValue::Text(rotated_refresh_oid.to_string()),
                )
                .attribute(
                    "client_oid",
                    EventValue::Text(authenticated_client_oid.to_string()),
                ),
        );
        Ok(TokenResponse {
            access_token,
            id_token,
            refresh_token: Some(refresh_token),
            token_type: TokenType::Bearer,
            expires_in: 3600,
            scope,
        })
    }

    async fn revoke_replayed_refresh_token(
        &self,
        refresh_oid: Uuid,
        client_oid: Uuid,
        now: DateTime<Utc>,
    ) -> Result<(), AppError> {
        self.client_authorization_repo
            .revoke_refresh_token_family(refresh_oid, client_oid, now)
            .await
            .map_err(AppError::map_source(TokenErrorCode::RevokeRefreshFailed))?;
        self.events.emit(
            BusinessEvent::audit("refresh_token.reuse_detected")
                .outcome("detected")
                .attribute(
                    "refresh_token_oid",
                    EventValue::Text(refresh_oid.to_string()),
                )
                .attribute("client_oid", EventValue::Text(client_oid.to_string())),
        );
        Ok(())
    }
    pub(super) async fn store_refresh_token(
        &self,
        client_oid: Uuid,
        data: RefreshTokenData,
        event: &mut BusinessEvent,
    ) -> Result<(Uuid, String), AppError> {
        let is_rotation = data.rotated_from.is_some();
        let record = self
            .client_authorization_repo
            .create(
                client_oid,
                ClientAuthorizationData::RefreshToken(data),
                Utc::now() + Duration::days(30),
            )
            .await
            .map_err(AppError::map_source(TokenErrorCode::StoreRefreshFailed))?;

        // Keep the persisted record identifiable even if protecting its token fails.
        event.attributes.push((
            if is_rotation {
                "rotated_refresh_token_oid"
            } else {
                "refresh_token_oid"
            },
            EventValue::Text(record.oid.to_string()),
        ));
        let token = self
            .data_protector
            .protect("refresh-token", record.oid.as_bytes())
            .await
            .map_err(AppError::map_source(TokenErrorCode::SignRefreshTokenFailed))?;
        Ok((record.oid, token))
    }
}

/// Applies the optional `scope` narrowing of a refresh request (RFC 6749 §6).
///
/// The request may drop scopes, but never add one — not even `openid`, which
/// would otherwise turn a plain OAuth grant into an OIDC one after the fact.
fn refresh_scope(granted: &ScopeSet, requested: Option<&str>) -> Result<ScopeSet, AppError> {
    let Some(requested) = requested.map(str::trim).filter(|value| !value.is_empty()) else {
        return Ok(granted.clone());
    };
    let requested = ScopeSet::parse(requested)
        .map_err(AppError::map_source(TokenErrorCode::RefreshScopeNotAllowed))?;
    if !granted.covers(&requested) {
        return Err(AppError::from_code(TokenErrorCode::RefreshScopeNotAllowed));
    }
    Ok(requested)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn refresh_scope_allows_hierarchical_narrowing_but_rejects_expansion() {
        let granted = ScopeSet::parse("account offline_access").unwrap();
        assert_eq!(
            refresh_scope(&granted, Some("account.read"))
                .unwrap()
                .to_scope_string(),
            "account.read"
        );
        assert!(refresh_scope(&granted, Some("openid account.read")).is_err());
        assert!(refresh_scope(&granted, Some("session.read")).is_err());
    }
}
