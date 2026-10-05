use super::signing::{SignAccessTokenInput, SignIdTokenInput};
use super::*;
use crate::domain::auth::SessionStatus;
use crate::observability::{BusinessEvent, EventValue};
use chrono::Duration;
use chrono::Utc;
use identity_domain::client_authorization::ClientAuthenticationMode;
use identity_domain::openid_connect::API_RESOURCE;
use identity_domain::openid_connect::CodeChallengeMethod;
use identity_domain::openid_connect::OAuthProtocolVersion;
use identity_domain::openid_connect::ScopeSet;
use tracing::Span;
use tracing::field::display;

use super::exchange::{issuance_result, resolve_client_id};

impl TokenService {
    #[tracing::instrument(
        skip_all,
        fields(
            authorization_code_id = tracing::field::Empty,
            client_oid = tracing::field::Empty
        )
    )]
    pub async fn exchange_authorization_code(
        &self,
        params: AuthorizationCodeGrantParams,
    ) -> Result<TokenResponse, AppError> {
        let mut event = BusinessEvent::business("token.issuance.result");
        let result = self
            .exchange_authorization_code_inner(params, &mut event)
            .await;
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

    async fn exchange_authorization_code_inner(
        &self,
        params: AuthorizationCodeGrantParams,
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

        let oauth_version = self.provider_service.oauth_version(&authenticated_client);

        if !authenticated_client.allows_grant(GrantType::AuthorizationCode) {
            return Err(AppError::from_code(TokenErrorCode::ClientGrantNotAllowed)
                .with_param("grant_type", GrantType::AuthorizationCode.as_str()));
        }

        let code_oid_bytes = self
            .data_protector
            .unprotect("authorization-code", &params.code)
            .await
            .map_err(AppError::map_source(TokenErrorCode::AuthCodeNotFound))?;
        let code_oid = Uuid::from_slice(&code_oid_bytes)
            .map_err(AppError::map_source(TokenErrorCode::AuthCodeNotFound))?;
        event.attributes.push((
            "authorization_code_id",
            EventValue::Text(code_oid.to_string()),
        ));
        Span::current().record("authorization_code_id", display(code_oid));
        Span::current().record("client_oid", display(authenticated_client_oid));

        let record = self
            .client_authorization_repo
            .find_by_oid(code_oid)
            .await
            .map_err(AppError::map_source(TokenErrorCode::CodeLookupFailed))?
            .ok_or_else(|| AppError::from_code(TokenErrorCode::AuthCodeNotFound))?;

        if record.type_ != ClientAuthorizationType::AuthorizationCode {
            return Err(AppError::from_code(TokenErrorCode::AuthCodeNotFound));
        }

        if record.client_oid != authenticated_client_oid {
            return Err(AppError::from_code(TokenErrorCode::CodeClientMismatch));
        }

        let now = Utc::now();
        tracing::debug!(
            revoked_at = ?record.revoked_at,
            expires_at = %record.expires_at,
            "authorization code state loaded"
        );
        if record.revoked_at.is_some() {
            self.client_authorization_repo
                .revoke_access_tokens_for_authorization_code(record.oid)
                .await
                .map_err(AppError::map_source(TokenErrorCode::RevokeCodeFailed))?;
            return Err(AppError::from_code(TokenErrorCode::AuthCodeRevoked));
        }

        if record.expires_at <= now {
            return Err(AppError::from_code(TokenErrorCode::AuthCodeExpired));
        }

        let data = match record.data {
            ClientAuthorizationData::AuthorizationCode(data) => data,
            _ => return Err(AppError::from_code(TokenErrorCode::DeserializeCodeFailed)),
        };
        let code_scope = ScopeSet::parse(&data.scope)
            .map_err(AppError::map_source(TokenErrorCode::DeserializeCodeFailed))?;
        let (session_acr, session_amr) = if let Some(session_repo) = &self.session_repo {
            let session = session_repo
                .find_by_oid(data.session_oid)
                .await
                .map_err(AppError::map_source(
                    TokenErrorCode::AuthCodeSessionLookupFailed,
                ))?
                .ok_or_else(|| AppError::from_code(TokenErrorCode::AuthCodeSessionNotFound))?;
            if session.revoked_at.is_some() {
                return Err(AppError::from_code(TokenErrorCode::AuthCodeSessionRevoked));
            }
            if session
                .expires_at
                .is_some_and(|expires_at| expires_at <= now)
            {
                return Err(AppError::from_code(TokenErrorCode::AuthCodeSessionExpired));
            }
            if session.status != SessionStatus::ACTIVE {
                return Err(AppError::from_code(TokenErrorCode::AuthCodeSessionInactive));
            }
            if session.user_oid.to_string() != data.user_oid {
                return Err(AppError::from_code(
                    TokenErrorCode::AuthCodeSessionUserMismatch,
                ));
            }
            (session.effective_acr(now).map(str::to_owned), session.amr)
        } else {
            (data.acr.clone(), data.amr.clone())
        };
        let protected_session_id = self
            .protected_session_id(data.session_oid, data.protected_session_id.as_deref())
            .await?;

        match params.redirect_uri.as_deref() {
            Some(redirect_uri) if redirect_uri != data.redirect_uri => {
                return Err(AppError::from_code(TokenErrorCode::RedirectUriMismatch));
            }
            None => {
                let oidc_with_multiple_redirects = code_scope.contains_openid()
                    && authenticated_client
                        .platforms()
                        .iter()
                        .map(|platform| platform.redirect_uris.len())
                        .sum::<usize>()
                        > 1;
                let may_omit = match oauth_version {
                    OAuthProtocolVersion::V2_0 => {
                        !data.redirect_uri_was_supplied
                            || (code_scope.contains_openid()
                                && authenticated_client
                                    .single_redirect_uri()
                                    .is_some_and(|uri| uri == data.redirect_uri))
                    }
                    OAuthProtocolVersion::V2_1 => {
                        data.code_challenge.is_some() && !oidc_with_multiple_redirects
                    }
                };
                if !may_omit {
                    return Err(AppError::from_code(TokenErrorCode::RedirectUriMismatch));
                }
            }
            Some(_) => {}
        }

        let verifier = params.code_verifier.as_deref();

        if params.client_secret.is_none()
            && params.client_assertion.is_none()
            && (data.code_challenge.as_deref().is_none_or(str::is_empty)
                || data.code_challenge_method != Some(CodeChallengeMethod::S256))
        {
            return Err(AppError::from_code(TokenErrorCode::PkceMethodUnsupported)
                .with_param("code_challenge_method", "S256 required for public client"));
        }

        verify_pkce(
            data.code_challenge.as_deref(),
            data.code_challenge_method,
            verifier,
            oauth_version,
        )?;

        let selection = self
            .provider_service
            .select_resources(&params.resources, &data.resources, &data.scope)
            .await?;
        let refresh_resources = if data.resources.is_empty() {
            &selection.resources
        } else {
            &data.resources
        };
        let issue_id_token = code_scope.contains_openid();
        if issue_id_token {
            if authenticated_client.metadata().require_auth_time == Some(true)
                && data.auth_time.is_none()
            {
                return Err(AppError::from_code(TokenErrorCode::SignIdTokenFailed));
            }
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
            .revoke_if_active(record.oid, ClientAuthorizationType::AuthorizationCode, now)
            .await
            .map_err(AppError::map_source(TokenErrorCode::RevokeCodeFailed))?;
        if !claimed {
            self.client_authorization_repo
                .revoke_access_tokens_for_authorization_code(record.oid)
                .await
                .map_err(AppError::map_source(TokenErrorCode::RevokeCodeFailed))?;
            return Err(AppError::from_code(TokenErrorCode::AuthCodeClaimFailed));
        }
        self.events.emit(
            BusinessEvent::business("authorization_code.consumed")
                .outcome("success")
                .attribute(
                    "authorization_code_id",
                    EventValue::Text(record.oid.to_string()),
                )
                .attribute(
                    "client_oid",
                    EventValue::Text(record.client_oid.to_string()),
                ),
        );
        tracing::debug!("authorization code consumed; issuing tokens");

        let user_oid = Uuid::parse_str(&data.user_oid)
            .map_err(AppError::map_source(TokenErrorCode::StoredUserOidInvalid))?;
        let user = self
            .user_repo
            .find_by_oid(UserOid(user_oid))
            .await
            .map_err(AppError::map_source(TokenErrorCode::UserLookupFailed))?
            .ok_or_else(|| AppError::from_code(TokenErrorCode::AuthCodeUserNotFound))?;

        let issuer = self.provider_service.issuer()?;
        let (signing_key_id, signing_key_pem, signing_alg) = self
            .load_access_token_signing_key(&configured_signing_key)
            .await?;
        let audience = client_id.clone();
        let access_token_audience = if ScopeSet::parse(&data.scope)
            .map(|scope| scope.has_api_scopes())
            .unwrap_or(false)
        {
            API_RESOURCE
        } else {
            audience.as_str()
        };
        let client_id_str = record.client_oid.to_string();
        let access_token_record = self
            .client_authorization_repo
            .create(
                record.client_oid,
                ClientAuthorizationData::AccessToken(AccessTokenData {
                    scope: selection.scope.clone(),
                    user_oid: data.user_oid.clone(),
                    session_oid: Some(data.session_oid),
                    protected_session_id: Some(protected_session_id.clone()),
                    authorization_code_oid: Some(record.oid.to_string()),
                    refresh_token_oid: None,
                    device_authorization_oid: None,
                    client_authentication_mode: Some(client_authentication_mode),
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
                client_id: &client_id_str,
                user_oid: &user_oid,
                client: &authenticated_client,
                user: Some(&user),
                protected_session_id: Some(&protected_session_id),
                scope: &selection.scope,
                claims: data.claims.as_ref(),
                auth_time: data.auth_time,
                acr: session_acr.as_deref(),
                amr: &session_amr,
            })
            .await?;
        let id_token = if issue_id_token {
            let (id_key_id, id_key_pem, id_token_alg) = &configured_signing_key;
            let signed = self
                .sign_id_token(SignIdTokenInput {
                    key_id: &id_key_id,
                    private_key_pem: &id_key_pem,
                    alg: *id_token_alg,
                    issuer: &issuer,
                    audience: &audience,
                    client: &authenticated_client,
                    user: &user,
                    scope: &data.scope,
                    nonce: data.nonce.as_deref(),
                    auth_time: data.auth_time,
                    acr: session_acr.as_deref(),
                    amr: &session_amr,
                    access_token: Some(&access_token),
                    protected_session_id: Some(&protected_session_id),
                })
                .await?;
            let id_token = self
                .encrypt_token_for_client(&signed, &authenticated_client)
                .await?;
            Some(id_token)
        } else {
            None
        };
        let refresh_scope_string = code_scope.to_scope_string();
        let refresh_token = if authenticated_client.allows_grant(GrantType::RefreshToken)
            && code_scope.contains_offline_access()
        {
            Some(
                self.store_refresh_token(
                    record.client_oid,
                    RefreshTokenData {
                        device_authorization_oid: None,
                        scope: refresh_scope_string,
                        resources: refresh_resources.to_vec(),
                        user_oid: data.user_oid.clone(),
                        session_oid: Some(data.session_oid),
                        protected_session_id: Some(protected_session_id),
                        auth_time: data.auth_time,
                        acr: session_acr,
                        amr: session_amr,
                        rotated_from: None,
                        authorization_code_oid: Some(record.oid.to_string()),
                        client_authentication_mode: Some(client_authentication_mode),
                    },
                    event,
                )
                .await?,
            )
        } else {
            None
        };

        let mut issuance_event = BusinessEvent::business("token.issuance.result")
            .outcome("success")
            .attribute(
                "access_token_oid",
                EventValue::Text(access_token_record.oid.to_string()),
            )
            .attribute(
                "authorization_code_id",
                EventValue::Text(record.oid.to_string()),
            )
            .attribute(
                "client_oid",
                EventValue::Text(record.client_oid.to_string()),
            )
            .attribute(
                "user_oid",
                EventValue::Pseudonymized {
                    purpose: "user_oid",
                    value: data.user_oid.clone(),
                },
            )
            .attribute(
                "session_oid",
                EventValue::Pseudonymized {
                    purpose: "session_oid",
                    value: data.session_oid.0.to_string(),
                },
            );
        if let Some((oid, _)) = &refresh_token {
            issuance_event =
                issuance_event.attribute("refresh_token_oid", EventValue::Text(oid.to_string()));
        }
        self.events.emit(issuance_event);
        Ok(TokenResponse {
            access_token,
            id_token,
            refresh_token: refresh_token.map(|(_, token)| token),
            token_type: TokenType::Bearer,
            expires_in: 3600,
            scope: selection.scope,
        })
    }
}
