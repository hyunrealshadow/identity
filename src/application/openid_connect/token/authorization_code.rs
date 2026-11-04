use chrono::{Duration, Utc};
use identity_domain::{
    auth,
    auth::ACR_AAL2,
    client_authorization::{
        AccessTokenPrincipal, ClientAuthenticationMode, ManagementGrantKindData,
    },
    openid_connect::{API_RESOURCE, CodeChallengeMethod, OAuthProtocolVersion, ScopeSet},
};
use tracing::{Span, debug, field::display};

use super::{
    exchange::{issuance_result, resolve_client_id},
    signing::{SignAccessTokenInput, SignIdTokenInput, validate_id_token_auth_time},
};
use crate::{
    domain::auth::SessionStatus,
    observability::{BusinessEvent, EventValue},
    openid_connect::{management, rbac as shared},
};

use super::*;

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
        debug!(
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
        let management_snapshot = shared::management_snapshot(data.management.as_ref());
        let business_snapshot = shared::business_snapshot(data.management.as_ref());
        let management = management_snapshot.is_some() || code_scope.has_management_scopes();
        let business_resource = !code_scope.has_management_scopes()
            && self
                .provider_service
                .has_rbac_resource(&data.resources)
                .await?;
        let business = business_snapshot.is_some() || business_resource;
        if management && business {
            return Err(AppError::from_code(TokenErrorCode::AuthCodeInvalid));
        }
        if business && business_snapshot.is_none() {
            return Err(AppError::from_code(TokenErrorCode::AuthCodeInvalid));
        }
        if management {
            // A management code is authoritative only with S256 PKCE, the
            // single GraphQL resource, no refresh grant, and a live binding
            // snapshot. Anything missing fails closed.
            let snapshot_data = management_snapshot
                .ok_or_else(|| AppError::from_code(TokenErrorCode::AuthCodeInvalid))?;
            if !code_scope.has_management_scopes()
                || snapshot_data.grant_kind != ManagementGrantKindData::UserRbac
            {
                return Err(AppError::from_code(TokenErrorCode::AuthCodeInvalid));
            }
            if code_scope.contains_offline_access() {
                return Err(AppError::from_code(TokenErrorCode::AuthCodeInvalid));
            }
            if !management::is_single_graphql_resource(&data.resources) {
                return Err(AppError::from_code(TokenErrorCode::AuthCodeInvalid));
            }
            if data.code_challenge.as_deref().is_none_or(str::is_empty)
                || data.code_challenge_method != Some(CodeChallengeMethod::S256)
            {
                return Err(AppError::from_code(TokenErrorCode::PkceMethodUnsupported)
                    .with_param("code_challenge_method", "S256 required for management"));
            }

            let client_fingerprint = self
                .provider_service
                .client_authority_fingerprint(&authenticated_client)
                .await
                .map_err(AppError::map_source(TokenErrorCode::AuthCodeInvalid))?;
            if client_fingerprint.as_uuid() != snapshot_data.client_policy_version {
                return Err(AppError::from_code(TokenErrorCode::AuthCodeInvalid)
                    .with_param("reason", "client scope ceiling changed"));
            }

            let binding_repo = self.management_authority_repo.as_ref().ok_or_else(|| {
                AppError::from_code(TokenErrorCode::AuthCodeInvalid)
                    .with_param("reason", "user permission authority support unavailable")
            })?;
            let snapshot = snapshot_data
                .to_snapshot()
                .map_err(|_| AppError::from_code(TokenErrorCode::AuthCodeInvalid))?;
            binding_repo
                .validate_snapshot(&snapshot)
                .await
                .map_err(|_| AppError::from_code(TokenErrorCode::AuthCodeInvalid))?;
        }
        if business {
            let snapshot = business_snapshot
                .ok_or_else(|| AppError::from_code(TokenErrorCode::AuthCodeInvalid))?;
            if data.resources.len() != 1 || data.resources[0] != snapshot.resource_uri {
                return Err(AppError::from_code(TokenErrorCode::AuthCodeInvalid));
            }
            if data.code_challenge.as_deref().is_none_or(str::is_empty)
                || data.code_challenge_method != Some(CodeChallengeMethod::S256)
            {
                return Err(AppError::from_code(TokenErrorCode::PkceMethodUnsupported)
                    .with_param("code_challenge_method", "S256"));
            }
            if code_scope.contains_offline_access()
                && !authenticated_client.allows_grant(GrantType::RefreshToken)
            {
                return Err(AppError::from_code(TokenErrorCode::AuthCodeInvalid));
            }
            let repository = self
                .rbac_authorization_repo
                .as_ref()
                .ok_or_else(|| AppError::from_code(TokenErrorCode::AuthCodeInvalid))?;
            let persisted = snapshot
                .to_snapshot()
                .map_err(AppError::map_source(TokenErrorCode::AuthCodeInvalid))?;
            repository
                .validate_snapshot(&persisted)
                .await
                .map_err(AppError::map_source(TokenErrorCode::AuthCodeInvalid))?;
        }
        if management && self.session_repo.is_none() {
            return Err(AppError::from_code(TokenErrorCode::AuthCodeInvalid)
                .with_param("reason", "management requires live session validation"));
        }
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
        if management
            && !session_acr
                .as_deref()
                .is_some_and(|acr| auth::acr_satisfies(acr, ACR_AAL2))
        {
            return Err(AppError::from_code(TokenErrorCode::AuthCodeInvalid));
        }
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
        let selected_scope_set = ScopeSet::parse(&selection.scope)
            .map_err(AppError::map_source(TokenErrorCode::AuthCodeInvalid))?;
        self.provider_service
            .validate_client_resource_ceiling(
                &authenticated_client,
                &selection.resources,
                &selected_scope_set,
                identity_domain::client_authorization::AccessTokenPrincipal::User,
            )
            .await
            .map_err(AppError::map_source(TokenErrorCode::AuthCodeInvalid))?;
        if management {
            // Never expand or silently drop management at exchange time. The
            // signed token must carry exactly the clipped code scope at the
            // single GraphQL audience.
            let selected = ScopeSet::parse(&selection.scope)
                .map_err(AppError::map_source(TokenErrorCode::AuthCodeInvalid))?;
            if !management::is_single_graphql_resource(&selection.resources)
                || selected.management_scopes() != code_scope.management_scopes()
            {
                return Err(AppError::from_code(TokenErrorCode::AuthCodeInvalid)
                    .with_param("reason", "management resource or scope changed"));
            }
        }
        if business {
            // The code's original business scope is the immutable ceiling. A
            // live intersection may shrink but must never add or silently
            // remove an already granted business scope.
            let snapshot_data = business_snapshot
                .ok_or_else(|| AppError::from_code(TokenErrorCode::AuthCodeInvalid))?;
            let selected = ScopeSet::parse(&selection.scope)
                .map_err(AppError::map_source(TokenErrorCode::AuthCodeInvalid))?;
            if selection.resources.len() != 1
                || selection.resources[0] != snapshot_data.resource_uri
                || shared::business_scope_names(&selected)
                    != shared::business_scope_names(&code_scope)
            {
                return Err(AppError::from_code(TokenErrorCode::AuthCodeInvalid));
            }
            shared::validate_business_authorization(
                shared::BusinessLivePorts {
                    repository: self.rbac_authorization_repo.as_ref(),
                    provider_service: &self.provider_service,
                },
                shared::BusinessTokenAuthorization {
                    live_client: &authenticated_client,
                    persisted: snapshot_data,
                    persisted_scope: &selection.scope,
                    scope: &selected,
                    principal: AccessTokenPrincipal::User,
                    subject_user_oid: Some(UserOid(
                        Uuid::parse_str(&data.user_oid)
                            .map_err(AppError::map_source(TokenErrorCode::StoredUserOidInvalid))?,
                    )),
                    audience: &selection.resources,
                },
            )
            .await
            .map_err(AppError::map_source(TokenErrorCode::AuthCodeInvalid))?;
        }
        let refresh_resources = if data.resources.is_empty() {
            &selection.resources
        } else {
            &data.resources
        };
        let issue_id_token = code_scope.contains_openid();
        if issue_id_token {
            validate_id_token_auth_time(&authenticated_client, data.auth_time)?;
        }
        let configured_signing_key = self
            .load_configured_signing_key(
                authenticated_client
                    .metadata()
                    .id_token_signed_response_algs
                    .as_deref(),
            )
            .await?;

        let user_oid = Uuid::parse_str(&data.user_oid)
            .map_err(AppError::map_source(TokenErrorCode::StoredUserOidInvalid))?;
        let user = self
            .user_repo
            .find_by_oid(UserOid(user_oid))
            .await
            .map_err(AppError::map_source(TokenErrorCode::UserLookupFailed))?
            .ok_or_else(|| AppError::from_code(TokenErrorCode::AuthCodeUserNotFound))?;
        if !user.enabled || user.locked {
            return Err(AppError::from_code(TokenErrorCode::AuthCodeUserNotFound)
                .with_param("reason", "user is disabled or locked"));
        }

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
        debug!("authorization code consumed; issuing tokens");

        let issuer = self.provider_service.issuer()?;
        let (signing_key_id, signing_key_pem, signing_alg) = self
            .load_access_token_signing_key(&configured_signing_key)
            .await?;
        let audience = client_id.clone();
        let access_token_audience =
            if code_scope.has_api_scopes() || code_scope.has_management_scopes() {
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
                    resources: selection.resources.clone(),
                    user_oid: Some(data.user_oid.clone()),
                    principal: AccessTokenPrincipal::User,
                    session_oid: Some(data.session_oid),
                    protected_session_id: Some(protected_session_id.clone()),
                    authorization_code_oid: Some(record.oid.to_string()),
                    refresh_token_oid: None,
                    device_authorization_oid: None,
                    client_authentication_mode: Some(client_authentication_mode),
                    management: data.management.clone(),
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
                subject: &data.user_oid,
                principal: AccessTokenPrincipal::User,
                client: &authenticated_client,
                user: Some(&user),
                protected_session_id: Some(&protected_session_id),
                scope: &selection.scope,
                claims: data.claims.as_ref(),
                auth_time: data.auth_time,
                acr: session_acr.as_deref(),
                amr: &session_amr,
                management: management_snapshot,
                business: business_snapshot,
            })
            .await?;
        let id_token = if issue_id_token {
            let (id_key_id, id_key_pem, id_token_alg) = &configured_signing_key;
            let signed = self
                .sign_id_token(SignIdTokenInput {
                    key_id: id_key_id,
                    private_key_pem: id_key_pem,
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
        let refresh_token = if !management
            && !code_scope.has_management_scopes()
            && authenticated_client.allows_grant(GrantType::RefreshToken)
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
                        management: data.management.clone(),
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
