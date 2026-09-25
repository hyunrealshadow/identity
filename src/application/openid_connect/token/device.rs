//! Device code redemption (RFC 8628 §3.4, §3.5).
//!
//! The redemption prepares everything that can fail — loading the signing key,
//! signing the tokens, encrypting the ID token — before it touches the
//! database. The repository then re-validates the request state under a row
//! lock and commits the consumption together with every token record in one
//! transaction, so an internal failure leaves the device code redeemable and a
//! second poll of an already redeemed code cannot produce a second token set
//! (ADR 0005).

use super::exchange::{issuance_result, resolve_client_id};
use super::signing::{SignAccessTokenInput, SignIdTokenInput};
use super::*;
use crate::domain::client_authorization::{
    ClientAuthorizationData, DeviceAuthorizationApproval, DeviceConsumeOutcome, RefreshTokenData,
};
use crate::domain::openid_connect::GrantType;
use crate::observability::{BusinessEvent, EventValue};

impl TokenService {
    #[tracing::instrument(
        skip_all,
        name = "token.device_code",
        fields(client_oid = tracing::field::Empty)
    )]
    pub async fn exchange_device_code(
        &self,
        params: DeviceCodeGrantParams,
    ) -> Result<TokenResponse, AppError> {
        let result = self.exchange_device_code_inner(params).await;
        if let Err(error) = &result {
            let (outcome, reason) = issuance_result(error);
            self.events.emit(
                BusinessEvent::business("token.device_code.result")
                    .outcome(outcome)
                    .reason(reason)
                    .attribute("error_code", EventValue::Integer(i64::from(error.code()))),
            );
        }
        result
    }

    async fn exchange_device_code_inner(
        &self,
        params: DeviceCodeGrantParams,
    ) -> Result<TokenResponse, AppError> {
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
                params.client_assertion_type,
                params.client_assertion.as_deref(),
            )
            .await?;
        let client = self
            .client_repo
            .find_by_oid(authenticated_client_oid)
            .await
            .map_err(|error| {
                AppError::from_code(TokenErrorCode::ClientLookupFailed).with_source(error)
            })?
            .ok_or_else(|| AppError::from_code(TokenErrorCode::ClientNotFound))?;

        // Re-check the grant at redemption: a client whose registration
        // changed after the user approved must not receive tokens.
        if !client.allows_grant(GrantType::DeviceCode) {
            return Err(AppError::from_code(TokenErrorCode::ClientGrantNotAllowed)
                .with_param("grant_type", GrantType::DeviceCode.as_str()));
        }

        tracing::Span::current().record(
            "client_oid",
            tracing::field::display(authenticated_client_oid),
        );

        let digest = device_code_digest(&params.device_code);
        let record = self
            .device_repo
            .find_device_request_by_device_code_digest(&digest)
            .await
            .map_err(|error| {
                AppError::from_code(TokenErrorCode::DeviceRequestLookupFailed).with_source(error)
            })?
            .ok_or_else(|| AppError::from_code(TokenErrorCode::DeviceCodeNotFound))?;

        if record.client_oid != authenticated_client_oid {
            return Err(AppError::from_code(
                TokenErrorCode::DeviceCodeClientMismatch,
            ));
        }

        let data = match &record.data {
            ClientAuthorizationData::DeviceAuthorizationRequest(data) => data.clone(),
            _ => return Err(AppError::from_code(TokenErrorCode::DeviceCodeNotFound)),
        };
        let now = chrono::Utc::now();
        if record.expires_at <= now {
            return Err(AppError::from_code(TokenErrorCode::DeviceCodeExpired));
        }

        let approval = match data.status {
            DeviceRequestStatus::Denied => {
                return Err(AppError::from_code(TokenErrorCode::DeviceCodeDenied));
            }
            DeviceRequestStatus::Consumed => {
                return Err(AppError::from_code(TokenErrorCode::DeviceCodeNotFound));
            }
            DeviceRequestStatus::Pending => {
                return Err(match self.poll_schedule(&record, now).await? {
                    PollDecision::Pending => AppError::from_code(TokenErrorCode::DeviceCodePending),
                    PollDecision::SlowDown => {
                        AppError::from_code(TokenErrorCode::DeviceCodeSlowDown)
                    }
                    PollDecision::Terminal(error) => error,
                });
            }
            DeviceRequestStatus::Approved => data
                .approval
                .clone()
                .ok_or_else(|| AppError::from_code(TokenErrorCode::DeviceRequestStateInvalid))?,
        };

        let device_authorization_oid = approval.device_authorization_oid;
        let relation = self
            .device_repo
            .find_device_authorization_by_oid(device_authorization_oid)
            .await
            .map_err(|error| {
                AppError::from_code(TokenErrorCode::DeviceRelationLookupFailed).with_source(error)
            })?
            .ok_or_else(|| AppError::from_code(TokenErrorCode::DeviceCodeRevoked))?;
        if relation.revoked_at.is_some() || relation.expires_at <= now {
            return Err(AppError::from_code(TokenErrorCode::DeviceCodeRevoked));
        }

        let scope = ScopeSet::parse(&approval.approved_scope).map_err(|error| {
            AppError::from_code(TokenErrorCode::DeviceRequestStateInvalid).with_source(error)
        })?;
        let user_oid = Uuid::parse_str(&approval.user_oid).map_err(|error| {
            AppError::from_code(TokenErrorCode::DeviceRequestStateInvalid).with_source(error)
        })?;
        let user = self
            .user_repo
            .find_by_oid(UserOid(user_oid))
            .await
            .map_err(|error| {
                AppError::from_code(TokenErrorCode::UserLookupFailed).with_source(error)
            })?
            .ok_or_else(|| AppError::from_code(TokenErrorCode::DeviceCodeUserNotFound))?;
        if !user.enabled || user.locked {
            return Err(AppError::from_code(TokenErrorCode::DeviceCodeUserNotFound));
        }

        self.issue_device_tokens(
            &client,
            &client_id,
            &approval,
            &scope,
            &user,
            record.oid,
            device_authorization_oid,
            now,
        )
        .await
    }

    /// Applies the persisted polling schedule to a still pending request.
    async fn poll_schedule(
        &self,
        record: &identity_domain::client_authorization::ClientAuthorization,
        now: chrono::DateTime<chrono::Utc>,
    ) -> Result<PollDecision, AppError> {
        match self
            .device_repo
            .record_device_poll(record.oid, now)
            .await
            .map_err(|error| {
                AppError::from_code(TokenErrorCode::DeviceRequestLookupFailed).with_source(error)
            })? {
            DevicePollOutcome::Accepted => Ok(PollDecision::Pending),
            DevicePollOutcome::TooFrequent => Ok(PollDecision::SlowDown),
            DevicePollOutcome::NotPollable => {
                // The request left the pending state between the read and the
                // poll: report the terminal state instead of pending.
                let current = self
                    .device_repo
                    .find_device_request_by_oid(record.oid)
                    .await
                    .map_err(|error| {
                        AppError::from_code(TokenErrorCode::DeviceRequestLookupFailed)
                            .with_source(error)
                    })?;
                let Some(current) = current else {
                    return Ok(PollDecision::Terminal(AppError::from_code(
                        TokenErrorCode::DeviceCodeNotFound,
                    )));
                };
                if current.expires_at <= now {
                    return Ok(PollDecision::Terminal(AppError::from_code(
                        TokenErrorCode::DeviceCodeExpired,
                    )));
                }
                match &current.data {
                    ClientAuthorizationData::DeviceAuthorizationRequest(data) => {
                        match data.status {
                            DeviceRequestStatus::Denied => Ok(PollDecision::Terminal(
                                AppError::from_code(TokenErrorCode::DeviceCodeDenied),
                            )),
                            DeviceRequestStatus::Consumed => Ok(PollDecision::Terminal(
                                AppError::from_code(TokenErrorCode::DeviceCodeNotFound),
                            )),
                            DeviceRequestStatus::Approved | DeviceRequestStatus::Pending => {
                                Ok(PollDecision::Pending)
                            }
                        }
                    }
                    _ => Ok(PollDecision::Terminal(AppError::from_code(
                        TokenErrorCode::DeviceCodeNotFound,
                    ))),
                }
            }
        }
    }

    /// Prepares and signs every token, then commits consumption and issuance
    /// together. Prepared records never leave the transaction on failure.
    #[allow(clippy::too_many_arguments)]
    async fn issue_device_tokens(
        &self,
        client: &OpenIdConnectClient,
        client_id: &str,
        approval: &DeviceAuthorizationApproval,
        scope: &ScopeSet,
        user: &User,
        request_oid: Uuid,
        device_authorization_oid: Uuid,
        now: chrono::DateTime<chrono::Utc>,
    ) -> Result<TokenResponse, AppError> {
        let issuer = self.provider_service.issuer()?;
        let (signing_key_id, signing_key_pem, signing_alg) = self.load_signing_key().await?;
        let scope_string = scope.to_scope_string();
        let access_token_audience = if scope.has_api_scopes() {
            identity_domain::openid_connect::API_RESOURCE
        } else {
            client_id
        };

        let access_token_oid = Uuid::new_v4();
        let access_token = self
            .sign_access_token(SignAccessTokenInput {
                token_id: &access_token_oid.to_string(),
                key_id: &signing_key_id,
                private_key_pem: &signing_key_pem,
                alg: signing_alg,
                issuer: &issuer,
                audience: access_token_audience,
                client_id,
                user_oid: &user.oid.0,
                // Device tokens have no browser session and therefore no sid.
                protected_session_id: None,
                scope: &scope_string,
                claims: None,
                auth_time: approval.auth_time,
                acr: approval.acr.as_deref(),
                amr: &approval.amr,
            })
            .await?;

        let id_token = if scope.contains_openid() {
            let signed = self
                .sign_id_token(SignIdTokenInput {
                    key_id: &signing_key_id,
                    private_key_pem: &signing_key_pem,
                    alg: identity_domain::key::JwsAlgorithm::Asymmetric(signing_alg),
                    issuer: &issuer,
                    audience: client_id,
                    client,
                    user,
                    scope: &scope_string,
                    nonce: None,
                    auth_time: approval.auth_time,
                    acr: approval.acr.as_deref(),
                    amr: &approval.amr,
                    access_token: Some(&access_token),
                    protected_session_id: None,
                })
                .await?;
            Some(match client.metadata().id_token_encrypted_response_alg {
                Some(alg) => {
                    let enc = client
                        .metadata()
                        .id_token_encrypted_response_enc
                        .unwrap_or(JweContentEncryption::A128CbcHs256);
                    self.encrypt_token(&signed, client, alg, enc).await?
                }
                None => signed,
            })
        } else {
            None
        };

        // Device issued refresh tokens follow the long lived access semantics of
        // this deployment and therefore require the refresh_token grant, which
        // is a local policy on top of RFC 8628.
        let refresh_token_oid = Uuid::new_v4();
        let refresh_token = if scope.offline_access && client.allows_grant(GrantType::RefreshToken)
        {
            Some(
                self.data_protector
                    .protect("refresh-token", refresh_token_oid.as_bytes())
                    .await
                    .map_err(|error| {
                        AppError::from_code(TokenErrorCode::SignRefreshTokenFailed)
                            .with_source(error)
                    })?,
            )
        } else {
            None
        };

        let mut records = vec![PreparedAuthorizationRecord {
            oid: access_token_oid,
            data: self.access_token_data(
                &scope_string,
                &approval.user_oid,
                None,
                None,
                None,
                Some(device_authorization_oid),
            ),
            expires_at: now + chrono::Duration::hours(1),
        }];
        if refresh_token.is_some() {
            records.push(PreparedAuthorizationRecord {
                oid: refresh_token_oid,
                data: ClientAuthorizationData::RefreshToken(RefreshTokenData {
                    scope: scope_string.clone(),
                    user_oid: approval.user_oid.clone(),
                    session_oid: None,
                    protected_session_id: None,
                    auth_time: approval.auth_time,
                    acr: approval.acr.clone(),
                    amr: approval.amr.clone(),
                    rotated_from: None,
                    authorization_code_oid: None,
                    device_authorization_oid: Some(device_authorization_oid.to_string()),
                }),
                expires_at: now + chrono::Duration::days(30),
            });
        }

        let outcome = self
            .device_repo
            .consume_device_request_with_tokens(request_oid, records, chrono::Utc::now())
            .await
            .map_err(|error| {
                AppError::from_code(TokenErrorCode::DeviceRedemptionFailed).with_source(error)
            })?;
        match outcome {
            DeviceConsumeOutcome::Consumed => {}
            DeviceConsumeOutcome::NotRedeemable => {
                return Err(AppError::from_code(TokenErrorCode::DeviceCodeNotFound));
            }
            DeviceConsumeOutcome::AuthorizationRevoked => {
                return Err(AppError::from_code(TokenErrorCode::DeviceCodeRevoked));
            }
        }

        self.events.emit(
            BusinessEvent::business("token.device_code.issued")
                .outcome("success")
                .attribute("client_oid", EventValue::Text(client_id.to_owned()))
                .attribute(
                    "device_authorization_oid",
                    EventValue::Text(device_authorization_oid.to_string()),
                )
                .attribute(
                    "user_oid",
                    EventValue::Pseudonymized {
                        purpose: "user_oid",
                        value: approval.user_oid.clone(),
                    },
                ),
        );

        Ok(TokenResponse {
            access_token,
            id_token,
            refresh_token,
            token_type: TokenType::Bearer,
            expires_in: 3600,
            scope: scope_string,
        })
    }
}

/// Result of matching a pending request against its polling schedule.
enum PollDecision {
    Pending,
    SlowDown,
    Terminal(AppError),
}
