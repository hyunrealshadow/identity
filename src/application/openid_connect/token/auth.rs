use super::*;

impl TokenService {
    pub(super) async fn authenticate_client_secret_basic(
        &self,
        client_id: &str,
        client_secret: &str,
    ) -> Result<Uuid, AppError> {
        self.authenticate_client_secret(client_id, client_secret)
            .await
    }

    pub(super) async fn authenticate_client_secret_post(
        &self,
        client_id: &str,
        client_secret: &str,
    ) -> Result<Uuid, AppError> {
        self.authenticate_client_secret(client_id, client_secret)
            .await
    }

    async fn authenticate_client_secret(
        &self,
        client_id: &str,
        client_secret: &str,
    ) -> Result<Uuid, AppError> {
        let client_oid = Uuid::parse_str(client_id).map_err(|error| {
            AppError::from_code(TokenErrorCode::ClientIdInvalid).with_source(error)
        })?;
        let client = self
            .client_repo
            .find_by_oid(client_oid)
            .await
            .map_err(|error| {
                AppError::from_code(TokenErrorCode::ClientLookupFailed).with_source(error)
            })?
            .ok_or_else(|| AppError::from_code(TokenErrorCode::ClientNotFound))?;

        let credentials = self
            .credential_repo
            .find_by_client_oid_and_type(
                client.client().oid,
                OpenIdConnectCredentialType::ClientSecret,
            )
            .await
            .map_err(|error| {
                AppError::from_code(TokenErrorCode::CredentialLookupFailed).with_source(error)
            })?;

        let valid = credentials.into_iter().any(|credential| {
            if let OpenIdConnectCredentialData::ClientSecret { secret } = &credential.data {
                constant_time_compare(secret.as_bytes(), client_secret.as_bytes())
            } else {
                false
            }
        });

        if !valid {
            return Err(AppError::from_code(
                TokenErrorCode::ClientCredentialsInvalid,
            ));
        }

        Ok(client.client().oid)
    }

    pub(super) async fn authenticate_client(
        &self,
        client_id: &str,
        client_secret: Option<&str>,
        client_assertion_type: Option<&str>,
        client_assertion: Option<&str>,
    ) -> Result<Uuid, AppError> {
        if let (Some(assertion_type), Some(assertion)) = (client_assertion_type, client_assertion)
            && assertion_type == "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
        {
            let client_oid = Uuid::parse_str(client_id).map_err(|error| {
                AppError::from_code(TokenErrorCode::ClientIdInvalid).with_source(error)
            })?;
            let client = self
                .client_repo
                .find_by_oid(client_oid)
                .await
                .map_err(|error| {
                    AppError::from_code(TokenErrorCode::ClientLookupFailed).with_source(error)
                })?
                .ok_or_else(|| AppError::from_code(TokenErrorCode::ClientNotFound))?;

            return match client.metadata().token_endpoint_auth_method.as_deref() {
                Some("client_secret_jwt") => {
                    self.authenticate_client_secret_jwt(client_id, assertion)
                        .await
                }
                _ => {
                    self.authenticate_private_key_jwt(client_id, assertion)
                        .await
                }
            };
        }

        let Some(client_secret) = client_secret else {
            let client_oid = Uuid::parse_str(client_id).map_err(|error| {
                AppError::from_code(TokenErrorCode::ClientIdInvalid).with_source(error)
            })?;
            let client = self
                .client_repo
                .find_by_oid(client_oid)
                .await
                .map_err(|error| {
                    AppError::from_code(TokenErrorCode::ClientLookupFailed).with_source(error)
                })?
                .ok_or_else(|| AppError::from_code(TokenErrorCode::ClientNotFound))?;

            if client.metadata().settings.allow_public_client_flow {
                return Ok(client.client().oid);
            }

            return Err(AppError::from_code(TokenErrorCode::ClientAuthRequired));
        };

        let client_oid = Uuid::parse_str(client_id).map_err(|error| {
            AppError::from_code(TokenErrorCode::ClientIdInvalid).with_source(error)
        })?;
        let client = self
            .client_repo
            .find_by_oid(client_oid)
            .await
            .map_err(|error| {
                AppError::from_code(TokenErrorCode::ClientLookupFailed).with_source(error)
            })?
            .ok_or_else(|| AppError::from_code(TokenErrorCode::ClientNotFound))?;

        if client.metadata().token_endpoint_auth_method.as_deref() == Some("client_secret_basic") {
            self.authenticate_client_secret_basic(client_id, client_secret)
                .await
        } else {
            self.authenticate_client_secret_post(client_id, client_secret)
                .await
        }
    }

    pub(super) async fn authenticate_private_key_jwt(
        &self,
        client_id: &str,
        assertion: &str,
    ) -> Result<Uuid, AppError> {
        let client_oid = Uuid::parse_str(client_id).map_err(|error| {
            AppError::from_code(TokenErrorCode::ClientIdInvalid).with_source(error)
        })?;
        let client = self
            .client_repo
            .find_by_oid(client_oid)
            .await
            .map_err(|error| {
                AppError::from_code(TokenErrorCode::ClientLookupFailed).with_source(error)
            })?
            .ok_or_else(|| AppError::from_code(TokenErrorCode::ClientNotFound))?;

        let payload = self.verify_client_assertion(&client, assertion).await?;
        self.validate_client_assertion_payload(client_id, &payload)?;

        Ok(client.client().oid)
    }

    pub(super) async fn authenticate_client_secret_jwt(
        &self,
        client_id: &str,
        assertion: &str,
    ) -> Result<Uuid, AppError> {
        let client_oid = Uuid::parse_str(client_id).map_err(|error| {
            AppError::from_code(TokenErrorCode::ClientIdInvalid).with_source(error)
        })?;
        let client = self
            .client_repo
            .find_by_oid(client_oid)
            .await
            .map_err(|error| {
                AppError::from_code(TokenErrorCode::ClientLookupFailed).with_source(error)
            })?
            .ok_or_else(|| AppError::from_code(TokenErrorCode::ClientNotFound))?;

        let payload = self
            .verify_client_secret_assertion(&client, assertion)
            .await?;
        self.validate_client_assertion_payload(client_id, &payload)?;

        Ok(client.client().oid)
    }

    fn validate_client_assertion_payload(
        &self,
        client_id: &str,
        payload: &JwtPayload,
    ) -> Result<(), AppError> {
        let issuer = self.provider_service.issuer()?;

        let iss = payload
            .claim(JwtClaimNames::ISS)
            .and_then(|value| value.as_str())
            .ok_or_else(|| AppError::from_code(TokenErrorCode::AssertionIssMissing))?;
        let sub = payload
            .subject()
            .ok_or_else(|| AppError::from_code(TokenErrorCode::AssertionSubMissing))?;
        if iss != client_id || sub != client_id {
            return Err(AppError::from_code(TokenErrorCode::AssertionIssSubMismatch));
        }

        let audience_matches = payload
            .claim(JwtClaimNames::AUD)
            .and_then(|value| {
                value
                    .as_str()
                    .map(|aud| aud == issuer.as_str())
                    .or_else(|| {
                        value.as_array().map(|items| {
                            items
                                .iter()
                                .filter_map(|item| item.as_str())
                                .any(|aud| aud == issuer.as_str())
                        })
                    })
            })
            .unwrap_or(false);
        if !audience_matches {
            return Err(AppError::from_code(TokenErrorCode::AssertionAudMismatch));
        }

        let now = chrono::Utc::now().timestamp();
        if let Some(exp) = payload
            .claim(JwtClaimNames::EXP)
            .and_then(|value| value.as_i64())
            && exp <= now
        {
            return Err(AppError::from_code(TokenErrorCode::AssertionExpired));
        }
        if let Some(nbf) = payload
            .claim(JwtClaimNames::NBF)
            .and_then(|value| value.as_i64())
            && nbf > now
        {
            return Err(AppError::from_code(TokenErrorCode::AssertionNotYetValid));
        }

        Ok(())
    }

    pub(super) async fn verify_client_assertion(
        &self,
        client: &identity_domain::openid_connect::OpenIdConnectClient,
        assertion: &str,
    ) -> Result<JwtPayload, AppError> {
        let header = jwt::decode_header(assertion).map_err(|error| {
            AppError::from_code(TokenErrorCode::AssertionHeaderInvalid).with_source(error)
        })?;
        let algorithm = header
            .claim(JwtClaimNames::ALG)
            .and_then(|value| value.as_str())
            .unwrap_or("none");
        if let Some(registered_algorithm) =
            client.metadata().token_endpoint_auth_signing_alg.as_deref()
            && registered_algorithm != algorithm
        {
            return Err(AppError::from_code(TokenErrorCode::AssertionVerifyFailed));
        }

        let credentials = self
            .credential_repo
            .find_by_client_oid_and_type(
                client.client().oid,
                OpenIdConnectCredentialType::ClientPublicKey,
            )
            .await
            .map_err(|error| {
                AppError::from_code(TokenErrorCode::CredentialLookupFailed).with_source(error)
            })?;

        for credential in credentials {
            if let OpenIdConnectCredentialData::ClientPublicKey { public_key, .. } = credential.data
                && let Ok(payload) =
                    decode_assertion_with_alg(algorithm, assertion, public_key.as_bytes())
            {
                return Ok(payload);
            }
        }

        let jwks_credentials = self
            .credential_repo
            .find_by_client_oid_and_type(
                client.client().oid,
                OpenIdConnectCredentialType::ClientJsonWebKeySet,
            )
            .await
            .map_err(|error| {
                AppError::from_code(TokenErrorCode::CredentialLookupFailed).with_source(error)
            })?;
        for credential in jwks_credentials {
            if let OpenIdConnectCredentialData::ClientJsonWebKeySet { public_keys, .. } =
                credential.data
            {
                for public_key in public_keys {
                    if let Ok(payload) =
                        decode_assertion_with_alg(algorithm, assertion, public_key.as_bytes())
                    {
                        return Ok(payload);
                    }
                }
            }
        }

        Err(AppError::from_code(TokenErrorCode::AssertionVerifyFailed))
    }

    pub(super) async fn verify_client_secret_assertion(
        &self,
        client: &identity_domain::openid_connect::OpenIdConnectClient,
        assertion: &str,
    ) -> Result<JwtPayload, AppError> {
        let header = jwt::decode_header(assertion).map_err(|error| {
            AppError::from_code(TokenErrorCode::AssertionHeaderInvalid).with_source(error)
        })?;
        let algorithm = header
            .claim(JwtClaimNames::ALG)
            .and_then(|value| value.as_str())
            .unwrap_or("none");
        if let Some(registered_algorithm) =
            client.metadata().token_endpoint_auth_signing_alg.as_deref()
            && registered_algorithm != algorithm
        {
            return Err(AppError::from_code(TokenErrorCode::AssertionVerifyFailed));
        }

        let credentials = self
            .credential_repo
            .find_by_client_oid_and_type(
                client.client().oid,
                OpenIdConnectCredentialType::ClientSecret,
            )
            .await
            .map_err(|error| {
                AppError::from_code(TokenErrorCode::CredentialLookupFailed).with_source(error)
            })?;

        for credential in credentials {
            if let OpenIdConnectCredentialData::ClientSecret { secret } = credential.data
                && let Ok(payload) =
                    decode_assertion_with_hmac_alg(algorithm, assertion, secret.as_bytes())
            {
                return Ok(payload);
            }
        }

        Err(AppError::from_code(TokenErrorCode::AssertionVerifyFailed))
    }
}
