use super::signing::SignAccessTokenInput;
use super::*;
use crate::domain::openid_connect::TokenEndpointAuthMethod;

impl TokenService {
    #[tracing::instrument(skip_all, name = "token.client_credentials")]
    pub async fn exchange_client_credentials(
        &self,
        params: ClientCredentialsGrantParams,
    ) -> Result<TokenResponse, AppError> {
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
                params.client_secret.is_none() && params.client_assertion.is_some()
            }
            TokenEndpointAuthMethod::None => false,
        };
        if !valid_proof || client.metadata().settings.allow_public_client_flow {
            return Err(AppError::from_code(TokenErrorCode::ClientAuthRequired));
        }
        if !client.allows_grant(GrantType::ClientCredentials) {
            return Err(AppError::from_code(TokenErrorCode::ClientGrantNotAllowed)
                .with_param("grant_type", GrantType::ClientCredentials.as_str()));
        }

        let scope = params.scope.unwrap_or_default();
        let requested = ScopeSet::parse(&scope)
            .map_err(|_| AppError::from_code(TokenErrorCode::ClientCredentialsScopeNotAllowed))?;
        let assigned = ScopeSet::parse(&client.assigned_scopes().join(" "))
            .map_err(|_| AppError::from_code(TokenErrorCode::ClientCredentialsScopeNotAllowed))?;
        if requested.openid
            || requested.profile
            || requested.email
            || requested.address
            || requested.phone
            || requested.offline_access
            || !assigned.covers(&requested)
        {
            return Err(AppError::from_code(
                TokenErrorCode::ClientCredentialsScopeNotAllowed,
            ));
        }
        let scope = requested.to_scope_string();
        let client_oid = client.client().oid;
        let issuer = self.provider_service.issuer()?;
        let (key_id, private_key_pem, alg) = self.load_signing_key().await?;
        let record = self
            .create_access_token_record(
                client_oid,
                &scope,
                &client_oid.to_string(),
                None,
                None,
                None,
                None,
            )
            .await?;
        let access_token = self
            .sign_access_token(SignAccessTokenInput {
                token_id: &record.oid.to_string(),
                key_id: &key_id,
                private_key_pem: &private_key_pem,
                alg,
                issuer: &issuer,
                audience: identity_domain::openid_connect::API_RESOURCE,
                client_id: &client_id,
                user_oid: &client_oid,
                protected_session_id: None,
                scope: &scope,
                claims: None,
                auth_time: None,
                acr: None,
                amr: &[],
            })
            .await?;
        Ok(TokenResponse {
            access_token,
            id_token: None,
            refresh_token: None,
            token_type: TokenType::Bearer,
            expires_in: 3600,
            scope,
        })
    }
}
