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
                params.client_secret_basic,
                params.client_assertion_type,
                params.client_assertion.as_deref(),
            )
            .await?;
        let methods = client.metadata();
        let valid_proof = if params.client_assertion.is_some() {
            params.client_secret.is_none()
                && (methods
                    .allows_token_endpoint_auth_method(TokenEndpointAuthMethod::ClientSecretJwt)
                    || methods
                        .allows_token_endpoint_auth_method(TokenEndpointAuthMethod::PrivateKeyJwt))
        } else if params.client_secret.is_some() {
            methods.allows_token_endpoint_auth_method(if params.client_secret_basic {
                TokenEndpointAuthMethod::ClientSecretBasic
            } else {
                TokenEndpointAuthMethod::ClientSecretPost
            })
        } else {
            false
        };
        if !valid_proof {
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
        let selection = self
            .provider_service
            .select_resources(&params.resources, &[], &requested.to_scope_string())
            .await?;
        let scope = selection.scope;
        let client_oid = client.client().oid;
        let issuer = self.provider_service.issuer()?;
        let configured_signing_key = self
            .load_configured_signing_key(client.metadata().id_token_signed_response_algs.as_deref())
            .await?;
        let (key_id, private_key_pem, alg) = self
            .load_access_token_signing_key(&configured_signing_key)
            .await?;
        let record = self
            .create_access_token_record(
                client_oid,
                &scope,
                &client_oid.to_string(),
                None,
                None,
                None,
                None,
                identity_domain::client_authorization::ClientAuthenticationMode::Confidential,
            )
            .await?;
        let access_token = self
            .sign_access_token(SignAccessTokenInput {
                resources: &selection.resources,
                token_id: &record.oid.to_string(),
                key_id: &key_id,
                private_key_pem: &private_key_pem,
                alg,
                issuer: &issuer,
                audience: identity_domain::openid_connect::API_RESOURCE,
                client_id: &client_id,
                user_oid: &client_oid,
                client: &client,
                user: None,
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
