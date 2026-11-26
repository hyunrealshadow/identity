use chrono::Utc;
use identity_domain::openid_connect::par::PAR_REQUEST_URI_PREFIX;
use serde_json::{Value, from_slice};

use crate::{
    error::codes::{authorize, common},
    openid_connect::par::request_uri_digest,
};

use super::*;

mod actions;

impl AuthorizeService {
    pub async fn validate_request(
        &self,
        params: AuthorizationRequestParams,
    ) -> Result<(AuthorizationRequest, OpenIdConnectClient), AppError> {
        if let Some(uri) = params
            .request_uri
            .as_deref()
            .filter(|uri| uri.starts_with(PAR_REQUEST_URI_PREFIX))
        {
            let expected = AuthorizationRequestParams {
                client_id: params.client_id.clone(),
                request_uri: params.request_uri.clone(),
                ..Default::default()
            };
            if params != expected {
                return Err(common::error::InvalidRequest.into_error());
            }
            let client_oid =
                identity_domain::openid_connect::identifier::parse_client_id(&params.client_id)
                    .map_err(|_| authorize::error::RequestUriInvalid.into_error())?;
            let stored = self
                .client_authorization_repo
                .consume_pushed_authorization_request(
                    &request_uri_digest(uri),
                    client_oid,
                    Utc::now(),
                )
                .await
                .map_err(common::error::PushedRequestStorageFailed::map_source())?
                .ok_or_else(|| authorize::error::RequestUriInvalid.into_error())?;
            let stored = stored.parameters;
            if stored.client_id != params.client_id || stored.request_uri.is_some() {
                return Err(authorize::error::RequestUriInvalid.into_error());
            }
            return self.validate_request_params(stored, true).await;
        }
        self.validate_request_params(params, false).await
    }

    pub(crate) async fn validate_pushed_request(
        &self,
        params: AuthorizationRequestParams,
    ) -> Result<(AuthorizationRequest, OpenIdConnectClient), AppError> {
        if params.request_uri.is_some() {
            return Err(common::error::InvalidRequest.into_error());
        }
        self.validate_request_params(params, true).await
    }

    /// Authorization and PAR run the same validation actions. The pushed
    /// flag only controls transport policy and request-object client binding.
    async fn validate_request_params(
        &self,
        params: AuthorizationRequestParams,
        pushed: bool,
    ) -> Result<(AuthorizationRequest, OpenIdConnectClient), AppError> {
        let loaded = self.load_authorization_client(params, pushed).await?;
        let params = self
            .process_authorization_request_object(loaded.params, &loaded.client, pushed)
            .await?;
        let request = self
            .parse_authorization_parameters(
                params,
                &loaded.client,
                loaded.client_id,
                loaded.oauth_version,
            )
            .await?;
        Ok((request, loaded.client))
    }

    fn validate_request_parameter_conflicts(
        params: &AuthorizationRequestParams,
    ) -> Result<(), AppError> {
        if params.request.is_some() && params.request_uri.is_some() {
            return Err(authorize::error::RequestAndUriConflict.into_error());
        }

        Ok(())
    }

    fn validate_required_params(params: &AuthorizationRequestParams) -> Result<(), AppError> {
        let mut missing_fields = Vec::new();

        for (name, value) in [
            ("response_type", params.response_type.as_str()),
            ("client_id", params.client_id.as_str()),
            ("scope", params.scope.as_str()),
        ] {
            if value.trim().is_empty() {
                missing_fields.push(name);
            }
        }

        if !missing_fields.is_empty() {
            return Err(
                authorize::error::RequiredParamMissing::new(missing_fields.join(", ")).into_error(),
            );
        }

        Ok(())
    }

    fn validate_id_token_hint_issuer(raw: Option<&str>, issuer: &Url) -> Result<(), AppError> {
        let Some(raw) = raw else {
            return Ok(());
        };

        let header_segment = raw
            .split('.')
            .next()
            .ok_or_else(|| authorize::error::IdTokenHintIssuerInvalid.into_error())?;
        let header = URL_SAFE_NO_PAD
            .decode(header_segment)
            .map_err(authorize::error::IdTokenHintIssuerInvalid::map_source())?;
        let header = from_slice::<Value>(&header)
            .map_err(authorize::error::IdTokenHintIssuerInvalid::map_source())?;
        if !cfg!(feature = "allow-none-alg")
            && header
                .get(JwtClaimNames::ALG)
                .and_then(|value| value.as_str())
                .is_none_or(|alg| alg.eq_ignore_ascii_case("none"))
        {
            return Err(authorize::error::IdTokenHintIssuerInvalid.into_error());
        }

        let payload_segment = raw
            .split('.')
            .nth(1)
            .ok_or_else(|| authorize::error::IdTokenHintIssuerInvalid.into_error())?;
        let payload = URL_SAFE_NO_PAD
            .decode(payload_segment)
            .map_err(authorize::error::IdTokenHintIssuerInvalid::map_source())?;
        let payload = from_slice::<Value>(&payload)
            .map_err(authorize::error::IdTokenHintIssuerInvalid::map_source())?;

        if payload
            .get(JwtClaimNames::ISS)
            .and_then(|value| value.as_str())
            .is_some_and(|iss| iss == issuer.as_str())
        {
            return Ok(());
        }

        Err(authorize::error::IdTokenHintIssuerInvalid.into_error())
    }

    fn validate_redirect_uri(
        &self,
        client: &OpenIdConnectClient,
        redirect_uri: &str,
    ) -> Result<(), AppError> {
        let allowed = client.has_redirect_uri_str(redirect_uri);

        if !allowed {
            return Err(authorize::error::RedirectUriNotRegistered.into_error());
        }

        Ok(())
    }

    fn validate_client_scope_assignment(
        client: &OpenIdConnectClient,
        scope: &ScopeSet,
    ) -> Result<(), AppError> {
        let unassigned = scope
            .names()
            .into_iter()
            .filter(|name| !client.has_assigned_scope(name))
            .collect::<Vec<_>>();

        if !unassigned.is_empty() {
            return Err(
                authorize::error::ScopeNotAssignedToClient::new(unassigned.join(", ")).into_error(),
            );
        }

        Ok(())
    }

    pub fn should_skip_consent(&self, client: &OpenIdConnectClient) -> bool {
        client.metadata().settings.skip_consent
    }
}
