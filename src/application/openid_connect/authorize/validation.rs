use super::*;
use identity_domain::openid_connect::{OAuthProtocolVersion, TokenEndpointAuthMethod};

impl AuthorizeService {
    pub async fn validate_request(
        &self,
        params: AuthorizationRequestParams,
    ) -> Result<(AuthorizationRequest, OpenIdConnectClient), AppError> {
        use identity_domain::openid_connect::par::PAR_REQUEST_URI_PREFIX;
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
                return Err(AppError::from_code(
                    crate::error::codes::common::CommonErrorCode::InvalidRequest,
                ));
            }
            let client_oid = Uuid::parse_str(&params.client_id)
                .map_err(|_| AppError::from_code(AuthorizeErrorCode::RequestUriInvalid))?;
            let stored = self
                .client_authorization_repo
                .consume_pushed_authorization_request(
                    &crate::openid_connect::par::request_uri_digest(uri),
                    client_oid,
                    chrono::Utc::now(),
                )
                .await
                .map_err(|error| {
                    AppError::from_code(
                        crate::error::codes::common::CommonErrorCode::PushedRequestStorageFailed,
                    )
                    .with_source(error)
                })?
                .ok_or_else(|| AppError::from_code(AuthorizeErrorCode::RequestUriInvalid))?;
            let stored = stored.parameters;
            if stored.client_id != params.client_id || stored.request_uri.is_some() {
                return Err(AppError::from_code(AuthorizeErrorCode::RequestUriInvalid));
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
            return Err(AppError::from_code(
                crate::error::codes::common::CommonErrorCode::InvalidRequest,
            ));
        }
        self.validate_request_params(params, true).await
    }

    async fn validate_request_params(
        &self,
        mut params: AuthorizationRequestParams,
        pushed: bool,
    ) -> Result<(AuthorizationRequest, OpenIdConnectClient), AppError> {
        Self::validate_request_parameter_conflicts(&params)?;

        if params.client_id.trim().is_empty()
            && let Some(request) = params.request.as_deref()
            && let Some(client_id) = Self::extract_request_object_client_id(request)?
        {
            params.client_id = client_id;
        }

        if params.client_id.trim().is_empty() {
            Self::validate_required_params(&params)?;
        }

        let client_id = Uuid::parse_str(&params.client_id).map_err(|error| {
            AppError::from_code(AuthorizeErrorCode::ClientIdInvalid).with_source(error)
        })?;

        let client = self
            .client_repo
            .find_by_oid(client_id)
            .await
            .map_err(|error| {
                AppError::from_code(AuthorizeErrorCode::ClientLookupFailed).with_source(error)
            })?
            .ok_or_else(|| AppError::from_code(AuthorizeErrorCode::ClientNotFound))?;

        if !pushed
            && (self
                .provider_service
                .pushed_authorization_settings()
                .require_pushed_authorization_requests
                || client
                    .metadata()
                    .settings
                    .require_pushed_authorization_requests)
        {
            return Err(AppError::from_code(
                crate::error::codes::common::CommonErrorCode::InvalidRequest,
            ));
        }

        let oauth_version = self.provider_service.oauth_version(&client);

        if let Some(raw_request_object) = self.resolve_request_object(&client, &params).await? {
            let payload = self
                .parse_request_object_payload(&client, &raw_request_object)
                .await?;
            if pushed
                && payload.get("client_id").and_then(serde_json::Value::as_str)
                    != Some(params.client_id.as_str())
            {
                return Err(
                    AppError::from_code(AuthorizeErrorCode::RequestObjectFieldMismatch)
                        .with_param("field", "client_id"),
                );
            }
            Self::validate_request_object_claims(
                &params,
                &payload,
                &self.provider_service.issuer()?,
            )?;
            params = Self::merge_request_object_params(params, &payload)?;
        }

        Self::validate_id_token_hint_issuer(
            params.id_token_hint.as_deref(),
            &self.provider_service.issuer()?,
        )?;
        Self::validate_required_params(&params)?;

        let response_type = params
            .response_type
            .parse::<ResponseType>()
            .map_err(|error| {
                AppError::from_code(AuthorizeErrorCode::ResponseTypeInvalid)
                    .with_param("response_type", params.response_type.as_str())
                    .with_source(error)
            })?;

        if !client.allows_response_type(&response_type) {
            return Err(
                AppError::from_code(AuthorizeErrorCode::ClientGrantNotAllowed)
                    .with_param("response_type", response_type.to_string()),
            );
        }

        let redirect_uri_was_supplied = !params.redirect_uri.trim().is_empty();
        if !redirect_uri_was_supplied
            && !ScopeSet::parse(&params.scope).is_ok_and(|scope| scope.contains_openid())
        {
            if let Some(only_uri) = client.single_redirect_uri() {
                params.redirect_uri = only_uri.to_owned();
            }
        }
        if params.redirect_uri.trim().is_empty() {
            return Err(
                AppError::from_code(AuthorizeErrorCode::RequiredParamMissing)
                    .with_param("field", "redirect_uri"),
            );
        }

        let redirect_uri = Url::parse(&params.redirect_uri).map_err(|error| {
            AppError::from_code(AuthorizeErrorCode::RedirectUriInvalid).with_source(error)
        })?;

        let response_mode = match params.response_mode {
            Some(value) => Some(value.parse::<ResponseMode>().map_err(|error| {
                AppError::from_code(AuthorizeErrorCode::ResponseModeInvalid)
                    .with_param("response_mode", value)
                    .with_source(error)
            })?),
            None => None,
        };

        self.provider_service
            .validate_scope_names(&params.scope)
            .await?;
        let scope = ScopeSet::parse(&params.scope).map_err(|error| {
            AppError::from_code(AuthorizeErrorCode::ScopeInvalid).with_source(error)
        })?;

        let resources = self
            .provider_service
            .validate_authorization_resources(&params.resources, &scope)
            .await?;

        // An identity token only exists in OIDC, so the response types that
        // ask for one demand `openid`. Code and token responses work as plain
        // OAuth authorizations without it (RFC 6749 §3.1.1); the token
        // endpoint then issues no ID token for that grant.
        if response_type.includes_id_token() && !scope.contains_openid() {
            return Err(AppError::from_code(AuthorizeErrorCode::OpenidScopeRequired));
        }
        Self::validate_client_scope_assignment(&client, &scope)?;

        let display = match params.display {
            Some(value) => Some(value.parse::<Display>().map_err(|error| {
                AppError::from_code(AuthorizeErrorCode::DisplayValueInvalid)
                    .with_param("display", value)
                    .with_source(error)
            })?),
            None => None,
        };

        let prompt = match params.prompt {
            Some(value) => Some(
                value
                    .split_whitespace()
                    .map(|item| {
                        item.parse::<PromptValue>().map_err(|error| {
                            AppError::from_code(AuthorizeErrorCode::PromptValueInvalid)
                                .with_param("prompt", item)
                                .with_source(error)
                        })
                    })
                    .collect::<Result<std::collections::HashSet<_>, _>>()?,
            ),
            None => None,
        };

        if let Some(ref prompt_set) = prompt
            && prompt_set.contains(&PromptValue::None)
            && prompt_set.len() > 1
        {
            return Err(AppError::from_code(AuthorizeErrorCode::PromptNoneCombined));
        }

        let max_age = params
            .max_age
            .map(|value| value.parse::<i32>())
            .transpose()
            .map_err(|error| {
                AppError::from_code(AuthorizeErrorCode::MaxAgeInvalid).with_source(error)
            })?
            .or_else(|| {
                scope
                    .contains_openid()
                    .then_some(client.metadata().default_max_age)
                    .flatten()
            });
        if max_age.is_some_and(|value| value < 0) {
            return Err(AppError::from_code(AuthorizeErrorCode::MaxAgeInvalid));
        }

        let request_uri = params
            .request_uri
            .map(|value| Url::parse(&value))
            .transpose()
            .map_err(|error| {
                AppError::from_code(AuthorizeErrorCode::RequestUriInvalid).with_source(error)
            })?;

        let code_challenge_method = match params.code_challenge_method {
            Some(value) => Some(value.parse::<CodeChallengeMethod>().map_err(|error| {
                AppError::from_code(AuthorizeErrorCode::CodeChallengeMethodInvalid)
                    .with_param("code_challenge_method", value)
                    .with_source(error)
            })?),
            None => None,
        };

        let has_code_challenge = params
            .code_challenge
            .as_deref()
            .is_some_and(|challenge| !challenge.is_empty());
        if params.code_challenge.is_some() || code_challenge_method.is_some() {
            if !has_code_challenge {
                return Err(
                    AppError::from_code(AuthorizeErrorCode::RequiredParamMissing)
                        .with_param("field", "code_challenge"),
                );
            }
            if oauth_version == OAuthProtocolVersion::V2_1
                && code_challenge_method != Some(CodeChallengeMethod::S256)
            {
                return Err(
                    AppError::from_code(AuthorizeErrorCode::CodeChallengeMethodInvalid)
                        .with_param("code_challenge_method", "S256 required"),
                );
            }
        }

        let public_only = client.metadata().effective_token_endpoint_auth_methods()
            == [TokenEndpointAuthMethod::None];
        if public_only && !client.metadata().settings.allow_public_client_flow {
            return Err(AppError::from_code(AuthorizeErrorCode::ResponseTypeInvalid)
                .with_param("response_type", response_type.to_string()));
        }
        if public_only && response_type.includes_code() {
            if !has_code_challenge {
                return Err(
                    AppError::from_code(AuthorizeErrorCode::RequiredParamMissing)
                        .with_param("field", "code_challenge"),
                );
            }
            if code_challenge_method != Some(CodeChallengeMethod::S256) {
                return Err(
                    AppError::from_code(AuthorizeErrorCode::CodeChallengeMethodInvalid)
                        .with_param("code_challenge_method", "S256 required"),
                );
            }
        }

        if oauth_version == OAuthProtocolVersion::V2_1 && response_type.includes_access_token() {
            return Err(AppError::from_code(AuthorizeErrorCode::ResponseTypeInvalid)
                .with_param("response_type", response_type.to_string()));
        }
        if oauth_version == OAuthProtocolVersion::V2_1
            && response_type.includes_code()
            && !has_code_challenge
        {
            return Err(
                AppError::from_code(AuthorizeErrorCode::RequiredParamMissing)
                    .with_param("field", "code_challenge"),
            );
        }

        let claims = params
            .claims
            .as_deref()
            .map(Self::parse_claims_request)
            .transpose()?;

        self.validate_redirect_uri(&client, &params.redirect_uri)?;

        let acr_values = params
            .acr_values
            .map(|value| value.split_whitespace().map(str::to_owned).collect())
            .or_else(|| {
                scope
                    .contains_openid()
                    .then(|| client.metadata().default_acr_values.clone())
                    .flatten()
            });
        let request = AuthorizationRequest {
            response_type,
            response_mode,
            client_id,
            redirect_uri,
            redirect_uri_raw: params.redirect_uri,
            redirect_uri_was_supplied,
            scope,
            resources,
            state: params.state,
            nonce: params.nonce,
            display,
            prompt,
            max_age,
            ui_locales: params
                .ui_locales
                .map(|value| value.split_whitespace().map(str::to_owned).collect()),
            claims_locales: params
                .claims_locales
                .map(|value| value.split_whitespace().map(str::to_owned).collect()),
            id_token_hint: params.id_token_hint,
            login_hint: params.login_hint,
            acr_values,
            claims,
            request_uri,
            code_challenge: params.code_challenge,
            code_challenge_method,
        };

        Ok((request, client))
    }

    fn validate_request_parameter_conflicts(
        params: &AuthorizationRequestParams,
    ) -> Result<(), AppError> {
        if params.request.is_some() && params.request_uri.is_some() {
            return Err(AppError::from_code(
                AuthorizeErrorCode::RequestAndUriConflict,
            ));
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
                AppError::from_code(AuthorizeErrorCode::RequiredParamMissing)
                    .with_param("fields", missing_fields.join(", ")),
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
            .ok_or_else(|| AppError::from_code(AuthorizeErrorCode::IdTokenHintIssuerInvalid))?;
        let header = URL_SAFE_NO_PAD.decode(header_segment).map_err(|error| {
            AppError::from_code(AuthorizeErrorCode::IdTokenHintIssuerInvalid).with_source(error)
        })?;
        let header = serde_json::from_slice::<serde_json::Value>(&header).map_err(|error| {
            AppError::from_code(AuthorizeErrorCode::IdTokenHintIssuerInvalid).with_source(error)
        })?;
        if !cfg!(feature = "allow-none-alg")
            && header
                .get(JwtClaimNames::ALG)
                .and_then(|value| value.as_str())
                .is_none_or(|alg| alg.eq_ignore_ascii_case("none"))
        {
            return Err(AppError::from_code(
                AuthorizeErrorCode::IdTokenHintIssuerInvalid,
            ));
        }

        let payload_segment = raw
            .split('.')
            .nth(1)
            .ok_or_else(|| AppError::from_code(AuthorizeErrorCode::IdTokenHintIssuerInvalid))?;
        let payload = URL_SAFE_NO_PAD.decode(payload_segment).map_err(|error| {
            AppError::from_code(AuthorizeErrorCode::IdTokenHintIssuerInvalid).with_source(error)
        })?;
        let payload = serde_json::from_slice::<serde_json::Value>(&payload).map_err(|error| {
            AppError::from_code(AuthorizeErrorCode::IdTokenHintIssuerInvalid).with_source(error)
        })?;

        if payload
            .get(JwtClaimNames::ISS)
            .and_then(|value| value.as_str())
            .is_some_and(|iss| iss == issuer.as_str())
        {
            return Ok(());
        }

        Err(AppError::from_code(
            AuthorizeErrorCode::IdTokenHintIssuerInvalid,
        ))
    }

    fn validate_redirect_uri(
        &self,
        client: &OpenIdConnectClient,
        redirect_uri: &str,
    ) -> Result<(), AppError> {
        let allowed = client.has_redirect_uri_str(redirect_uri);

        if !allowed {
            return Err(AppError::from_code(
                AuthorizeErrorCode::RedirectUriNotRegistered,
            ));
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
                AppError::from_code(AuthorizeErrorCode::ScopeNotAssignedToClient)
                    .with_param("scopes", unassigned.join(", ")),
            );
        }

        Ok(())
    }

    pub fn should_skip_consent(&self, client: &OpenIdConnectClient) -> bool {
        client.metadata().settings.skip_consent
    }
}
