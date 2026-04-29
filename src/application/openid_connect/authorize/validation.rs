use super::*;

impl AuthorizeService {
    pub async fn validate_request(
        &self,
        mut params: AuthorizationRequestParams,
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

        if let Some(raw_request_object) = self.resolve_request_object(&client, &params).await? {
            let payload = self
                .parse_request_object_payload(&client, &raw_request_object)
                .await?;
            Self::validate_request_object_claims(
                &params,
                &payload,
                &self.provider_service.issuer()?,
            )?;
            params = Self::merge_request_object_params(params, &payload)?;
        }

        Self::validate_required_params(&params)?;

        let response_type = params
            .response_type
            .parse::<ResponseType>()
            .map_err(|error| {
                AppError::from_code(AuthorizeErrorCode::ResponseTypeInvalid).with_source(error)
            })?;

        let redirect_uri = Url::parse(&params.redirect_uri).map_err(|error| {
            AppError::from_code(AuthorizeErrorCode::RedirectUriInvalid).with_source(error)
        })?;

        let response_mode = params
            .response_mode
            .map(|value| value.parse::<ResponseMode>())
            .transpose()
            .map_err(|error| {
                AppError::from_code(AuthorizeErrorCode::ResponseTypeInvalid).with_source(error)
            })?;

        let scope = ScopeSet::parse(&params.scope).map_err(|error| {
            AppError::from_code(AuthorizeErrorCode::ScopeInvalid).with_source(error)
        })?;

        if !scope.contains_openid() {
            return Err(AppError::from_code(AuthorizeErrorCode::OpenidScopeRequired));
        }
        Self::validate_client_scope_assignment(&client, &scope)?;

        let display = params
            .display
            .map(|value| value.parse::<Display>())
            .transpose()
            .map_err(|error| {
                AppError::from_code(AuthorizeErrorCode::DisplayValueInvalid).with_source(error)
            })?;

        let prompt = params
            .prompt
            .map(|value| {
                value
                    .split_whitespace()
                    .map(|item| item.parse::<PromptValue>())
                    .collect::<Result<std::collections::HashSet<_>, _>>()
            })
            .transpose()
            .map_err(|error| {
                AppError::from_code(AuthorizeErrorCode::PromptValueInvalid).with_source(error)
            })?;

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
            })?;

        let request_uri = params
            .request_uri
            .map(|value| Url::parse(&value))
            .transpose()
            .map_err(|error| {
                AppError::from_code(AuthorizeErrorCode::RequestUriInvalid).with_source(error)
            })?;

        let code_challenge_method = params
            .code_challenge_method
            .map(|value| value.parse::<CodeChallengeMethod>())
            .transpose()
            .map_err(|error| {
                AppError::from_code(AuthorizeErrorCode::CodeChallengeMethodInvalid)
                    .with_source(error)
            })?;

        let claims = params
            .claims
            .as_deref()
            .map(Self::parse_claims_request)
            .transpose()?;

        let request = AuthorizationRequest {
            response_type,
            response_mode,
            client_id,
            redirect_uri,
            scope,
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
            acr_values: params
                .acr_values
                .map(|value| value.split_whitespace().map(str::to_owned).collect()),
            claims,
            request_uri,
            code_challenge: params.code_challenge,
            code_challenge_method,
        };

        self.validate_redirect_uri(&client, &request.redirect_uri)?;

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
            ("redirect_uri", params.redirect_uri.as_str()),
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

    fn validate_redirect_uri(
        &self,
        client: &OpenIdConnectClient,
        redirect_uri: &Url,
    ) -> Result<(), AppError> {
        let allowed = client.has_redirect_uri(redirect_uri);

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
