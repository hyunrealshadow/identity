use std::collections::HashSet;

use identity_domain::openid_connect::{
    AuthorizationRequest, CodeChallengeMethod, Display, OAuthProtocolVersion, OpenIdConnectClient,
    PromptValue, ResponseMode, ResponseType, ScopeSet, TokenEndpointAuthMethod,
};
use serde_json::Value;
use url::Url;
use uuid::Uuid;

use crate::{
    error::{
        AppError,
        codes::{authorize::AuthorizeErrorCode, common::CommonErrorCode},
    },
    openid_connect::authorize::{AuthorizationRequestParams, AuthorizeService},
};

pub(super) struct LoadedAuthorizationClient {
    pub(super) params: AuthorizationRequestParams,
    pub(super) client: OpenIdConnectClient,
    pub(super) client_id: Uuid,
    pub(super) oauth_version: OAuthProtocolVersion,
}

struct InteractionParameters {
    display: Option<Display>,
    prompt: Option<HashSet<PromptValue>>,
    max_age: Option<i32>,
    request_uri: Option<Url>,
}

impl AuthorizeService {
    pub(super) async fn load_authorization_client(
        &self,
        mut params: AuthorizationRequestParams,
        pushed: bool,
    ) -> Result<LoadedAuthorizationClient, AppError> {
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

        let client_id = Uuid::parse_str(&params.client_id)
            .map_err(AppError::map_source(AuthorizeErrorCode::ClientIdInvalid))?;

        let client = self
            .client_repo
            .find_by_oid(client_id)
            .await
            .map_err(AppError::map_source(AuthorizeErrorCode::ClientLookupFailed))?
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
            return Err(AppError::from_code(CommonErrorCode::InvalidRequest));
        }

        let oauth_version = self.provider_service.oauth_version(&client);

        Ok(LoadedAuthorizationClient {
            params,
            client,
            client_id,
            oauth_version,
        })
    }

    pub(super) async fn process_authorization_request_object(
        &self,
        mut params: AuthorizationRequestParams,
        client: &OpenIdConnectClient,
        pushed: bool,
    ) -> Result<AuthorizationRequestParams, AppError> {
        if let Some(raw_request_object) = self.resolve_request_object(client, &params).await? {
            let payload = self
                .parse_request_object_payload(client, &raw_request_object)
                .await?;
            if pushed
                && payload.get("client_id").and_then(Value::as_str)
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

        Ok(params)
    }

    pub(super) async fn parse_authorization_parameters(
        &self,
        mut params: AuthorizationRequestParams,
        client: &OpenIdConnectClient,
        client_id: Uuid,
        oauth_version: OAuthProtocolVersion,
    ) -> Result<AuthorizationRequest, AppError> {
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
            && let Some(only_uri) = client.single_redirect_uri()
        {
            params.redirect_uri = only_uri.to_owned();
        }
        if params.redirect_uri.trim().is_empty() {
            return Err(
                AppError::from_code(AuthorizeErrorCode::RequiredParamMissing)
                    .with_param("field", "redirect_uri"),
            );
        }

        let redirect_uri = Url::parse(&params.redirect_uri)
            .map_err(AppError::map_source(AuthorizeErrorCode::RedirectUriInvalid))?;

        let response_mode = match params.response_mode.as_deref() {
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
        let scope = ScopeSet::parse(&params.scope)
            .map_err(AppError::map_source(AuthorizeErrorCode::ScopeInvalid))?;

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
        Self::validate_client_scope_assignment(client, &scope)?;

        let InteractionParameters {
            display,
            prompt,
            max_age,
            request_uri,
        } = Self::parse_interaction_parameters(&params, client, &scope)?;

        let code_challenge_method = Self::validate_authorization_pkce(
            client,
            oauth_version,
            &response_type,
            params.code_challenge.as_deref(),
            params.code_challenge_method.as_deref(),
        )?;

        let claims = params
            .claims
            .as_deref()
            .map(Self::parse_claims_request)
            .transpose()?;

        self.validate_redirect_uri(client, &params.redirect_uri)?;

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

        Ok(request)
    }

    fn parse_interaction_parameters(
        params: &AuthorizationRequestParams,
        client: &OpenIdConnectClient,
        scope: &ScopeSet,
    ) -> Result<InteractionParameters, AppError> {
        let display = match params.display.as_deref() {
            Some(value) => Some(value.parse::<Display>().map_err(|error| {
                AppError::from_code(AuthorizeErrorCode::DisplayValueInvalid)
                    .with_param("display", value)
                    .with_source(error)
            })?),
            None => None,
        };

        let prompt = match params.prompt.as_deref() {
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
                    .collect::<Result<HashSet<_>, _>>()?,
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
            .as_deref()
            .map(|value| value.parse::<i32>())
            .transpose()
            .map_err(AppError::map_source(AuthorizeErrorCode::MaxAgeInvalid))?
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
            .as_deref()
            .map(Url::parse)
            .transpose()
            .map_err(AppError::map_source(AuthorizeErrorCode::RequestUriInvalid))?;

        Ok(InteractionParameters {
            display,
            prompt,
            max_age,
            request_uri,
        })
    }

    fn validate_authorization_pkce(
        client: &OpenIdConnectClient,
        oauth_version: OAuthProtocolVersion,
        response_type: &ResponseType,
        challenge: Option<&str>,
        method: Option<&str>,
    ) -> Result<Option<CodeChallengeMethod>, AppError> {
        let code_challenge_method = match method {
            Some(value) => Some(value.parse::<CodeChallengeMethod>().map_err(|error| {
                AppError::from_code(AuthorizeErrorCode::CodeChallengeMethodInvalid)
                    .with_param("code_challenge_method", value)
                    .with_source(error)
            })?),
            None => None,
        };

        let has_code_challenge = challenge.is_some_and(|challenge| !challenge.is_empty());
        if challenge.is_some() || code_challenge_method.is_some() {
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

        Ok(code_challenge_method)
    }
}
