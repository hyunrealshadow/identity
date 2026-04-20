use std::{sync::Arc, time::Duration};

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use josekit::{jws::RS256, jwt};
use url::Url;
use uuid::Uuid;

use crate::{
    application::{
        data_protection::DataProtector,
        error::{AppError, codes::authorize::AuthorizeErrorCode},
        openid_connect::provider::OpenIdProviderService,
    },
    domain::{
        auth::repository::LoginRepository,
        client_request::{ClientRequestRepository, ClientRequestType},
        openid_connect::{
            AuthorizationRequest, AuthorizationRequestData, CodeChallengeMethod, Display,
            OAuthErrorCode, OAuthErrorResponse, OpenIdConnectClient, OpenIdConnectClientRepository,
            OpenIdConnectCredentialData, OpenIdConnectCredentialRepository,
            OpenIdConnectCredentialType, PromptValue, ResponseType, ScopeSet,
            model::authorization_request::ClaimsRequest, model::claim::JwtClaimNames,
        },
    },
};

#[derive(Debug, Clone)]
pub struct AuthorizationRequestParams {
    pub response_type: String,
    pub client_id: String,
    pub redirect_uri: String,
    pub scope: String,
    pub state: String,
    pub nonce: Option<String>,
    pub display: Option<String>,
    pub prompt: Option<String>,
    pub max_age: Option<String>,
    pub ui_locales: Option<String>,
    pub claims_locales: Option<String>,
    pub id_token_hint: Option<String>,
    pub login_hint: Option<String>,
    pub acr_values: Option<String>,
    pub claims: Option<String>,
    pub request: Option<String>,
    pub request_uri: Option<String>,
    pub code_challenge: Option<String>,
    pub code_challenge_method: Option<String>,
}

pub struct AuthorizeService {
    client_repo: Arc<dyn OpenIdConnectClientRepository>,
    credential_repo: Arc<dyn OpenIdConnectCredentialRepository>,
    client_request_repo: Arc<dyn ClientRequestRepository>,
    login_repo: Arc<dyn LoginRepository>,
    provider_service: Arc<OpenIdProviderService>,
    http_client: reqwest::Client,
    data_protector: Arc<dyn DataProtector>,
}

impl AuthorizeService {
    pub fn new(
        client_repo: Arc<dyn OpenIdConnectClientRepository>,
        credential_repo: Arc<dyn OpenIdConnectCredentialRepository>,
        client_request_repo: Arc<dyn ClientRequestRepository>,
        login_repo: Arc<dyn LoginRepository>,
        provider_service: Arc<OpenIdProviderService>,
        data_protector: Arc<dyn DataProtector>,
    ) -> Self {
        Self {
            client_repo,
            credential_repo,
            client_request_repo,
            login_repo,
            provider_service,
            http_client: reqwest::Client::builder()
                .redirect(reqwest::redirect::Policy::none())
                .timeout(Duration::from_secs(5))
                .build()
                .expect("request_uri HTTP client must build"),
            data_protector,
        }
    }

    pub async fn encrypt_login_id(&self, login_oid: Uuid) -> Result<String, AppError> {
        self.data_protector
            .protect("login-id", login_oid.as_bytes())
            .await
            .map_err(|error| {
                AppError::from_code(AuthorizeErrorCode::LoginIdInvalid).with_source(error)
            })
    }

    pub async fn decrypt_login_id(&self, protected_login_id: &str) -> Result<Uuid, AppError> {
        let bytes = self
            .data_protector
            .unprotect("login-id", protected_login_id)
            .await
            .map_err(|error| {
                AppError::from_code(AuthorizeErrorCode::LoginIdInvalid).with_source(error)
            })?;

        Uuid::from_slice(&bytes).map_err(|error| {
            AppError::from_code(AuthorizeErrorCode::LoginIdInvalid).with_source(error)
        })
    }

    pub async fn validate_request(
        &self,
        mut params: AuthorizationRequestParams,
    ) -> Result<(AuthorizationRequest, OpenIdConnectClient), AppError> {
        Self::validate_request_parameter_conflicts(&params)?;

        if params.client_id.trim().is_empty() {
            if let Some(request) = params.request.as_deref() {
                if let Some(client_id) = Self::extract_request_object_client_id(request)? {
                    params.client_id = client_id;
                }
            }
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

        let scope = ScopeSet::parse(&params.scope).map_err(|error| {
            AppError::from_code(AuthorizeErrorCode::ScopeInvalid).with_source(error)
        })?;

        if !scope.contains_openid() {
            return Err(AppError::from_code(AuthorizeErrorCode::OpenidScopeRequired));
        }

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

    async fn resolve_request_object(
        &self,
        client: &OpenIdConnectClient,
        params: &AuthorizationRequestParams,
    ) -> Result<Option<String>, AppError> {
        if let Some(request) = params.request.clone() {
            return Ok(Some(request));
        }

        if let Some(request_uri) = params.request_uri.clone() {
            let request_uri = Url::parse(&request_uri).map_err(|error| {
                AppError::from_code(AuthorizeErrorCode::RequestUriInvalid).with_source(error)
            })?;
            self.validate_request_uri(client, &request_uri)?;
            let raw_request_object = self.fetch_request_object(&request_uri).await?;
            return Ok(Some(raw_request_object));
        }

        Ok(None)
    }

    fn validate_redirect_uri(
        &self,
        client: &OpenIdConnectClient,
        redirect_uri: &Url,
    ) -> Result<(), AppError> {
        let allowed = client
            .metadata()
            .redirect_uris
            .as_ref()
            .filter(|uris| uris.iter().any(|uri| uri == redirect_uri));

        if allowed.is_none() {
            return Err(AppError::from_code(
                AuthorizeErrorCode::RedirectUriNotRegistered,
            ));
        }

        Ok(())
    }

    pub fn is_internal_client(&self, client: &OpenIdConnectClient) -> bool {
        client.metadata().internal_client.unwrap_or(false)
    }

    pub fn should_skip_consent(&self, client: &OpenIdConnectClient) -> bool {
        client.metadata().skip_consent.unwrap_or(false)
    }

    fn validate_request_uri(
        &self,
        client: &OpenIdConnectClient,
        request_uri: &Url,
    ) -> Result<(), AppError> {
        if request_uri.scheme() != "https" {
            return Err(AppError::from_code(AuthorizeErrorCode::RequestUriNotHttps));
        }

        if request_uri.fragment().is_some() {
            return Err(AppError::from_code(
                AuthorizeErrorCode::RequestUriHasFragment,
            ));
        }

        let is_unsafe_target = match request_uri.host() {
            Some(url::Host::Ipv4(address)) => {
                let octets = address.octets();
                address.is_loopback()
                    // RFC 1918 Class A: 10.0.0.0/8
                    || octets[0] == 10
                    // RFC 1918 Class B: 172.16.0.0/12
                    || (octets[0] == 172 && (16..=31).contains(&octets[1]))
                    // RFC 1918 Class C: 192.168.0.0/16
                    || (octets[0] == 192 && octets[1] == 168)
                    // Link-local: 169.254.0.0/16
                    || (octets[0] == 169 && octets[1] == 254)
            }
            Some(url::Host::Ipv6(address)) => {
                let segments = address.segments();
                address.is_loopback()
                    // ULA: fc00::/7 (fc00:: through fdff::)
                    || (segments[0] & 0xfe00) == 0xfc00
                    // Link-local: fe80::/10
                    || (segments[0] & 0xffc0) == 0xfe80
            }
            Some(url::Host::Domain(domain)) => domain.eq_ignore_ascii_case("localhost"),
            None => true,
        };

        if is_unsafe_target {
            return Err(AppError::from_code(
                AuthorizeErrorCode::RequestUriUnsafeHost,
            ));
        }

        let registered = client
            .metadata()
            .request_uris
            .as_ref()
            .map(|uris| uris.iter().any(|uri| uri == request_uri))
            .unwrap_or(false);

        if !registered {
            return Err(AppError::from_code(
                AuthorizeErrorCode::RequestUriNotRegistered,
            ));
        }

        Ok(())
    }

    async fn fetch_request_object(&self, request_uri: &Url) -> Result<String, AppError> {
        const MAX_REQUEST_OBJECT_BYTES: usize = 1024 * 1024;

        let mut response = self
            .http_client
            .get(request_uri.clone())
            .send()
            .await
            .map_err(|error| {
                AppError::from_code(AuthorizeErrorCode::RequestUriFetchFailed).with_source(error)
            })?;

        if response.status() != reqwest::StatusCode::OK {
            return Err(AppError::from_code(AuthorizeErrorCode::RequestUriNot200));
        }

        if response
            .content_length()
            .is_some_and(|length| length > MAX_REQUEST_OBJECT_BYTES as u64)
        {
            return Err(AppError::from_code(AuthorizeErrorCode::RequestUriTooLarge));
        }

        let mut body = Vec::new();
        while let Some(chunk) = response.chunk().await.map_err(|error| {
            AppError::from_code(AuthorizeErrorCode::RequestUriReadFailed).with_source(error)
        })? {
            if body.len() + chunk.len() > MAX_REQUEST_OBJECT_BYTES {
                return Err(AppError::from_code(AuthorizeErrorCode::RequestUriTooLarge));
            }

            body.extend_from_slice(&chunk);
        }

        String::from_utf8(body).map_err(|error| {
            AppError::from_code(AuthorizeErrorCode::RequestUriReadFailed).with_source(error)
        })
    }

    async fn parse_request_object_payload(
        &self,
        client: &OpenIdConnectClient,
        raw: &str,
    ) -> Result<serde_json::Value, AppError> {
        let header = jwt::decode_header(raw).map_err(|error| {
            AppError::from_code(AuthorizeErrorCode::RequestObjectHeaderInvalid).with_source(error)
        })?;

        let algorithm = header
            .claim(JwtClaimNames::ALG)
            .and_then(|value| value.as_str())
            .unwrap_or("none");
        let payload = match algorithm {
            "none" => {
                return Err(AppError::from_code(
                    AuthorizeErrorCode::RequestObjectAlgUnsupported,
                ));
            }
            "RS256" => self.verify_rs256_request_object(client, raw).await?,
            _ => {
                return Err(AppError::from_code(
                    AuthorizeErrorCode::RequestObjectAlgUnsupported,
                ));
            }
        };

        let mut value = serde_json::Map::new();
        for claim in [
            "response_type",
            "client_id",
            "redirect_uri",
            "scope",
            "state",
            "nonce",
            "display",
            "prompt",
            "max_age",
            "ui_locales",
            "claims_locales",
            "id_token_hint",
            "login_hint",
            "acr_values",
            "claims",
            "code_challenge",
            "code_challenge_method",
            "iss",
            "aud",
            "exp",
            "nbf",
            "iat",
        ] {
            if let Some(claim_value) = payload.claim(claim) {
                value.insert(claim.to_string(), claim_value.clone());
            }
        }

        Ok(serde_json::Value::Object(value))
    }

    async fn verify_rs256_request_object(
        &self,
        client: &OpenIdConnectClient,
        raw: &str,
    ) -> Result<jwt::JwtPayload, AppError> {
        let credentials = self
            .credential_repo
            .find_by_client_oid_and_type(
                client.client().oid,
                OpenIdConnectCredentialType::ClientPublicKey,
            )
            .await
            .map_err(|error| {
                AppError::from_code(AuthorizeErrorCode::CredentialLookupFailed).with_source(error)
            })?;

        for credential in credentials {
            if let OpenIdConnectCredentialData::ClientPublicKey { public_key } = credential.data {
                let verifier = RS256
                    .verifier_from_pem(public_key.as_bytes())
                    .map_err(|error| {
                        AppError::from_code(AuthorizeErrorCode::RequestObjectKeyInvalid)
                            .with_source(error)
                    })?;
                if let Ok((payload, _)) = jwt::decode_with_verifier(raw, &verifier) {
                    return Ok(payload);
                }
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
                AppError::from_code(AuthorizeErrorCode::CredentialLookupFailed).with_source(error)
            })?;

        for credential in jwks_credentials {
            if let OpenIdConnectCredentialData::ClientJsonWebKeySet { public_keys, .. } =
                credential.data
            {
                for public_key in public_keys {
                    let verifier =
                        RS256
                            .verifier_from_pem(public_key.as_bytes())
                            .map_err(|error| {
                                AppError::from_code(AuthorizeErrorCode::RequestObjectKeyInvalid)
                                    .with_source(error)
                            })?;
                    if let Ok((payload, _)) = jwt::decode_with_verifier(raw, &verifier) {
                        return Ok(payload);
                    }
                }
            }
        }

        Err(AppError::from_code(
            AuthorizeErrorCode::RequestObjectVerifyFailed,
        ))
    }

    fn merge_request_object_params(
        mut params: AuthorizationRequestParams,
        payload: &serde_json::Value,
    ) -> Result<AuthorizationRequestParams, AppError> {
        if let Some(value) = payload
            .get("response_type")
            .and_then(|value| value.as_str())
        {
            params.response_type = value.to_string();
        }
        if let Some(value) = payload.get("client_id").and_then(|value| value.as_str()) {
            params.client_id = value.to_string();
        }
        if let Some(value) = payload.get("redirect_uri").and_then(|value| value.as_str()) {
            params.redirect_uri = value.to_string();
        }
        if let Some(value) = payload.get("scope").and_then(|value| value.as_str()) {
            params.scope = value.to_string();
        }
        if let Some(value) = payload.get("state").and_then(|value| value.as_str()) {
            params.state = value.to_string();
        }
        if let Some(value) = payload.get("nonce").and_then(|value| value.as_str()) {
            params.nonce = Some(value.to_string());
        }
        if let Some(value) = payload.get("login_hint").and_then(|value| value.as_str()) {
            params.login_hint = Some(value.to_string());
        }
        if let Some(value) = payload.get("display").and_then(|value| value.as_str()) {
            params.display = Some(value.to_string());
        }
        if let Some(value) = payload.get("prompt").and_then(|value| value.as_str()) {
            params.prompt = Some(value.to_string());
        }
        if let Some(value) = payload.get("max_age") {
            if let Some(value) = value.as_i64() {
                params.max_age = Some(value.to_string());
            }
        }
        if let Some(value) = payload.get("ui_locales").and_then(|value| value.as_str()) {
            params.ui_locales = Some(value.to_string());
        }
        if let Some(value) = payload
            .get("claims_locales")
            .and_then(|value| value.as_str())
        {
            params.claims_locales = Some(value.to_string());
        }
        if let Some(value) = payload
            .get("id_token_hint")
            .and_then(|value| value.as_str())
        {
            params.id_token_hint = Some(value.to_string());
        }
        if let Some(value) = payload.get("acr_values").and_then(|value| value.as_str()) {
            params.acr_values = Some(value.to_string());
        }
        if let Some(value) = payload.get("claims") {
            params.claims = Some(value.to_string());
        }
        if let Some(value) = payload
            .get("code_challenge")
            .and_then(|value| value.as_str())
        {
            params.code_challenge = Some(value.to_string());
        }
        if let Some(value) = payload
            .get("code_challenge_method")
            .and_then(|value| value.as_str())
        {
            params.code_challenge_method = Some(value.to_string());
        }

        Ok(params)
    }

    fn validate_request_object_claims(
        params: &AuthorizationRequestParams,
        payload: &serde_json::Value,
        issuer: &Url,
    ) -> Result<(), AppError> {
        Self::validate_required_request_object_field(
            payload,
            "response_type",
            params.response_type.as_str(),
        )?;
        Self::validate_required_request_object_field(
            payload,
            "client_id",
            params.client_id.as_str(),
        )?;
        Self::validate_required_request_object_field(
            payload,
            "redirect_uri",
            params.redirect_uri.as_str(),
        )?;
        Self::validate_required_request_object_field(payload, "scope", params.scope.as_str())?;
        Self::validate_required_request_object_field(payload, "state", params.state.as_str())?;
        Self::validate_optional_request_object_field(payload, "nonce", params.nonce.as_deref())?;
        Self::validate_optional_request_object_field(
            payload,
            "display",
            params.display.as_deref(),
        )?;
        Self::validate_optional_request_object_field(payload, "prompt", params.prompt.as_deref())?;
        Self::validate_optional_numeric_request_object_field(
            payload,
            "max_age",
            params.max_age.as_deref(),
        )?;
        Self::validate_optional_request_object_field(
            payload,
            "ui_locales",
            params.ui_locales.as_deref(),
        )?;
        Self::validate_optional_request_object_field(
            payload,
            "claims_locales",
            params.claims_locales.as_deref(),
        )?;
        Self::validate_optional_request_object_field(
            payload,
            "id_token_hint",
            params.id_token_hint.as_deref(),
        )?;
        Self::validate_optional_request_object_field(
            payload,
            "login_hint",
            params.login_hint.as_deref(),
        )?;
        Self::validate_optional_request_object_field(
            payload,
            "acr_values",
            params.acr_values.as_deref(),
        )?;
        Self::validate_optional_json_request_object_field(
            payload,
            "claims",
            params.claims.as_deref(),
        )?;
        Self::validate_optional_request_object_field(
            payload,
            "code_challenge",
            params.code_challenge.as_deref(),
        )?;
        Self::validate_optional_request_object_field(
            payload,
            "code_challenge_method",
            params.code_challenge_method.as_deref(),
        )?;

        if let Some(iss) = payload
            .get(JwtClaimNames::ISS)
            .and_then(|value| value.as_str())
        {
            if iss != params.client_id {
                return Err(AppError::from_code(
                    AuthorizeErrorCode::RequestObjectIssMismatch,
                ));
            }
        }

        if let Some(aud) = payload.get(JwtClaimNames::AUD) {
            let issuer_value = issuer.as_str();
            let matches = aud
                .as_str()
                .map(|value| value == issuer_value)
                .unwrap_or_else(|| {
                    aud.as_array()
                        .map(|values| {
                            values
                                .iter()
                                .filter_map(|value| value.as_str())
                                .any(|value| value == issuer_value)
                        })
                        .unwrap_or(false)
                });

            if !matches {
                return Err(AppError::from_code(
                    AuthorizeErrorCode::RequestObjectAudMismatch,
                ));
            }
        }

        let now = chrono::Utc::now().timestamp();
        if let Some(exp) = payload
            .get(JwtClaimNames::EXP)
            .and_then(|value| value.as_i64())
        {
            if exp <= now {
                return Err(AppError::from_code(
                    AuthorizeErrorCode::RequestObjectExpired,
                ));
            }
        }

        if let Some(nbf) = payload
            .get(JwtClaimNames::NBF)
            .and_then(|value| value.as_i64())
        {
            if nbf > now {
                return Err(AppError::from_code(
                    AuthorizeErrorCode::RequestObjectNotYetValid,
                ));
            }
        }

        if let Some(iat) = payload
            .get(JwtClaimNames::IAT)
            .and_then(|value| value.as_i64())
        {
            if iat > now {
                return Err(AppError::from_code(
                    AuthorizeErrorCode::RequestObjectIatFuture,
                ));
            }
        }

        Ok(())
    }

    fn validate_required_request_object_field(
        payload: &serde_json::Value,
        field: &str,
        outer: &str,
    ) -> Result<(), AppError> {
        if outer.trim().is_empty() {
            return Ok(());
        }

        if let Some(inner) = payload.get(field).and_then(|value| value.as_str()) {
            if inner != outer {
                return Err(
                    AppError::from_code(AuthorizeErrorCode::RequestObjectFieldMismatch)
                        .with_param("field", field),
                );
            }
        }

        Ok(())
    }

    fn validate_optional_request_object_field(
        payload: &serde_json::Value,
        field: &str,
        outer: Option<&str>,
    ) -> Result<(), AppError> {
        if let (Some(inner), Some(outer)) =
            (payload.get(field).and_then(|value| value.as_str()), outer)
        {
            if inner != outer {
                return Err(
                    AppError::from_code(AuthorizeErrorCode::RequestObjectFieldMismatch)
                        .with_param("field", field),
                );
            }
        }

        Ok(())
    }

    fn validate_optional_numeric_request_object_field(
        payload: &serde_json::Value,
        field: &str,
        outer: Option<&str>,
    ) -> Result<(), AppError> {
        if let (Some(inner), Some(outer)) =
            (payload.get(field).and_then(|value| value.as_i64()), outer)
        {
            if inner.to_string() != outer {
                return Err(
                    AppError::from_code(AuthorizeErrorCode::RequestObjectFieldMismatch)
                        .with_param("field", field),
                );
            }
        }

        Ok(())
    }

    fn validate_optional_json_request_object_field(
        payload: &serde_json::Value,
        field: &str,
        outer: Option<&str>,
    ) -> Result<(), AppError> {
        if let (Some(inner), Some(outer)) = (payload.get(field), outer) {
            let outer = serde_json::from_str::<serde_json::Value>(outer).map_err(|error| {
                AppError::from_code(AuthorizeErrorCode::RequestObjectJsonInvalid).with_source(error)
            })?;

            if inner != &outer {
                return Err(
                    AppError::from_code(AuthorizeErrorCode::RequestObjectFieldMismatch)
                        .with_param("field", field),
                );
            }
        }

        Ok(())
    }

    fn parse_claims_request(raw: &str) -> Result<ClaimsRequest, AppError> {
        let value = serde_json::from_str::<serde_json::Value>(raw).map_err(|error| {
            AppError::from_code(AuthorizeErrorCode::ClaimsParamInvalid).with_source(error)
        })?;
        let object = value
            .as_object()
            .ok_or_else(|| AppError::from_code(AuthorizeErrorCode::ClaimsNotObject))?;

        let map_field =
            |field: &str| -> Result<Option<serde_json::Map<String, serde_json::Value>>, AppError> {
                match object.get(field) {
                    None => Ok(None),
                    Some(value) => value.as_object().cloned().map(Some).ok_or_else(|| {
                        AppError::from_code(AuthorizeErrorCode::ClaimsFieldNotObject)
                            .with_param("field", field)
                    }),
                }
            };

        Ok(ClaimsRequest {
            id_token: map_field("id_token")?,
            userinfo: map_field("userinfo")?,
        })
    }

    fn extract_request_object_client_id(raw: &str) -> Result<Option<String>, AppError> {
        let payload = Self::decode_request_object_payload_unverified(raw)?;
        Ok(payload
            .get("client_id")
            .and_then(|value| value.as_str())
            .map(str::to_owned))
    }

    fn decode_request_object_payload_unverified(raw: &str) -> Result<serde_json::Value, AppError> {
        let payload_segment = raw
            .split('.')
            .nth(1)
            .ok_or_else(|| AppError::from_code(AuthorizeErrorCode::RequestObjectEncodingInvalid))?;

        let payload = URL_SAFE_NO_PAD.decode(payload_segment).map_err(|error| {
            AppError::from_code(AuthorizeErrorCode::RequestObjectBase64Invalid).with_source(error)
        })?;

        serde_json::from_slice::<serde_json::Value>(&payload).map_err(|error| {
            AppError::from_code(AuthorizeErrorCode::RequestObjectPayloadInvalid).with_source(error)
        })
    }

    pub async fn create_authorization_request(
        &self,
        request: &AuthorizationRequest,
    ) -> Result<Uuid, AppError> {
        let data =
            serde_json::to_value(AuthorizationRequestData::from(request)).map_err(|error| {
                AppError::from_code(AuthorizeErrorCode::SerializeRequestFailed).with_source(error)
            })?;

        let record = self
            .client_request_repo
            .create(
                request.client_id,
                ClientRequestType::AuthorizationRequest,
                data,
                chrono::Utc::now() + chrono::Duration::minutes(10),
            )
            .await
            .map_err(|error| {
                AppError::from_code(AuthorizeErrorCode::StoreRequestFailed).with_source(error)
            })?;

        Ok(record.oid)
    }

    pub async fn create_login_flow(
        &self,
        client_oid: Uuid,
        authorization_request_id: Uuid,
        requested_acr: Option<&str>,
    ) -> Result<String, AppError> {
        let login = self
            .login_repo
            .create_pending(client_oid, authorization_request_id, requested_acr)
            .await
            .map_err(|error| {
                AppError::from_code(AuthorizeErrorCode::StoreLoginFailed).with_source(error)
            })?;

        self.encrypt_login_id(login.oid).await
    }

    pub async fn load_authorization_request(
        &self,
        authorization_request_id: Uuid,
    ) -> Result<AuthorizationRequestData, AppError> {
        let record = self
            .client_request_repo
            .find_by_oid(authorization_request_id)
            .await
            .map_err(|error| {
                AppError::from_code(AuthorizeErrorCode::LoadRequestFailed).with_source(error)
            })?
            .ok_or_else(|| AppError::from_code(AuthorizeErrorCode::AuthzRequestNotFound))?;

        if record.type_ != ClientRequestType::AuthorizationRequest {
            return Err(AppError::from_code(
                AuthorizeErrorCode::AuthzRequestTypeMismatch,
            ));
        }

        serde_json::from_value::<AuthorizationRequestData>(record.data).map_err(|error| {
            AppError::from_code(AuthorizeErrorCode::DeserializeRequestFailed).with_source(error)
        })
    }

    pub async fn load_consent_context(
        &self,
        authorization_request_id: Uuid,
    ) -> Result<(AuthorizationRequestData, OpenIdConnectClient), AppError> {
        let request = self
            .load_authorization_request(authorization_request_id)
            .await?;
        let client_id = Uuid::parse_str(&request.client_id).map_err(|error| {
            AppError::from_code(AuthorizeErrorCode::StoredClientIdInvalid).with_source(error)
        })?;
        let client = self
            .client_repo
            .find_by_oid(client_id)
            .await
            .map_err(|error| {
                AppError::from_code(AuthorizeErrorCode::ClientLookupFailed).with_source(error)
            })?
            .ok_or_else(|| AppError::from_code(AuthorizeErrorCode::ClientNotFound))?;

        Ok((request, client))
    }

    pub async fn load_consent_context_by_login(
        &self,
        protected_login_oid: &str,
    ) -> Result<
        (
            crate::domain::auth::model::Login,
            AuthorizationRequestData,
            OpenIdConnectClient,
        ),
        AppError,
    > {
        let login = self.load_login_by_protected_id(protected_login_oid).await?;
        let (request, client) = self.load_consent_context(login.client_request_oid).await?;
        Ok((login, request, client))
    }

    pub async fn load_login_by_protected_id(
        &self,
        protected_login_id: &str,
    ) -> Result<crate::domain::auth::model::Login, AppError> {
        let login_oid = self.decrypt_login_id(protected_login_id).await?;

        self.login_repo
            .find_by_oid(login_oid)
            .await
            .map_err(|error| {
                AppError::from_code(AuthorizeErrorCode::LoadLoginFailed).with_source(error)
            })?
            .ok_or_else(|| AppError::from_code(AuthorizeErrorCode::LoginNotFound))
    }

    pub async fn approve_authorization_request(
        &self,
        authorization_request_id: Uuid,
        session_oid: Uuid,
        user_oid: Uuid,
        auth_time: Option<i64>,
    ) -> Result<Url, AppError> {
        let request = self
            .load_authorization_request(authorization_request_id)
            .await?;
        let redirect_uri = Url::parse(&request.redirect_uri).map_err(|error| {
            AppError::from_code(AuthorizeErrorCode::StoredRedirectUriInvalid).with_source(error)
        })?;

        let record = self
            .client_request_repo
            .create(
                Uuid::parse_str(&request.client_id).map_err(|error| {
                    AppError::from_code(AuthorizeErrorCode::StoredClientIdInvalid)
                        .with_source(error)
                })?,
                ClientRequestType::AuthorizationCode,
                serde_json::to_value(crate::domain::client_request::AuthorizationCodeData {
                    scope: request.scope.clone(),
                    nonce: request.nonce.clone(),
                    code_challenge: request.code_challenge.clone(),
                    code_challenge_method: request.code_challenge_method.clone(),
                    user_oid: user_oid.to_string(),
                    session_oid: session_oid.to_string(),
                    acr: None,
                    redirect_uri: request.redirect_uri.clone(),
                    auth_time,
                })
                .map_err(|error| {
                    AppError::from_code(AuthorizeErrorCode::SerializeCodeFailed).with_source(error)
                })?,
                chrono::Utc::now() + chrono::Duration::minutes(10),
            )
            .await
            .map_err(|error| {
                AppError::from_code(AuthorizeErrorCode::StoreCodeFailed).with_source(error)
            })?;

        let protected_code = self
            .data_protector
            .protect("authorization-code", record.oid.as_bytes())
            .await
            .map_err(|error| {
                AppError::from_code(AuthorizeErrorCode::StoreCodeFailed).with_source(error)
            })?;

        let mut redirect = redirect_uri;
        redirect
            .query_pairs_mut()
            .append_pair("code", &protected_code)
            .append_pair("state", &request.state);

        Ok(redirect)
    }

    pub async fn approve_authorization_request_by_login(
        &self,
        protected_login_oid: &str,
        session_oid: Uuid,
        user_oid: Uuid,
        auth_time: Option<i64>,
    ) -> Result<Url, AppError> {
        let login = self.load_login_by_protected_id(protected_login_oid).await?;
        self.approve_authorization_request(login.client_request_oid, session_oid, user_oid, auth_time)
            .await
    }

    pub async fn deny_authorization_request(
        &self,
        authorization_request_id: Uuid,
    ) -> Result<Url, AppError> {
        let request = self
            .load_authorization_request(authorization_request_id)
            .await?;
        let redirect_uri = Url::parse(&request.redirect_uri).map_err(|error| {
            AppError::from_code(AuthorizeErrorCode::StoredRedirectUriInvalid).with_source(error)
        })?;
        Ok(OAuthErrorResponse::new(OAuthErrorCode::AccessDenied)
            .with_state(request.state)
            .to_redirect_url(&redirect_uri))
    }

    pub async fn deny_authorization_request_by_login(
        &self,
        protected_login_oid: &str,
    ) -> Result<Url, AppError> {
        let login = self.load_login_by_protected_id(protected_login_oid).await?;
        self.deny_authorization_request(login.client_request_oid)
            .await
    }
}

#[cfg(test)]
mod tests {
    use std::{
        collections::HashMap,
        sync::{Arc, Mutex},
    };

    use async_trait::async_trait;
    use axum::{Router, response::Redirect, routing::get};
    use base64::Engine;
    use chrono::Utc;
    use josekit::{
        jws::{JwsHeader, RS256},
        jwt::{self, JwtPayload},
    };
    use openssl::rsa::Rsa;
    use serde_json::json;
    use tokio::{
        io::AsyncWriteExt,
        net::TcpListener,
        time::{Duration, timeout},
    };
    use url::Url;
    use uuid::Uuid;

    use super::{AuthorizationRequestParams, AuthorizeService};
    use crate::application::{
        data_protection::{DataProtector, DataProtectorImpl},
        openid_connect::provider::OpenIdProviderService,
        setting::runtime::SettingProvider,
    };
    use crate::domain::{
        auth::{
            LoginStatus,
            model::Login,
            repository::{LoginRepository, LoginRepositoryError},
        },
        client::model::{Client, ClientProtocol},
        client_request::{
            ClientRequest, ClientRequestRepository, ClientRequestRepositoryError, ClientRequestType,
        },
        key::{
            Key, KeyData, KeyOid, KeyType,
            material::{SymmetricKeyAlgorithm, SymmetricKeyData},
            repository::{KeyRepository, KeyRepositoryError},
        },
        openid_connect::{
            OpenIdConnectClient, OpenIdConnectClientMetadata, OpenIdConnectClientRepository,
            OpenIdConnectClientRepositoryError, OpenIdConnectCredential,
            OpenIdConnectCredentialData, OpenIdConnectCredentialRepository,
            OpenIdConnectCredentialRepositoryError, OpenIdConnectCredentialType,
        },
        setting::installation::{InstallationSetting, InstallationState},
    };

    struct StaticInstallationProvider {
        value: Arc<InstallationState>,
    }

    impl SettingProvider<InstallationSetting> for StaticInstallationProvider {
        fn current_value(&self) -> Arc<InstallationState> {
            self.value.clone()
        }
    }

    fn provider_service() -> Arc<OpenIdProviderService> {
        Arc::new(OpenIdProviderService::new(Arc::new(
            StaticInstallationProvider {
                value: Arc::new(InstallationState {
                    initialized: true,
                    domain: Some("https://identity.example.com".to_string()),
                    first_user_oid: Some(Uuid::new_v4()),
                    first_key_oid: Some(Uuid::new_v4()),
                    initialized_at: Some(chrono::Utc::now()),
                }),
            },
        )))
    }

    struct MissingClientRepository;

    #[derive(Default)]
    struct InMemoryClientRequestRepository {
        records: Mutex<HashMap<Uuid, ClientRequest>>,
    }

    struct InMemoryLoginRepository;

    #[derive(Default)]
    struct InMemoryCredentialRepository {
        credentials: Mutex<Vec<OpenIdConnectCredential>>,
    }

    #[async_trait]
    impl ClientRequestRepository for InMemoryClientRequestRepository {
        async fn create(
            &self,
            client_oid: Uuid,
            type_: ClientRequestType,
            data: serde_json::Value,
            expires_at: chrono::DateTime<chrono::Utc>,
        ) -> Result<ClientRequest, ClientRequestRepositoryError> {
            let record = ClientRequest {
                oid: Uuid::new_v4(),
                client_oid,
                type_,
                data,
                expires_at,
                revoked_at: None,
                created_at: chrono::Utc::now(),
                updated_at: None,
            };
            self.records
                .lock()
                .unwrap()
                .insert(record.oid, record.clone());
            Ok(record)
        }

        async fn find_by_oid(
            &self,
            oid: Uuid,
        ) -> Result<Option<ClientRequest>, ClientRequestRepositoryError> {
            Ok(self.records.lock().unwrap().get(&oid).cloned())
        }

        async fn find_refresh_token_by_token(
            &self,
            token: &str,
        ) -> Result<Option<ClientRequest>, ClientRequestRepositoryError> {
            Ok(self
                .records
                .lock()
                .unwrap()
                .values()
                .find(|record| {
                    serde_json::from_value::<crate::domain::client_request::RefreshTokenData>(
                        record.data.clone(),
                    )
                    .map(|data| data.token == token)
                    .unwrap_or(false)
                })
                .cloned())
        }

        async fn revoke(&self, oid: Uuid) -> Result<(), ClientRequestRepositoryError> {
            if let Some(record) = self.records.lock().unwrap().get_mut(&oid) {
                record.revoked_at = Some(chrono::Utc::now());
            }
            Ok(())
        }
    }

    #[async_trait]
    impl LoginRepository for InMemoryLoginRepository {
        async fn find_by_oid(&self, _oid: Uuid) -> Result<Option<Login>, LoginRepositoryError> {
            Ok(None)
        }

        async fn create_pending(
            &self,
            _client_oid: Uuid,
            _client_request_oid: Uuid,
            requested_acr: Option<&str>,
        ) -> Result<Login, LoginRepositoryError> {
            Ok(Login {
                oid: Uuid::new_v4(),
                client_oid: _client_oid,
                client_request_oid: _client_request_oid,
                user_oid: None,
                status: LoginStatus::CREATED.to_string(),
                failed_attempts: 0,
                created_at: chrono::Utc::now(),
                acr: None,
                requested_acr: requested_acr.map(str::to_owned),
            })
        }

        async fn bind_user(
            &self,
            login_oid: Uuid,
            user_oid: Uuid,
            status: &str,
        ) -> Result<Login, LoginRepositoryError> {
            Ok(Login {
                oid: login_oid,
                client_oid: Uuid::new_v4(),
                client_request_oid: Uuid::new_v4(),
                user_oid: Some(user_oid),
                status: status.to_string(),
                failed_attempts: 0,
                created_at: chrono::Utc::now(),
                acr: None,
                requested_acr: None,
            })
        }

        async fn update_status(
            &self,
            _login_oid: Uuid,
            _status: &str,
            _session_oid: Option<Uuid>,
            _acr: Option<&str>,
        ) -> Result<(), LoginRepositoryError> {
            Ok(())
        }

        async fn increment_failed_attempts(
            &self,
            _login_oid: Uuid,
            _failure_reason: Option<&str>,
        ) -> Result<(), LoginRepositoryError> {
            Ok(())
        }
    }

    #[async_trait]
    impl OpenIdConnectCredentialRepository for InMemoryCredentialRepository {
        async fn find_by_oid(
            &self,
            oid: Uuid,
        ) -> Result<Option<OpenIdConnectCredential>, OpenIdConnectCredentialRepositoryError>
        {
            Ok(self
                .credentials
                .lock()
                .unwrap()
                .iter()
                .find(|item| item.oid == oid)
                .cloned())
        }

        async fn find_by_client_oid_and_type(
            &self,
            client_oid: Uuid,
            type_: OpenIdConnectCredentialType,
        ) -> Result<Vec<OpenIdConnectCredential>, OpenIdConnectCredentialRepositoryError> {
            Ok(self
                .credentials
                .lock()
                .unwrap()
                .iter()
                .filter(|item| item.client_oid == client_oid && item.r#type == type_)
                .cloned()
                .collect())
        }
    }

    #[async_trait]
    impl OpenIdConnectClientRepository for MissingClientRepository {
        async fn find_by_oid(
            &self,
            _oid: Uuid,
        ) -> Result<Option<OpenIdConnectClient>, OpenIdConnectClientRepositoryError> {
            Ok(None)
        }
    }

    struct FoundClientRepository;

    struct RequestUriClientRepository {
        request_uris: Vec<Url>,
    }

    const TEST_CLIENT_ID: Uuid = Uuid::nil();

    #[async_trait]
    impl OpenIdConnectClientRepository for FoundClientRepository {
        async fn find_by_oid(
            &self,
            oid: Uuid,
        ) -> Result<Option<OpenIdConnectClient>, OpenIdConnectClientRepositoryError> {
            Ok(Some(
                OpenIdConnectClient::new(
                    Client {
                        oid,
                        protocol: ClientProtocol::OpenIdConnect,
                        name: "Example RP".to_string(),
                        names: vec![],
                        description: None,
                        created_at: Utc::now(),
                        updated_at: None,
                    },
                    OpenIdConnectClientMetadata {
                        redirect_uris: Some(vec![
                            url::Url::parse("https://client.example.com/callback").unwrap(),
                        ]),
                        post_logout_redirect_uris: None,
                        response_types: None,
                        grant_types: None,
                        application_type: None,
                        contacts: None,
                        logo_uri: None,
                        client_uri: None,
                        policy_uri: None,
                        tos_uri: None,
                        sector_identifier_uri: None,
                        subject_type: None,
                        id_token_signed_response_alg: None,
                        id_token_encrypted_response_alg: None,
                        id_token_encrypted_response_enc: None,
                        userinfo_signed_response_alg: None,
                        userinfo_encrypted_response_alg: None,
                        userinfo_encrypted_response_enc: None,
                        request_object_signing_alg: None,
                        request_object_encryption_alg: None,
                        request_object_encryption_enc: None,
                        token_endpoint_auth_method: None,
                        token_endpoint_auth_signing_alg: None,
                        default_max_age: None,
                        require_auth_time: None,
                        default_acr_values: None,
                        initiate_login_uri: None,
                        request_uris: None,
                        skip_consent: Some(true),
                        internal_client: Some(false),
                    },
                )
                .unwrap(),
            ))
        }
    }

    #[async_trait]
    impl OpenIdConnectClientRepository for RequestUriClientRepository {
        async fn find_by_oid(
            &self,
            oid: Uuid,
        ) -> Result<Option<OpenIdConnectClient>, OpenIdConnectClientRepositoryError> {
            Ok(Some(
                OpenIdConnectClient::new(
                    Client {
                        oid,
                        protocol: ClientProtocol::OpenIdConnect,
                        name: "Example RP".to_string(),
                        names: vec![],
                        description: None,
                        created_at: Utc::now(),
                        updated_at: None,
                    },
                    OpenIdConnectClientMetadata {
                        redirect_uris: Some(vec![
                            url::Url::parse("https://client.example.com/callback").unwrap(),
                        ]),
                        post_logout_redirect_uris: None,
                        response_types: None,
                        grant_types: None,
                        application_type: None,
                        contacts: None,
                        logo_uri: None,
                        client_uri: None,
                        policy_uri: None,
                        tos_uri: None,
                        sector_identifier_uri: None,
                        subject_type: None,
                        id_token_signed_response_alg: None,
                        id_token_encrypted_response_alg: None,
                        id_token_encrypted_response_enc: None,
                        userinfo_signed_response_alg: None,
                        userinfo_encrypted_response_alg: None,
                        userinfo_encrypted_response_enc: None,
                        request_object_signing_alg: None,
                        request_object_encryption_alg: None,
                        request_object_encryption_enc: None,
                        token_endpoint_auth_method: None,
                        token_endpoint_auth_signing_alg: None,
                        default_max_age: None,
                        require_auth_time: None,
                        default_acr_values: None,
                        initiate_login_uri: None,
                        request_uris: Some(self.request_uris.clone()),
                        skip_consent: Some(true),
                        internal_client: Some(false),
                    },
                )
                .unwrap(),
            ))
        }
    }

    struct MockKeyRepository;

    #[async_trait]
    impl KeyRepository for MockKeyRepository {
        async fn find_by_oid(&self, _oid: KeyOid) -> Result<Option<Key>, KeyRepositoryError> {
            Ok(None)
        }

        async fn list_available_asymmetric(&self) -> Result<Vec<Key>, KeyRepositoryError> {
            Ok(vec![])
        }

        async fn list_available_symmetric(&self) -> Result<Vec<Key>, KeyRepositoryError> {
            let raw_key = base64::engine::general_purpose::STANDARD.encode([0x42u8; 32]);
            Ok(vec![Key {
                oid: KeyOid::from(Uuid::new_v4()),
                r#type: KeyType::Symmetric,
                data: KeyData::Symmetric(SymmetricKeyData {
                    key: raw_key,
                    algorithm: SymmetricKeyAlgorithm::XChaCha20Poly1305,
                }),
                expires_at: Some(Utc::now() + chrono::Duration::hours(1)),
                revoked_at: None,
                created_at: Utc::now(),
                updated_at: None,
            }])
        }

        async fn create(
            &self,
            _key_type: KeyType,
            _data: &KeyData,
            _expires_at: Option<chrono::DateTime<Utc>>,
        ) -> Result<Key, KeyRepositoryError> {
            unimplemented!()
        }

        async fn update_certificate_by_oid(
            &self,
            _oid: KeyOid,
            _certificate_pem: &str,
        ) -> Result<Option<Key>, KeyRepositoryError> {
            unimplemented!()
        }

        async fn revoke_by_oid(
            &self,
            _oid: KeyOid,
            _revoked_at: chrono::DateTime<Utc>,
        ) -> Result<Option<Key>, KeyRepositoryError> {
            unimplemented!()
        }
    }

    fn test_data_protector() -> Arc<dyn DataProtector> {
        Arc::new(DataProtectorImpl::new(Arc::new(MockKeyRepository)))
    }

    fn params(scope: &str) -> AuthorizationRequestParams {
        AuthorizationRequestParams {
            response_type: "code".to_string(),
            client_id: TEST_CLIENT_ID.to_string(),
            redirect_uri: "https://client.example.com/callback".to_string(),
            scope: scope.to_string(),
            state: "state123".to_string(),
            nonce: None,
            display: None,
            prompt: None,
            max_age: None,
            ui_locales: None,
            claims_locales: None,
            id_token_hint: None,
            login_hint: None,
            acr_values: None,
            claims: None,
            request: None,
            request_uri: None,
            code_challenge: None,
            code_challenge_method: None,
        }
    }

    fn empty_optional_params() -> AuthorizationRequestParams {
        AuthorizationRequestParams {
            state: "state123".to_string(),
            ..params("openid profile")
        }
    }

    fn signing_keypair() -> (Vec<u8>, Vec<u8>) {
        let rsa = Rsa::generate(2048).unwrap();
        (
            rsa.private_key_to_pem().unwrap(),
            rsa.public_key_to_pem().unwrap(),
        )
    }

    fn authorize_service_with_public_key(public_key: Vec<u8>) -> AuthorizeService {
        let credential_repo = InMemoryCredentialRepository {
            credentials: Mutex::new(vec![OpenIdConnectCredential {
                oid: Uuid::new_v4(),
                client_oid: TEST_CLIENT_ID,
                r#type: OpenIdConnectCredentialType::ClientPublicKey,
                hint: "request_object".to_string(),
                data: OpenIdConnectCredentialData::ClientPublicKey {
                    public_key: String::from_utf8(public_key).unwrap(),
                },
                expires_at: chrono::Utc::now(),
                revoked_at: None,
                created_at: chrono::Utc::now(),
                updated_at: None,
            }]),
        };

        AuthorizeService::new(
            Arc::new(FoundClientRepository),
            Arc::new(credential_repo),
            Arc::new(InMemoryClientRequestRepository::default()),
            Arc::new(InMemoryLoginRepository),
            provider_service(),
            test_data_protector(),
        )
    }

    fn authorize_service_with_request_uri(request_uri: &str) -> AuthorizeService {
        AuthorizeService::new(
            Arc::new(RequestUriClientRepository {
                request_uris: vec![Url::parse(request_uri).unwrap()],
            }),
            Arc::new(InMemoryCredentialRepository::default()),
            Arc::new(InMemoryClientRequestRepository::default()),
            Arc::new(InMemoryLoginRepository),
            provider_service(),
            test_data_protector(),
        )
    }

    async fn spawn_chunked_response_server(chunks: Vec<Vec<u8>>, keep_open_for: Duration) -> Url {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();

        tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            stream
                .write_all(
                    b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nContent-Type: text/plain\r\n\r\n",
                )
                .await
                .unwrap();

            for chunk in chunks {
                stream
                    .write_all(format!("{:X}\r\n", chunk.len()).as_bytes())
                    .await
                    .unwrap();
                stream.write_all(&chunk).await.unwrap();
                stream.write_all(b"\r\n").await.unwrap();
            }

            tokio::time::sleep(keep_open_for).await;
        });

        Url::parse(&format!("http://{address}/request.jwt")).unwrap()
    }

    async fn spawn_redirect_response_server(location: &str) -> Url {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let location = location.to_string();

        let app = Router::new().route(
            "/request.jwt",
            get(move || {
                let location = location.clone();
                async move { Redirect::temporary(&location) }
            }),
        );

        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });

        Url::parse(&format!("http://{address}/request.jwt")).unwrap()
    }

    fn signed_request_object(
        private_key: &[u8],
        fields: impl IntoIterator<Item = (&'static str, serde_json::Value)>,
    ) -> String {
        let mut header = JwsHeader::new();
        header.set_token_type("JWT");

        let mut payload = JwtPayload::new();
        for (name, value) in fields {
            payload.set_claim(name, Some(value)).unwrap();
        }

        let signer = RS256.signer_from_pem(private_key).unwrap();
        jwt::encode_with_signer(&payload, &header, &signer).unwrap()
    }

    #[tokio::test]
    async fn validate_request_rejects_missing_openid_scope() {
        let service = AuthorizeService::new(
            Arc::new(MissingClientRepository),
            Arc::new(InMemoryCredentialRepository::default()),
            Arc::new(InMemoryClientRequestRepository::default()),
            Arc::new(InMemoryLoginRepository),
            provider_service(),
            test_data_protector(),
        );

        let result = service.validate_request(params("profile email")).await;

        assert!(result.is_err());
    }

    #[tokio::test]
    async fn validate_request_rejects_unknown_scope() {
        let service = AuthorizeService::new(
            Arc::new(MissingClientRepository),
            Arc::new(InMemoryCredentialRepository::default()),
            Arc::new(InMemoryClientRequestRepository::default()),
            Arc::new(InMemoryLoginRepository),
            provider_service(),
            test_data_protector(),
        );

        let result = service
            .validate_request(params("openid custom_scope"))
            .await;

        assert!(result.is_err());
    }

    #[tokio::test]
    async fn validate_request_reports_missing_required_fields() {
        let service = AuthorizeService::new(
            Arc::new(MissingClientRepository),
            Arc::new(InMemoryCredentialRepository::default()),
            Arc::new(InMemoryClientRequestRepository::default()),
            Arc::new(InMemoryLoginRepository),
            provider_service(),
            test_data_protector(),
        );

        let params = AuthorizationRequestParams {
            response_type: String::new(),
            client_id: String::new(),
            redirect_uri: String::new(),
            scope: String::new(),
            state: String::new(),
            nonce: None,
            display: None,
            prompt: None,
            max_age: None,
            ui_locales: None,
            claims_locales: None,
            id_token_hint: None,
            login_hint: None,
            acr_values: None,
            claims: None,
            request: None,
            request_uri: None,
            code_challenge: None,
            code_challenge_method: None,
        };

        let error = service.validate_request(params).await.unwrap_err();
        let debug = format!("{error:?}");

        assert!(debug.contains("response_type"));
        assert!(debug.contains("client_id"));
        assert!(debug.contains("redirect_uri"));
        assert!(debug.contains("scope"));
    }

    #[tokio::test]
    async fn validate_request_rejects_request_and_request_uri_together() {
        let service = AuthorizeService::new(
            Arc::new(FoundClientRepository),
            Arc::new(InMemoryCredentialRepository::default()),
            Arc::new(InMemoryClientRequestRepository::default()),
            Arc::new(InMemoryLoginRepository),
            provider_service(),
            test_data_protector(),
        );
        let params = AuthorizationRequestParams {
            request: Some("header.payload.signature".to_string()),
            request_uri: Some("https://client.example.com/request.jwt".to_string()),
            ..params("openid profile")
        };

        let error = service.validate_request(params).await.unwrap_err();

        assert_eq!(error.code(), 6012); // RequestAndUriConflict
    }

    #[tokio::test]
    async fn validate_request_supports_request_parameter() {
        let (private_key, public_key) = signing_keypair();
        let service = authorize_service_with_public_key(public_key);

        let request = signed_request_object(
            &private_key,
            [
                ("response_type", json!("code")),
                ("client_id", json!(TEST_CLIENT_ID)),
                ("redirect_uri", json!("https://client.example.com/callback")),
                ("scope", json!("openid profile")),
                ("state", json!("state-123")),
                ("login_hint", json!("alice@example.com")),
            ],
        );

        let params = AuthorizationRequestParams {
            client_id: TEST_CLIENT_ID.to_string(),
            response_type: String::new(),
            redirect_uri: String::new(),
            scope: String::new(),
            state: String::new(),
            request: Some(request),
            request_uri: None,
            ..empty_optional_params()
        };

        let (request, _) = service.validate_request(params).await.unwrap();
        assert_eq!(request.response_type.to_string(), "code");
        assert_eq!(
            request.redirect_uri.as_str(),
            "https://client.example.com/callback"
        );
        assert_eq!(request.scope.to_scope_string(), "openid profile");
        assert_eq!(request.state, "state-123");
        assert_eq!(request.login_hint.as_deref(), Some("alice@example.com"));
    }

    #[tokio::test]
    async fn validate_request_supports_request_parameter_without_outer_client_id() {
        let (private_key, public_key) = signing_keypair();
        let service = authorize_service_with_public_key(public_key);

        let request = signed_request_object(
            &private_key,
            [
                ("response_type", json!("code")),
                ("client_id", json!(TEST_CLIENT_ID)),
                ("redirect_uri", json!("https://client.example.com/callback")),
                ("scope", json!("openid profile")),
                ("state", json!("state-456")),
            ],
        );

        let params = AuthorizationRequestParams {
            client_id: String::new(),
            response_type: String::new(),
            redirect_uri: String::new(),
            scope: String::new(),
            state: String::new(),
            request: Some(request),
            request_uri: None,
            ..empty_optional_params()
        };

        let (request, _) = service.validate_request(params).await.unwrap();
        assert_eq!(request.client_id, TEST_CLIENT_ID);
        assert_eq!(request.state, "state-456");
    }

    #[tokio::test]
    async fn validate_request_rejects_mismatched_request_object_field() {
        let (private_key, public_key) = signing_keypair();
        let service = authorize_service_with_public_key(public_key);
        let request = signed_request_object(
            &private_key,
            [
                ("response_type", json!("code")),
                ("client_id", json!(TEST_CLIENT_ID)),
                ("redirect_uri", json!("https://client.example.com/other")),
                ("scope", json!("openid profile")),
            ],
        );

        let params = AuthorizationRequestParams {
            request: Some(request),
            ..params("openid profile")
        };

        let error = service.validate_request(params).await.unwrap_err();
        assert!(format!("{error:?}").contains("redirect_uri"));
    }

    #[tokio::test]
    async fn validate_request_uri_rejects_fragment() {
        let service =
            authorize_service_with_request_uri("https://client.example.com/request.jwt#fragment");
        let params = AuthorizationRequestParams {
            request_uri: Some("https://client.example.com/request.jwt#fragment".to_string()),
            ..params("openid profile")
        };

        let error = service.validate_request(params).await.unwrap_err();
        assert_eq!(error.code(), 6016); // RequestUriHasFragment
    }

    #[tokio::test]
    async fn validate_request_uri_rejects_loopback_target() {
        let service = authorize_service_with_request_uri("https://127.0.0.1/request.jwt");
        let params = AuthorizationRequestParams {
            request_uri: Some("https://127.0.0.1/request.jwt".to_string()),
            ..params("openid profile")
        };

        let error = service.validate_request(params).await.unwrap_err();
        assert_eq!(error.code(), 6017, "loopback must be blocked"); // RequestUriUnsafeHost
    }

    #[tokio::test]
    async fn validate_request_uri_rejects_rfc1918_class_a() {
        let service = authorize_service_with_request_uri("https://10.0.0.1/request.jwt");
        let params = AuthorizationRequestParams {
            request_uri: Some("https://10.0.0.1/request.jwt".to_string()),
            ..params("openid profile")
        };
        let error = service.validate_request(params).await.unwrap_err();
        assert_eq!(error.code(), 6017, "10.x.x.x must be blocked"); // RequestUriUnsafeHost
    }

    #[tokio::test]
    async fn validate_request_uri_rejects_rfc1918_class_b() {
        let service = authorize_service_with_request_uri("https://172.16.0.1/request.jwt");
        let params = AuthorizationRequestParams {
            request_uri: Some("https://172.16.0.1/request.jwt".to_string()),
            ..params("openid profile")
        };
        let error = service.validate_request(params).await.unwrap_err();
        assert_eq!(error.code(), 6017, "172.16.x must be blocked"); // RequestUriUnsafeHost
    }

    #[tokio::test]
    async fn validate_request_uri_rejects_rfc1918_class_b_upper_bound() {
        let service = authorize_service_with_request_uri("https://172.31.255.255/request.jwt");
        let params = AuthorizationRequestParams {
            request_uri: Some("https://172.31.255.255/request.jwt".to_string()),
            ..params("openid profile")
        };
        let error = service.validate_request(params).await.unwrap_err();
        assert_eq!(error.code(), 6017, "172.31.x must be blocked"); // RequestUriUnsafeHost
    }

    #[tokio::test]
    async fn validate_request_uri_rejects_rfc1918_class_c() {
        let service = authorize_service_with_request_uri("https://192.168.1.100/request.jwt");
        let params = AuthorizationRequestParams {
            request_uri: Some("https://192.168.1.100/request.jwt".to_string()),
            ..params("openid profile")
        };
        let error = service.validate_request(params).await.unwrap_err();
        assert_eq!(error.code(), 6017, "192.168.x must be blocked"); // RequestUriUnsafeHost
    }

    #[tokio::test]
    async fn validate_request_uri_rejects_link_local_ipv4() {
        let service = authorize_service_with_request_uri("https://169.254.1.1/request.jwt");
        let params = AuthorizationRequestParams {
            request_uri: Some("https://169.254.1.1/request.jwt".to_string()),
            ..params("openid profile")
        };
        let error = service.validate_request(params).await.unwrap_err();
        assert_eq!(error.code(), 6017, "169.254.x link-local must be blocked"); // RequestUriUnsafeHost
    }

    #[tokio::test]
    async fn validate_request_uri_rejects_ipv6_loopback() {
        let service = authorize_service_with_request_uri("https://[::1]/request.jwt");
        let params = AuthorizationRequestParams {
            request_uri: Some("https://[::1]/request.jwt".to_string()),
            ..params("openid profile")
        };
        let error = service.validate_request(params).await.unwrap_err();
        assert_eq!(error.code(), 6017, "::1 loopback must be blocked"); // RequestUriUnsafeHost
    }

    #[tokio::test]
    async fn validate_request_uri_rejects_ipv6_ula() {
        let service = authorize_service_with_request_uri("https://[fc00::1]/request.jwt");
        let params = AuthorizationRequestParams {
            request_uri: Some("https://[fc00::1]/request.jwt".to_string()),
            ..params("openid profile")
        };
        let error = service.validate_request(params).await.unwrap_err();
        assert_eq!(error.code(), 6017, "fc00::/7 ULA must be blocked"); // RequestUriUnsafeHost
    }

    #[tokio::test]
    async fn validate_request_uri_rejects_ipv6_link_local() {
        let service = authorize_service_with_request_uri("https://[fe80::1]/request.jwt");
        let params = AuthorizationRequestParams {
            request_uri: Some("https://[fe80::1]/request.jwt".to_string()),
            ..params("openid profile")
        };
        let error = service.validate_request(params).await.unwrap_err();
        assert_eq!(error.code(), 6017, "fe80::/10 link-local must be blocked"); // RequestUriUnsafeHost
    }

    #[tokio::test]
    async fn fetch_request_object_rejects_oversized_chunked_response_before_completion() {
        let service = authorize_service_with_request_uri("https://client.example.com/request.jwt");
        let request_uri = spawn_chunked_response_server(
            vec![vec![b'a'; 1024 * 1024], vec![b'b'; 1]],
            Duration::from_secs(6),
        )
        .await;

        let result = timeout(
            Duration::from_secs(2),
            service.fetch_request_object(&request_uri),
        )
        .await;

        let error = result
            .expect("oversized response should be rejected before server finishes")
            .unwrap_err();
        assert_eq!(error.code(), 6021); // RequestUriTooLarge
    }

    #[tokio::test]
    async fn fetch_request_object_rejects_redirect_response() {
        let service = authorize_service_with_request_uri("https://client.example.com/request.jwt");
        let request_uri = spawn_redirect_response_server("http://127.0.0.1/final.jwt").await;

        let error = service
            .fetch_request_object(&request_uri)
            .await
            .unwrap_err();

        assert_eq!(error.code(), 6020); // RequestUriNot200
    }

    #[tokio::test]
    async fn parse_request_object_payload_preserves_registered_claims() {
        let (private_key, public_key) = signing_keypair();
        let service = authorize_service_with_public_key(public_key);
        let client = FoundClientRepository
            .find_by_oid(TEST_CLIENT_ID)
            .await
            .unwrap()
            .unwrap();
        let now = chrono::Utc::now().timestamp();
        let jwt = signed_request_object(
            &private_key,
            [
                ("response_type", json!("code")),
                ("client_id", json!(TEST_CLIENT_ID)),
                ("redirect_uri", json!("https://client.example.com/callback")),
                ("scope", json!("openid profile")),
                ("iss", json!(TEST_CLIENT_ID)),
                ("aud", json!("https://identity.example.com/")),
                ("exp", json!(now + 300)),
                ("nbf", json!(now - 10)),
            ],
        );

        let parsed = service
            .parse_request_object_payload(&client, &jwt)
            .await
            .unwrap();

        assert_eq!(parsed["iss"], json!(TEST_CLIENT_ID));
        assert_eq!(parsed["aud"], json!("https://identity.example.com/"));
        assert_eq!(parsed["exp"], json!(now + 300));
        assert_eq!(parsed["nbf"], json!(now - 10));
    }

    #[test]
    fn validate_request_object_claims_rejects_future_issued_at() {
        let mut params = params("openid profile");
        params.state = "state-123".to_string();
        let payload = serde_json::json!({
            "response_type": "code",
            "client_id": TEST_CLIENT_ID.to_string(),
            "redirect_uri": "https://client.example.com/callback",
            "scope": "openid profile",
            "state": "state-123",
            "iat": chrono::Utc::now().timestamp() + 60,
        });

        let result = AuthorizeService::validate_request_object_claims(
            &params,
            &payload,
            &Url::parse("https://identity.example.com/").unwrap(),
        );

        assert!(result.is_err());
        assert_eq!(result.unwrap_err().code(), 6033); // RequestObjectIatFuture
    }

    #[tokio::test]
    async fn validate_request_accepts_registered_redirect_uri() {
        let service = AuthorizeService::new(
            Arc::new(FoundClientRepository),
            Arc::new(InMemoryCredentialRepository::default()),
            Arc::new(InMemoryClientRequestRepository::default()),
            Arc::new(InMemoryLoginRepository),
            provider_service(),
            test_data_protector(),
        );

        let result = service.validate_request(params("openid profile")).await;

        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn create_authorization_request_returns_oid() {
        let request_repo = Arc::new(InMemoryClientRequestRepository::default());
        let service = AuthorizeService::new(
            Arc::new(FoundClientRepository),
            Arc::new(InMemoryCredentialRepository::default()),
            request_repo,
            Arc::new(InMemoryLoginRepository),
            provider_service(),
            test_data_protector(),
        );

        let (request, _) = service
            .validate_request(params("openid profile"))
            .await
            .unwrap();
        let oid = service
            .create_authorization_request(&request)
            .await
            .unwrap();

        assert_ne!(oid, Uuid::nil());
    }

    #[tokio::test]
    async fn create_login_flow_returns_protected_id() {
        let request_repo = Arc::new(InMemoryClientRequestRepository::default());
        let service = AuthorizeService::new(
            Arc::new(FoundClientRepository),
            Arc::new(InMemoryCredentialRepository::default()),
            request_repo.clone(),
            Arc::new(InMemoryLoginRepository),
            provider_service(),
            test_data_protector(),
        );

        let (request, _) = service
            .validate_request(params("openid profile"))
            .await
            .unwrap();
        let authorization_request_id = service
            .create_authorization_request(&request)
            .await
            .unwrap();
        let login_id = service
            .create_login_flow(request.client_id, authorization_request_id, None)
            .await
            .unwrap();

        assert!(!login_id.is_empty());
    }

    #[tokio::test]
    async fn load_authorization_request_returns_stored_data() {
        let request_repo = Arc::new(InMemoryClientRequestRepository::default());
        let service = AuthorizeService::new(
            Arc::new(FoundClientRepository),
            Arc::new(InMemoryCredentialRepository::default()),
            request_repo.clone(),
            Arc::new(InMemoryLoginRepository),
            provider_service(),
            test_data_protector(),
        );

        let (request, _) = service
            .validate_request(params("openid profile"))
            .await
            .unwrap();
        let oid = service
            .create_authorization_request(&request)
            .await
            .unwrap();
        let loaded = service.load_authorization_request(oid).await.unwrap();

        assert_eq!(loaded.state, "state123");
        assert_eq!(loaded.scope, "openid profile");
    }

    #[tokio::test]
    async fn approve_authorization_request_returns_redirect_with_code_and_state() {
        let request_repo = Arc::new(InMemoryClientRequestRepository::default());
        let service = AuthorizeService::new(
            Arc::new(FoundClientRepository),
            Arc::new(InMemoryCredentialRepository::default()),
            request_repo.clone(),
            Arc::new(InMemoryLoginRepository),
            provider_service(),
            test_data_protector(),
        );

        let (request, _) = service
            .validate_request(params("openid profile"))
            .await
            .unwrap();
        let oid = service
            .create_authorization_request(&request)
            .await
            .unwrap();
        let redirect = service
            .approve_authorization_request(oid, Uuid::new_v4(), Uuid::new_v4(), None)
            .await
            .unwrap();

        let query = redirect.query().unwrap();
        assert!(query.contains("code="));
        assert!(query.contains("state=state123"));
    }

    #[tokio::test]
    async fn create_authorization_request_persists_login_hint() {
        let request_repo = Arc::new(InMemoryClientRequestRepository::default());
        let service = AuthorizeService::new(
            Arc::new(FoundClientRepository),
            Arc::new(InMemoryCredentialRepository::default()),
            request_repo.clone(),
            Arc::new(InMemoryLoginRepository),
            provider_service(),
            test_data_protector(),
        );

        let mut request_params = params("openid profile");
        request_params.login_hint = Some("alice@example.com".to_string());

        let (request, _) = service.validate_request(request_params).await.unwrap();
        let oid = service
            .create_authorization_request(&request)
            .await
            .unwrap();
        let loaded = service.load_authorization_request(oid).await.unwrap();

        assert_eq!(loaded.login_hint.as_deref(), Some("alice@example.com"));
    }

    #[tokio::test]
    async fn deny_authorization_request_returns_access_denied_redirect() {
        let request_repo = Arc::new(InMemoryClientRequestRepository::default());
        let service = AuthorizeService::new(
            Arc::new(FoundClientRepository),
            Arc::new(InMemoryCredentialRepository::default()),
            request_repo.clone(),
            Arc::new(InMemoryLoginRepository),
            provider_service(),
            test_data_protector(),
        );

        let (request, _) = service
            .validate_request(params("openid profile"))
            .await
            .unwrap();
        let oid = service
            .create_authorization_request(&request)
            .await
            .unwrap();
        let redirect = service.deny_authorization_request(oid).await.unwrap();

        let query = redirect.query().unwrap();
        assert!(query.contains("error=access_denied"));
        assert!(query.contains("state=state123"));
    }

    #[test]
    fn merge_request_object_overrides_scope_and_login_hint() {
        let payload = serde_json::json!({
            "scope": "openid email",
            "state": "override-state",
            "login_hint": "alice@example.com"
        });

        let params = AuthorizationRequestParams {
            response_type: "code".to_string(),
            client_id: Uuid::nil().to_string(),
            redirect_uri: "https://client.example.com/callback".to_string(),
            scope: "openid profile".to_string(),
            state: "state123".to_string(),
            nonce: None,
            display: None,
            prompt: None,
            max_age: None,
            ui_locales: None,
            claims_locales: None,
            id_token_hint: None,
            login_hint: None,
            acr_values: None,
            claims: None,
            request: None,
            request_uri: None,
            code_challenge: None,
            code_challenge_method: None,
        };

        let merged = AuthorizeService::merge_request_object_params(params, &payload).unwrap();

        assert_eq!(merged.scope, "openid email");
        assert_eq!(merged.state, "override-state");
        assert_eq!(merged.login_hint.as_deref(), Some("alice@example.com"));
    }

    #[test]
    fn validate_request_object_claims_rejects_client_id_mismatch() {
        let params = AuthorizationRequestParams {
            response_type: "code".to_string(),
            client_id: Uuid::nil().to_string(),
            redirect_uri: "https://client.example.com/callback".to_string(),
            scope: "openid profile".to_string(),
            state: "state123".to_string(),
            nonce: None,
            display: None,
            prompt: None,
            max_age: None,
            ui_locales: None,
            claims_locales: None,
            id_token_hint: None,
            login_hint: None,
            acr_values: None,
            claims: None,
            request: None,
            request_uri: None,
            code_challenge: None,
            code_challenge_method: None,
        };
        let payload = serde_json::json!({
            "client_id": Uuid::new_v4().to_string(),
            "redirect_uri": "https://client.example.com/callback"
        });

        let result = AuthorizeService::validate_request_object_claims(
            &params,
            &payload,
            &Url::parse("https://identity.example.com/").unwrap(),
        );

        assert!(result.is_err());
    }

    #[test]
    fn validate_request_object_claims_rejects_redirect_uri_mismatch() {
        let params = AuthorizationRequestParams {
            response_type: "code".to_string(),
            client_id: Uuid::nil().to_string(),
            redirect_uri: "https://client.example.com/callback".to_string(),
            scope: "openid profile".to_string(),
            state: "state123".to_string(),
            nonce: None,
            display: None,
            prompt: None,
            max_age: None,
            ui_locales: None,
            claims_locales: None,
            id_token_hint: None,
            login_hint: None,
            acr_values: None,
            claims: None,
            request: None,
            request_uri: None,
            code_challenge: None,
            code_challenge_method: None,
        };
        let payload = serde_json::json!({
            "client_id": Uuid::nil().to_string(),
            "redirect_uri": "https://other.example.com/callback"
        });

        let result = AuthorizeService::validate_request_object_claims(
            &params,
            &payload,
            &Url::parse("https://identity.example.com/").unwrap(),
        );

        assert!(result.is_err());
    }

    #[test]
    fn validate_request_object_claims_rejects_issuer_mismatch() {
        let params = AuthorizationRequestParams {
            response_type: "code".to_string(),
            client_id: Uuid::nil().to_string(),
            redirect_uri: "https://client.example.com/callback".to_string(),
            scope: "openid profile".to_string(),
            state: "state123".to_string(),
            nonce: None,
            display: None,
            prompt: None,
            max_age: None,
            ui_locales: None,
            claims_locales: None,
            id_token_hint: None,
            login_hint: None,
            acr_values: None,
            claims: None,
            request: None,
            request_uri: None,
            code_challenge: None,
            code_challenge_method: None,
        };
        let payload = serde_json::json!({
            "iss": Uuid::new_v4().to_string(),
            "aud": "https://identity.example.com/"
        });

        let result = AuthorizeService::validate_request_object_claims(
            &params,
            &payload,
            &Url::parse("https://identity.example.com/").unwrap(),
        );

        assert!(result.is_err());
    }

    #[test]
    fn validate_request_object_claims_rejects_audience_mismatch() {
        let params = AuthorizationRequestParams {
            response_type: "code".to_string(),
            client_id: Uuid::nil().to_string(),
            redirect_uri: "https://client.example.com/callback".to_string(),
            scope: "openid profile".to_string(),
            state: "state123".to_string(),
            nonce: None,
            display: None,
            prompt: None,
            max_age: None,
            ui_locales: None,
            claims_locales: None,
            id_token_hint: None,
            login_hint: None,
            acr_values: None,
            claims: None,
            request: None,
            request_uri: None,
            code_challenge: None,
            code_challenge_method: None,
        };
        let payload = serde_json::json!({
            "iss": Uuid::nil().to_string(),
            "aud": "https://other.example.com/"
        });

        let result = AuthorizeService::validate_request_object_claims(
            &params,
            &payload,
            &Url::parse("https://identity.example.com/").unwrap(),
        );

        assert!(result.is_err());
    }

    #[test]
    fn validate_request_object_claims_rejects_expired_request_object() {
        let params = AuthorizationRequestParams {
            response_type: "code".to_string(),
            client_id: Uuid::nil().to_string(),
            redirect_uri: "https://client.example.com/callback".to_string(),
            scope: "openid profile".to_string(),
            state: "state123".to_string(),
            nonce: None,
            display: None,
            prompt: None,
            max_age: None,
            ui_locales: None,
            claims_locales: None,
            id_token_hint: None,
            login_hint: None,
            acr_values: None,
            claims: None,
            request: None,
            request_uri: None,
            code_challenge: None,
            code_challenge_method: None,
        };
        let payload = serde_json::json!({
            "exp": chrono::Utc::now().timestamp() - 60
        });

        let result = AuthorizeService::validate_request_object_claims(
            &params,
            &payload,
            &Url::parse("https://identity.example.com/").unwrap(),
        );

        assert!(result.is_err());
    }

    #[test]
    fn validate_request_object_claims_rejects_future_not_before() {
        let params = AuthorizationRequestParams {
            response_type: "code".to_string(),
            client_id: Uuid::nil().to_string(),
            redirect_uri: "https://client.example.com/callback".to_string(),
            scope: "openid profile".to_string(),
            state: "state123".to_string(),
            nonce: None,
            display: None,
            prompt: None,
            max_age: None,
            ui_locales: None,
            claims_locales: None,
            id_token_hint: None,
            login_hint: None,
            acr_values: None,
            claims: None,
            request: None,
            request_uri: None,
            code_challenge: None,
            code_challenge_method: None,
        };
        let payload = serde_json::json!({
            "nbf": chrono::Utc::now().timestamp() + 60
        });

        let result = AuthorizeService::validate_request_object_claims(
            &params,
            &payload,
            &Url::parse("https://identity.example.com/").unwrap(),
        );

        assert!(result.is_err());
    }

    #[tokio::test]
    async fn parse_unsecured_request_object_is_rejected() {
        let service = AuthorizeService::new(
            Arc::new(FoundClientRepository),
            Arc::new(InMemoryCredentialRepository::default()),
            Arc::new(InMemoryClientRequestRepository::default()),
            Arc::new(InMemoryLoginRepository),
            provider_service(),
            test_data_protector(),
        );
        let client = FoundClientRepository
            .find_by_oid(Uuid::nil())
            .await
            .unwrap()
            .unwrap();
        let mut header = JwsHeader::new();
        header.set_token_type("JWT");

        let mut payload = JwtPayload::new();
        payload
            .set_claim("scope", Some(serde_json::json!("openid email")))
            .unwrap();
        payload
            .set_claim("state", Some(serde_json::json!("request-state")))
            .unwrap();

        let jwt = jwt::encode_unsecured(&payload, &header).unwrap();
        let result = service.parse_request_object_payload(&client, &jwt).await;

        assert!(result.is_err());
    }

    #[tokio::test]
    async fn parse_rs256_request_object_extracts_payload() {
        let rsa = Rsa::generate(2048).unwrap();
        let private_key = rsa.private_key_to_pem().unwrap();
        let public_key = rsa.public_key_to_pem().unwrap();

        let credential_repo = InMemoryCredentialRepository {
            credentials: Mutex::new(vec![OpenIdConnectCredential {
                oid: Uuid::new_v4(),
                client_oid: Uuid::nil(),
                r#type: OpenIdConnectCredentialType::ClientPublicKey,
                hint: "request_object".to_string(),
                data: OpenIdConnectCredentialData::ClientPublicKey {
                    public_key: String::from_utf8(public_key).unwrap(),
                },
                expires_at: chrono::Utc::now(),
                revoked_at: None,
                created_at: chrono::Utc::now(),
                updated_at: None,
            }]),
        };

        let service = AuthorizeService::new(
            Arc::new(FoundClientRepository),
            Arc::new(credential_repo),
            Arc::new(InMemoryClientRequestRepository::default()),
            Arc::new(InMemoryLoginRepository),
            provider_service(),
            test_data_protector(),
        );

        let client = FoundClientRepository
            .find_by_oid(Uuid::nil())
            .await
            .unwrap()
            .unwrap();
        let mut header = JwsHeader::new();
        header.set_token_type("JWT");
        let mut payload = JwtPayload::new();
        payload
            .set_claim("scope", Some(serde_json::json!("openid email")))
            .unwrap();
        let signer = RS256.signer_from_pem(&private_key).unwrap();
        let jwt = jwt::encode_with_signer(&payload, &header, &signer).unwrap();

        let parsed = service
            .parse_request_object_payload(&client, &jwt)
            .await
            .unwrap();

        assert_eq!(parsed["scope"], "openid email");
    }
}
