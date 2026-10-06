use http::{Method, header};
use identity_application::{
    error::{
        AppError,
        codes::{authorize_http::AuthorizeHttpErrorCode, common::CommonErrorCode},
    },
    openid_connect::authorize::AuthorizationRequestParams,
};
use salvo::Request;
use serde::Deserialize;
use url::form_urlencoded::parse;

#[derive(Debug, Clone, Default, Deserialize)]
pub struct RawAuthorizeRequest {
    pub response_type: Option<String>,
    pub response_mode: Option<String>,
    pub client_id: Option<String>,
    pub redirect_uri: Option<String>,
    pub scope: Option<String>,
    pub resources: Vec<String>,
    pub state: Option<String>,
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

impl RawAuthorizeRequest {
    fn insert(&mut self, key: &str, value: String) {
        match key {
            "response_type" => self.response_type = Some(value),
            "response_mode" => self.response_mode = Some(value),
            "client_id" => self.client_id = Some(value),
            "redirect_uri" => self.redirect_uri = Some(value),
            "scope" => self.scope = Some(value),
            "resource" => self.resources.push(value),
            "state" => self.state = Some(value),
            "nonce" => self.nonce = Some(value),
            "display" => self.display = Some(value),
            "prompt" => self.prompt = Some(value),
            "max_age" => self.max_age = Some(value),
            "ui_locales" => self.ui_locales = Some(value),
            "claims_locales" => self.claims_locales = Some(value),
            "id_token_hint" => self.id_token_hint = Some(value),
            "login_hint" => self.login_hint = Some(value),
            "acr_values" => self.acr_values = Some(value),
            "claims" => self.claims = Some(value),
            "request" => self.request = Some(value),
            "request_uri" => self.request_uri = Some(value),
            "code_challenge" => self.code_challenge = Some(value),
            "code_challenge_method" => self.code_challenge_method = Some(value),
            _ => {}
        }
    }
}

impl From<RawAuthorizeRequest> for AuthorizationRequestParams {
    fn from(value: RawAuthorizeRequest) -> Self {
        Self {
            response_type: value.response_type.unwrap_or_default(),
            response_mode: value.response_mode,
            client_id: value.client_id.unwrap_or_default(),
            redirect_uri: value.redirect_uri.unwrap_or_default(),
            scope: value.scope.unwrap_or_default(),
            resources: value.resources.clone(),
            state: value.state.unwrap_or_default(),
            nonce: value.nonce,
            display: value.display,
            prompt: value.prompt,
            max_age: value.max_age,
            ui_locales: value.ui_locales,
            claims_locales: value.claims_locales,
            id_token_hint: value.id_token_hint,
            login_hint: value.login_hint,
            acr_values: value.acr_values,
            claims: value.claims,
            request: value.request,
            request_uri: value.request_uri,
            code_challenge: value.code_challenge,
            code_challenge_method: value.code_challenge_method,
        }
    }
}

pub fn parse_authorize_pairs(input: &[u8]) -> RawAuthorizeRequest {
    let mut raw = RawAuthorizeRequest::default();

    for (key, value) in parse(input) {
        raw.insert(key.as_ref(), value.into_owned());
    }

    raw
}

pub async fn extract_authorize_request(
    request: &mut Request,
) -> Result<RawAuthorizeRequest, AppError> {
    let raw = match *request.method() {
        Method::GET => parse_authorize_pairs(request.uri().query().unwrap_or_default().as_bytes()),
        Method::POST => {
            let is_form = request
                .headers()
                .get(header::CONTENT_TYPE)
                .and_then(|value| value.to_str().ok())
                .map(|value| value.starts_with("application/x-www-form-urlencoded"))
                .unwrap_or(false);

            if !is_form {
                return Err(AppError::from_code(
                    AuthorizeHttpErrorCode::PostContentTypeInvalid,
                ));
            }

            let body = request
                .payload_with_max_size(64 * 1024)
                .await
                .map_err(AppError::map_source(CommonErrorCode::InvalidRequest))?;

            parse_authorize_pairs(body)
        }
        _ => {
            return Err(
                AppError::from_code(AuthorizeHttpErrorCode::MethodNotAllowed)
                    .with_param("method", request.method().as_str()),
            );
        }
    };

    Ok(raw)
}

pub fn has_request_object_transport(raw: &RawAuthorizeRequest) -> bool {
    raw.request
        .as_deref()
        .is_some_and(|value| !value.trim().is_empty())
        || raw
            .request_uri
            .as_deref()
            .is_some_and(|value| !value.trim().is_empty())
}

pub fn authorize_input_error(raw: &RawAuthorizeRequest) -> Option<AppError> {
    // A missing redirect_uri may be resolved from the sole registered URI for
    // an OAuth client. The service handles that check after loading the client.
    if has_request_object_transport(raw) {
        return None;
    }

    if raw
        .client_id
        .as_deref()
        .is_some_and(|id| !id.trim().is_empty())
    {
        return None;
    }
    let mut must_show_page = vec!["client_id"];
    if raw
        .redirect_uri
        .as_deref()
        .is_none_or(|uri| uri.trim().is_empty())
    {
        must_show_page.push("redirect_uri");
    }

    Some(
        AppError::from_code(AuthorizeHttpErrorCode::RequiredParamMissing)
            .with_param("fields", must_show_page.join(", ")),
    )
}

#[cfg(test)]
mod tests {
    use salvo::test::TestClient;

    use super::*;

    #[tokio::test]
    async fn authorize_extractor_reads_query_parameters() {
        let mut request = TestClient::get("http://127.0.0.1:5800/oauth2/authorize?response_type=code&client_id=client&redirect_uri=https%3A%2F%2Fclient.example.com%2Fcallback&scope=openid&state=state")
            .build();

        let extracted = extract_authorize_request(&mut request).await.unwrap();
        assert_eq!(extracted.response_type.as_deref(), Some("code"));
    }

    #[tokio::test]
    async fn authorize_extractor_reads_response_mode() {
        let mut request = TestClient::get("http://127.0.0.1:5800/oauth2/authorize?response_type=code&response_mode=form_post&client_id=client&redirect_uri=https%3A%2F%2Fclient.example.com%2Fcallback&scope=openid&state=state")
            .build();

        let extracted = extract_authorize_request(&mut request).await.unwrap();
        assert_eq!(extracted.response_mode.as_deref(), Some("form_post"));
    }

    #[tokio::test]
    async fn authorize_extractor_reads_form_parameters() {
        let mut request = TestClient::post("http://127.0.0.1:5800/oauth2/authorize")
            .add_header(header::CONTENT_TYPE, "application/x-www-form-urlencoded", true)
            .text("response_type=code&client_id=client&redirect_uri=https%3A%2F%2Fclient.example.com%2Fcallback&scope=openid&state=state")
            .build();

        let extracted = extract_authorize_request(&mut request).await.unwrap();
        assert_eq!(extracted.scope.as_deref(), Some("openid"));
    }

    #[test]
    fn missing_redirect_uri_is_resolved_after_client_lookup() {
        let raw = RawAuthorizeRequest {
            client_id: Some("client-id".to_owned()),
            ..RawAuthorizeRequest::default()
        };
        assert!(authorize_input_error(&raw).is_none());
    }

    #[tokio::test]
    async fn authorization_query_and_form_keep_all_resource_parameters() {
        let body = "resource=https%3A%2F%2Fa.example%2F&resource=urn%3Ab";
        let mut requests = [
            TestClient::get(format!("http://localhost/oauth2/authorize?{body}")).build(),
            TestClient::post("http://localhost/oauth2/authorize")
                .add_header(
                    header::CONTENT_TYPE,
                    "application/x-www-form-urlencoded",
                    true,
                )
                .text(body)
                .build(),
        ];
        for request in &mut requests {
            let extracted = extract_authorize_request(request).await.unwrap();
            assert_eq!(extracted.resources, ["https://a.example/", "urn:b"]);
            let params: AuthorizationRequestParams = extracted.into();
            assert_eq!(params.resources, ["https://a.example/", "urn:b"]);
        }
    }
}
