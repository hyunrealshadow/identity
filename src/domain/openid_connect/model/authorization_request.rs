use std::{collections::HashSet, fmt, str::FromStr};

use serde::{Deserialize, Serialize};
use url::Url;
use uuid::Uuid;

use crate::domain::openid_connect::ScopeSet;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResponseType {
    Code,
    IdToken,
    TokenIdToken,
}

impl ResponseType {
    pub fn is_implicit(&self) -> bool {
        matches!(self, Self::IdToken | Self::TokenIdToken)
    }
}

impl fmt::Display for ResponseType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Code => "code",
            Self::IdToken => "id_token",
            Self::TokenIdToken => "id_token token",
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParseResponseTypeError;

impl fmt::Display for ParseResponseTypeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("invalid response type")
    }
}

impl std::error::Error for ParseResponseTypeError {}

impl FromStr for ResponseType {
    type Err = ParseResponseTypeError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(match s {
            "code" => Self::Code,
            "id_token" => Self::IdToken,
            "id_token token" => Self::TokenIdToken,
            "token id_token" => Self::TokenIdToken,
            _ => return Err(ParseResponseTypeError),
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResponseMode {
    Query,
    Fragment,
    FormPost,
}

impl fmt::Display for ResponseMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Query => "query",
            Self::Fragment => "fragment",
            Self::FormPost => "form_post",
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParseResponseModeError;

impl fmt::Display for ParseResponseModeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("invalid response mode")
    }
}

impl std::error::Error for ParseResponseModeError {}

impl FromStr for ResponseMode {
    type Err = ParseResponseModeError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(match s {
            "query" => Self::Query,
            "fragment" => Self::Fragment,
            "form_post" => Self::FormPost,
            _ => return Err(ParseResponseModeError),
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum PromptValue {
    None,
    Login,
    Consent,
    SelectAccount,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsePromptValueError;

impl fmt::Display for ParsePromptValueError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("invalid prompt value")
    }
}

impl std::error::Error for ParsePromptValueError {}

impl FromStr for PromptValue {
    type Err = ParsePromptValueError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(match s {
            "none" => Self::None,
            "login" => Self::Login,
            "consent" => Self::Consent,
            "select_account" => Self::SelectAccount,
            _ => return Err(ParsePromptValueError),
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Display {
    Page,
    Popup,
    Touch,
    Wap,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParseDisplayError;

impl fmt::Display for ParseDisplayError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("invalid display value")
    }
}

impl std::error::Error for ParseDisplayError {}

impl FromStr for Display {
    type Err = ParseDisplayError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(match s {
            "page" => Self::Page,
            "popup" => Self::Popup,
            "touch" => Self::Touch,
            "wap" => Self::Wap,
            _ => return Err(ParseDisplayError),
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CodeChallengeMethod {
    S256,
    Plain,
}

impl fmt::Display for CodeChallengeMethod {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::S256 => "S256",
            Self::Plain => "plain",
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParseCodeChallengeMethodError;

impl fmt::Display for ParseCodeChallengeMethodError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("invalid code challenge method")
    }
}

impl std::error::Error for ParseCodeChallengeMethodError {}

impl FromStr for CodeChallengeMethod {
    type Err = ParseCodeChallengeMethodError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(match s {
            "S256" => Self::S256,
            "plain" => Self::Plain,
            _ => return Err(ParseCodeChallengeMethodError),
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ClaimsRequest {
    pub id_token: Option<serde_json::Map<String, serde_json::Value>>,
    pub userinfo: Option<serde_json::Map<String, serde_json::Value>>,
}

#[derive(Debug, Clone)]
pub struct AuthorizationRequest {
    pub response_type: ResponseType,
    pub response_mode: Option<ResponseMode>,
    pub client_id: Uuid,
    pub redirect_uri: Url,
    pub scope: ScopeSet,
    pub state: String,
    pub nonce: Option<String>,
    pub display: Option<Display>,
    pub prompt: Option<HashSet<PromptValue>>,
    pub max_age: Option<i32>,
    pub ui_locales: Option<Vec<String>>,
    pub claims_locales: Option<Vec<String>>,
    pub id_token_hint: Option<String>,
    pub login_hint: Option<String>,
    pub acr_values: Option<Vec<String>>,
    pub claims: Option<ClaimsRequest>,
    pub request_uri: Option<Url>,
    pub code_challenge: Option<String>,
    pub code_challenge_method: Option<CodeChallengeMethod>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AuthorizationRequestData {
    pub response_type: String,
    #[serde(default)]
    pub response_mode: Option<String>,
    pub client_id: String,
    pub redirect_uri: String,
    pub scope: String,
    pub state: String,
    pub nonce: Option<String>,
    pub login_hint: Option<String>,
    pub code_challenge: Option<String>,
    pub code_challenge_method: Option<String>,
    pub acr_values: Option<Vec<String>>,
    pub claims: Option<String>,
}

impl From<&AuthorizationRequest> for AuthorizationRequestData {
    fn from(value: &AuthorizationRequest) -> Self {
        Self {
            response_type: value.response_type.to_string(),
            response_mode: value.response_mode.map(|mode| mode.to_string()),
            client_id: value.client_id.to_string(),
            redirect_uri: value.redirect_uri.to_string(),
            scope: value.scope.to_scope_string(),
            state: value.state.clone(),
            nonce: value.nonce.clone(),
            login_hint: value.login_hint.clone(),
            code_challenge: value.code_challenge.clone(),
            code_challenge_method: value.code_challenge_method.as_ref().map(|m| m.to_string()),
            acr_values: value.acr_values.clone(),
            claims: value
                .claims
                .as_ref()
                .and_then(|c| serde_json::to_string(c).ok()),
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::domain::openid_connect::ScopeSet;
    use url::Url;
    use uuid::Uuid;

    use super::{
        AuthorizationRequest, AuthorizationRequestData, CodeChallengeMethod, Display, PromptValue,
        ResponseMode, ResponseType,
    };
    use std::str::FromStr;

    #[test]
    fn parse_response_type_code() {
        let rt = ResponseType::from_str("code").unwrap();
        assert_eq!(rt, ResponseType::Code);
        assert!(!rt.is_implicit());
    }

    #[test]
    fn implicit_response_types_report_is_implicit() {
        assert!(ResponseType::IdToken.is_implicit());
        assert!(ResponseType::TokenIdToken.is_implicit());
    }

    #[test]
    fn parse_implicit_response_type_with_access_token() {
        assert_eq!(
            ResponseType::from_str("id_token token").unwrap(),
            ResponseType::TokenIdToken
        );
        assert_eq!(
            ResponseType::from_str("token id_token").unwrap(),
            ResponseType::TokenIdToken
        );
        assert_eq!(ResponseType::TokenIdToken.to_string(), "id_token token");
    }

    #[test]
    fn code_response_type_is_not_implicit() {
        assert!(!ResponseType::Code.is_implicit());
    }

    #[test]
    fn parse_prompt_values() {
        let prompt = PromptValue::from_str("none").unwrap();
        assert_eq!(prompt, PromptValue::None);
        let prompt = PromptValue::from_str("login").unwrap();
        assert_eq!(prompt, PromptValue::Login);
    }

    #[test]
    fn parse_display_values() {
        let display = Display::from_str("page").unwrap();
        assert_eq!(display, Display::Page);
    }

    #[test]
    fn parse_response_mode_values() {
        assert_eq!(
            ResponseMode::from_str("query").unwrap(),
            ResponseMode::Query
        );
        assert_eq!(
            ResponseMode::from_str("fragment").unwrap(),
            ResponseMode::Fragment
        );
        assert_eq!(
            ResponseMode::from_str("form_post").unwrap(),
            ResponseMode::FormPost
        );
        assert!("web_message".parse::<ResponseMode>().is_err());
    }

    #[test]
    fn parse_code_challenge_method() {
        let method = CodeChallengeMethod::from_str("S256").unwrap();
        assert_eq!(method, CodeChallengeMethod::S256);
    }

    #[test]
    fn authorization_request_basic() {
        let req = AuthorizationRequest {
            response_type: ResponseType::Code,
            response_mode: Some(ResponseMode::FormPost),
            client_id: Uuid::nil(),
            redirect_uri: Url::parse("https://client.example.com/callback").unwrap(),
            scope: ScopeSet::parse("openid profile").unwrap(),
            state: "abc123".to_string(),
            nonce: Some("n-0S6_WzA2Mj".to_string()),
            display: Some(Display::Page),
            prompt: None,
            max_age: None,
            ui_locales: None,
            claims_locales: None,
            id_token_hint: None,
            login_hint: None,
            acr_values: None,
            claims: None,
            request_uri: None,
            code_challenge: None,
            code_challenge_method: None,
        };

        assert_eq!(req.response_type, ResponseType::Code);
        assert_eq!(req.response_mode, Some(ResponseMode::FormPost));
        assert!(req.scope.openid);
        assert!(req.scope.profile);
    }

    #[test]
    fn authorization_request_data_round_trips() {
        let request = AuthorizationRequest {
            response_type: ResponseType::Code,
            response_mode: None,
            client_id: Uuid::nil(),
            redirect_uri: Url::parse("https://client.example.com/callback").unwrap(),
            scope: ScopeSet::parse("openid email").unwrap(),
            state: "abc123".to_string(),
            nonce: Some("nonce123".to_string()),
            display: None,
            prompt: None,
            max_age: None,
            ui_locales: None,
            claims_locales: None,
            id_token_hint: None,
            login_hint: None,
            acr_values: None,
            claims: None,
            request_uri: None,
            code_challenge: None,
            code_challenge_method: None,
        };

        let data = AuthorizationRequestData::from(&request);
        let json = serde_json::to_string(&data).unwrap();
        let parsed: AuthorizationRequestData = serde_json::from_str(&json).unwrap();

        assert_eq!(parsed.response_type, "code");
        assert_eq!(parsed.scope, "openid email");
        assert_eq!(parsed.nonce.as_deref(), Some("nonce123"));
        assert_eq!(parsed.login_hint, None);
    }
}
