use std::{fmt, str::FromStr};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OAuthErrorCode {
    InvalidRequest,
    UnauthorizedClient,
    AccessDenied,
    UnsupportedResponseType,
    InvalidScope,
    ServerError,
    TemporarilyUnavailable,
    LoginRequired,
    ConsentRequired,
    InteractionRequired,
}

impl fmt::Display for OAuthErrorCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::InvalidRequest => "invalid_request",
            Self::UnauthorizedClient => "unauthorized_client",
            Self::AccessDenied => "access_denied",
            Self::UnsupportedResponseType => "unsupported_response_type",
            Self::InvalidScope => "invalid_scope",
            Self::ServerError => "server_error",
            Self::TemporarilyUnavailable => "temporarily_unavailable",
            Self::LoginRequired => "login_required",
            Self::ConsentRequired => "consent_required",
            Self::InteractionRequired => "interaction_required",
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParseOAuthErrorCodeError;

impl fmt::Display for ParseOAuthErrorCodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("invalid oauth error code")
    }
}

impl std::error::Error for ParseOAuthErrorCodeError {}

impl FromStr for OAuthErrorCode {
    type Err = ParseOAuthErrorCodeError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(match s {
            "invalid_request" => Self::InvalidRequest,
            "unauthorized_client" => Self::UnauthorizedClient,
            "access_denied" => Self::AccessDenied,
            "unsupported_response_type" => Self::UnsupportedResponseType,
            "invalid_scope" => Self::InvalidScope,
            "server_error" => Self::ServerError,
            "temporarily_unavailable" => Self::TemporarilyUnavailable,
            "login_required" => Self::LoginRequired,
            "consent_required" => Self::ConsentRequired,
            "interaction_required" => Self::InteractionRequired,
            _ => return Err(ParseOAuthErrorCodeError),
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OAuthErrorResponse {
    pub error: OAuthErrorCode,
    pub error_description: Option<String>,
    pub error_uri: Option<String>,
    pub state: Option<String>,
}

impl OAuthErrorResponse {
    pub fn new(error: OAuthErrorCode) -> Self {
        Self {
            error,
            error_description: None,
            error_uri: None,
            state: None,
        }
    }

    pub fn with_state(mut self, state: impl Into<String>) -> Self {
        self.state = Some(state.into());
        self
    }

    pub fn to_redirect_url(&self, redirect_uri: &url::Url) -> url::Url {
        let mut url = redirect_uri.clone();
        {
            let mut query = url.query_pairs_mut();
            query.append_pair("error", &self.error.to_string());
            if let Some(state) = &self.state {
                query.append_pair("state", state);
            }
        }
        url
    }

    pub fn to_fragment_redirect_url(&self, redirect_uri: &url::Url) -> url::Url {
        let mut url = redirect_uri.clone();
        let mut fragment = format!("error={}", self.error);
        if let Some(state) = &self.state {
            use std::fmt::Write;
            write!(fragment, "&state={state}").unwrap();
        }
        url.set_fragment(Some(&fragment));
        url
    }
}

#[cfg(test)]
mod tests {
    use super::OAuthErrorCode;
    use std::str::FromStr;

    #[test]
    fn oauth_error_code_from_str() {
        assert_eq!(
            OAuthErrorCode::from_str("invalid_request").unwrap(),
            OAuthErrorCode::InvalidRequest
        );
        assert_eq!(
            OAuthErrorCode::from_str("unauthorized_client").unwrap(),
            OAuthErrorCode::UnauthorizedClient
        );
        assert_eq!(
            OAuthErrorCode::from_str("access_denied").unwrap(),
            OAuthErrorCode::AccessDenied
        );
        assert_eq!(
            OAuthErrorCode::from_str("unsupported_response_type").unwrap(),
            OAuthErrorCode::UnsupportedResponseType
        );
        assert_eq!(
            OAuthErrorCode::from_str("invalid_scope").unwrap(),
            OAuthErrorCode::InvalidScope
        );
        assert_eq!(
            OAuthErrorCode::from_str("server_error").unwrap(),
            OAuthErrorCode::ServerError
        );
        assert_eq!(
            OAuthErrorCode::from_str("temporarily_unavailable").unwrap(),
            OAuthErrorCode::TemporarilyUnavailable
        );
        assert_eq!(
            OAuthErrorCode::from_str("login_required").unwrap(),
            OAuthErrorCode::LoginRequired
        );
        assert_eq!(
            OAuthErrorCode::from_str("consent_required").unwrap(),
            OAuthErrorCode::ConsentRequired
        );
        assert_eq!(
            OAuthErrorCode::from_str("interaction_required").unwrap(),
            OAuthErrorCode::InteractionRequired
        );
    }

    #[test]
    fn oauth_error_code_display() {
        assert_eq!(
            OAuthErrorCode::InvalidRequest.to_string(),
            "invalid_request"
        );
        assert_eq!(OAuthErrorCode::LoginRequired.to_string(), "login_required");
    }

    #[test]
    fn to_fragment_redirect_url_places_error_in_fragment() {
        let error =
            super::OAuthErrorResponse::new(OAuthErrorCode::AccessDenied).with_state("state123");
        let redirect_uri = url::Url::parse("https://client.example.com/callback").unwrap();
        let url = error.to_fragment_redirect_url(&redirect_uri);

        assert_eq!(url.query(), None);
        assert_eq!(url.fragment(), Some("error=access_denied&state=state123"));
    }

    #[test]
    fn to_redirect_url_places_error_in_query() {
        let error = super::OAuthErrorResponse::new(OAuthErrorCode::LoginRequired).with_state("abc");
        let redirect_uri = url::Url::parse("https://client.example.com/callback").unwrap();
        let url = error.to_redirect_url(&redirect_uri);

        assert_eq!(url.fragment(), None);
        assert!(url.query().unwrap().contains("error=login_required"));
        assert!(url.query().unwrap().contains("state=abc"));
    }
}
