use std::{fmt, str::FromStr};

use strum::{AsRefStr, Display, EnumIter, IntoEnumIterator};

#[derive(Debug, Clone, PartialEq, Eq, Display, AsRefStr, EnumIter)]
#[strum(serialize_all = "snake_case")]
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
    AccountSelectionRequired,
    InvalidRequestUri,
    InvalidRequestObject,
    RequestNotSupported,
    RequestUriNotSupported,
    RegistrationNotSupported,
    UnmetAuthenticationRequirements,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParseOAuthErrorCodeError;

impl fmt::Display for ParseOAuthErrorCodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("invalid oauth error code")
    }
}

impl std::error::Error for ParseOAuthErrorCodeError {}

impl OAuthErrorCode {
    #[must_use]
    pub const fn description(&self) -> &'static str {
        match self {
            Self::InvalidRequest => "The authorization request is invalid.",
            Self::UnauthorizedClient => "The client is not authorized to make this request.",
            Self::AccessDenied => "The authorization request was denied.",
            Self::UnsupportedResponseType => "The requested response type is not supported.",
            Self::InvalidScope => "The requested scope is invalid or unavailable.",
            Self::ServerError => "The authorization server could not complete the request.",
            Self::TemporarilyUnavailable => "The authorization server is temporarily unavailable.",
            Self::LoginRequired => "The user must sign in to continue.",
            Self::ConsentRequired => "The user must grant consent to continue.",
            Self::InteractionRequired => "User interaction is required to continue.",
            Self::AccountSelectionRequired => "The user must select an account to continue.",
            Self::InvalidRequestUri => "The request URI is invalid.",
            Self::InvalidRequestObject => "The request object is invalid.",
            Self::RequestNotSupported => "The authorization request is not supported.",
            Self::RequestUriNotSupported => "Request URIs are not supported.",
            Self::RegistrationNotSupported => "Dynamic client registration is not supported.",
            Self::UnmetAuthenticationRequirements => {
                "The authentication performed does not satisfy the requested requirements."
            }
        }
    }
}

impl FromStr for OAuthErrorCode {
    type Err = ParseOAuthErrorCodeError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::iter()
            .find(|variant| variant.as_ref() == s)
            .ok_or(ParseOAuthErrorCodeError)
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
        let error_description = Some(error.description().to_owned());
        Self {
            error,
            error_description,
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
            query.append_pair("error", self.error.as_ref());
            if let Some(error_description) = &self.error_description {
                query.append_pair("error_description", error_description);
            }
            if let Some(state) = &self.state {
                query.append_pair("state", state);
            }
        }
        url
    }

    pub fn to_fragment_redirect_url(&self, redirect_uri: &url::Url) -> url::Url {
        let mut url = redirect_uri.clone();
        let mut serializer = url::form_urlencoded::Serializer::new(String::new());
        serializer.append_pair("error", self.error.as_ref());
        if let Some(error_description) = &self.error_description {
            serializer.append_pair("error_description", error_description);
        }
        if let Some(state) = &self.state {
            serializer.append_pair("state", state);
        }
        url.set_fragment(Some(&serializer.finish()));
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
        assert_eq!(
            OAuthErrorCode::from_str("account_selection_required").unwrap(),
            OAuthErrorCode::AccountSelectionRequired
        );
        assert_eq!(
            OAuthErrorCode::from_str("invalid_request_uri").unwrap(),
            OAuthErrorCode::InvalidRequestUri
        );
        assert_eq!(
            OAuthErrorCode::from_str("invalid_request_object").unwrap(),
            OAuthErrorCode::InvalidRequestObject
        );
        assert_eq!(
            OAuthErrorCode::from_str("request_not_supported").unwrap(),
            OAuthErrorCode::RequestNotSupported
        );
        assert_eq!(
            OAuthErrorCode::from_str("request_uri_not_supported").unwrap(),
            OAuthErrorCode::RequestUriNotSupported
        );
        assert_eq!(
            OAuthErrorCode::from_str("registration_not_supported").unwrap(),
            OAuthErrorCode::RegistrationNotSupported
        );
    }

    #[test]
    fn oauth_error_code_display() {
        assert_eq!(
            OAuthErrorCode::InvalidRequest.to_string(),
            "invalid_request"
        );
        assert_eq!(OAuthErrorCode::LoginRequired.to_string(), "login_required");
        assert_eq!(
            OAuthErrorCode::AccountSelectionRequired.to_string(),
            "account_selection_required"
        );
        assert_eq!(
            OAuthErrorCode::RegistrationNotSupported.to_string(),
            "registration_not_supported"
        );
    }

    #[test]
    fn to_fragment_redirect_url_places_error_in_fragment() {
        let error =
            super::OAuthErrorResponse::new(OAuthErrorCode::AccessDenied).with_state("state123");
        let redirect_uri = url::Url::parse("https://client.example.com/callback").unwrap();
        let url = error.to_fragment_redirect_url(&redirect_uri);

        assert_eq!(url.query(), None);
        let fields = url::form_urlencoded::parse(url.fragment().unwrap().as_bytes())
            .into_owned()
            .collect::<std::collections::HashMap<_, _>>();
        assert_eq!(
            fields.get("error").map(String::as_str),
            Some("access_denied")
        );
        assert_eq!(
            fields.get("error_description").map(String::as_str),
            Some("The authorization request was denied.")
        );
        assert_eq!(fields.get("state").map(String::as_str), Some("state123"));
    }

    #[test]
    fn to_redirect_url_places_error_in_query() {
        let error = super::OAuthErrorResponse::new(OAuthErrorCode::LoginRequired).with_state("abc");
        let redirect_uri = url::Url::parse("https://client.example.com/callback").unwrap();
        let url = error.to_redirect_url(&redirect_uri);

        assert_eq!(url.fragment(), None);
        assert!(url.query().unwrap().contains("error=login_required"));
        assert_eq!(
            url.query_pairs()
                .find(|(name, _)| name == "error_description")
                .map(|(_, value)| value.into_owned()),
            Some("The user must sign in to continue.".to_owned())
        );
        assert!(url.query().unwrap().contains("state=abc"));
    }
}
