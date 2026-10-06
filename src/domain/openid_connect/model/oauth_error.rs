use std::{error::Error, fmt, str::FromStr};

use strum::{AsRefStr, Display, EnumIter, IntoEnumIterator};
use url::{Url, form_urlencoded::Serializer};

#[derive(Debug, Clone, PartialEq, Eq, Display, AsRefStr, EnumIter)]
#[strum(serialize_all = "snake_case")]
pub enum OAuthErrorCode {
    InvalidRequest,
    UnauthorizedClient,
    AccessDenied,
    UnsupportedResponseType,
    InvalidScope,
    InvalidTarget,
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

impl Error for ParseOAuthErrorCodeError {}

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
    pub issuer: Option<String>,
}

impl OAuthErrorResponse {
    pub fn new(error: OAuthErrorCode) -> Self {
        Self {
            error,
            error_description: None,
            error_uri: None,
            state: None,
            issuer: None,
        }
    }

    pub fn with_state(mut self, state: impl Into<String>) -> Self {
        self.state = Some(state.into());
        self
    }

    pub fn with_description(mut self, description: impl Into<String>) -> Self {
        self.error_description = Some(description.into());
        self
    }

    pub fn with_issuer(mut self, issuer: impl Into<String>) -> Self {
        self.issuer = Some(issuer.into());
        self
    }

    pub fn to_redirect_url(&self, redirect_uri: &Url) -> Url {
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
            if let Some(issuer) = &self.issuer {
                query.append_pair("iss", issuer);
            }
        }
        url
    }

    pub fn to_fragment_redirect_url(&self, redirect_uri: &Url) -> Url {
        let mut url = redirect_uri.clone();
        let mut serializer = Serializer::new(String::new());
        serializer.append_pair("error", self.error.as_ref());
        if let Some(error_description) = &self.error_description {
            serializer.append_pair("error_description", error_description);
        }
        if let Some(state) = &self.state {
            serializer.append_pair("state", state);
        }
        if let Some(issuer) = &self.issuer {
            serializer.append_pair("iss", issuer);
        }
        url.set_fragment(Some(&serializer.finish()));
        url
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use url::{Url, form_urlencoded::parse};

    use super::{OAuthErrorCode, OAuthErrorResponse};

    #[test]
    fn to_fragment_redirect_url_places_error_in_fragment() {
        let error = OAuthErrorResponse::new(OAuthErrorCode::AccessDenied)
            .with_description("The authorization request was denied.")
            .with_state("state123")
            .with_issuer("https://identity.example.com/");
        let redirect_uri = Url::parse("https://client.example.com/callback").unwrap();
        let url = error.to_fragment_redirect_url(&redirect_uri);

        assert_eq!(url.query(), None);
        let fields = parse(url.fragment().unwrap().as_bytes())
            .into_owned()
            .collect::<HashMap<_, _>>();
        assert_eq!(
            fields.get("error").map(String::as_str),
            Some("access_denied")
        );
        assert_eq!(
            fields.get("error_description").map(String::as_str),
            Some("The authorization request was denied.")
        );
        assert_eq!(fields.get("state").map(String::as_str), Some("state123"));
        assert_eq!(
            fields.get("iss").map(String::as_str),
            Some("https://identity.example.com/")
        );
    }

    #[test]
    fn to_redirect_url_places_error_in_query() {
        let error = OAuthErrorResponse::new(OAuthErrorCode::LoginRequired)
            .with_description("The user must sign in to continue.")
            .with_state("abc")
            .with_issuer("https://identity.example.com/");
        let redirect_uri = Url::parse("https://client.example.com/callback").unwrap();
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
        assert_eq!(
            url.query_pairs()
                .find(|(name, _)| name == "iss")
                .map(|(_, value)| value.into_owned()),
            Some("https://identity.example.com/".to_owned())
        );
    }
}
