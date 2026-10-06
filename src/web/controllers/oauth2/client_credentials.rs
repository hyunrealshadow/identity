use base64::{Engine, engine::general_purpose::STANDARD};
use http::{HeaderMap, header};
use identity_application::error::{AppError, codes::token::TokenErrorCode};
use identity_domain::openid_connect::ClientAssertionType;

pub(super) fn parse_basic_client_auth(headers: &HeaderMap) -> Option<(String, String)> {
    let header = headers.get(header::AUTHORIZATION)?.to_str().ok()?;
    let encoded = header.strip_prefix("Basic ")?;
    let decoded = STANDARD.decode(encoded).ok()?;
    let decoded = String::from_utf8(decoded).ok()?;
    let (client_id, client_secret) = decoded.split_once(':')?;
    Some((client_id.to_string(), client_secret.to_string()))
}

/// Transport credentials only. Authentication and grant authorization remain
/// in the application service, so every grant uses the same security policy.
pub(super) struct ClientCredentials {
    pub client_id: Option<String>,
    pub client_secret: Option<String>,
    pub basic: bool,
    pub assertion_type: Option<ClientAssertionType>,
}

impl ClientCredentials {
    pub fn resolve(
        headers: &HeaderMap,
        client_id: Option<String>,
        client_secret: Option<String>,
        assertion_type: Option<String>,
    ) -> Result<Self, AppError> {
        let basic = parse_basic_client_auth(headers);
        let assertion_type = assertion_type
            .as_deref()
            .map(str::parse::<ClientAssertionType>)
            .transpose()
            .map_err(|_| AppError::from_code(TokenErrorCode::AssertionVerifyFailed))?;
        Ok(Self {
            client_id: basic.as_ref().map(|(id, _)| id.clone()).or(client_id),
            client_secret: basic
                .as_ref()
                .map(|(_, secret)| secret.clone())
                .or(client_secret),
            basic: basic.is_some(),
            assertion_type,
        })
    }
}
