use http::{HeaderMap, header};
use identity_application::{
    error::{AppError, codes::token::TokenErrorCode},
    openid_connect::token::TokenRevocationParams,
};
use serde::Deserialize;

use super::super::client_credentials::{ClientCredentials, parse_basic_client_auth};

#[derive(Debug, Deserialize)]
pub(super) struct TokenForm {
    #[serde(default, rename = "resource")]
    pub(super) resources: Vec<String>,
    pub(super) grant_type: String,
    pub(super) code: Option<String>,
    pub(super) device_code: Option<String>,
    pub(super) refresh_token: Option<String>,
    /// Optional narrowing of the granted scope on a refresh (RFC 6749 §6).
    pub(super) scope: Option<String>,
    pub(super) redirect_uri: Option<String>,
    pub(super) client_id: Option<String>,
    pub(super) client_secret: Option<String>,
    pub(super) client_assertion_type: Option<String>,
    pub(super) client_assertion: Option<String>,
    pub(super) code_verifier: Option<String>,
}

/// RFC 7009 / RFC 7662 share transport parameters and reject ambiguous
/// authentication before either operation is executed.
#[derive(Deserialize)]
pub(super) struct TokenInspectionForm {
    token: String,
    /// Optional hints may be ignored; both supported token formats are checked.
    #[serde(rename = "token_type_hint")]
    _token_type_hint: Option<String>,
    client_id: Option<String>,
    client_secret: Option<String>,
    client_assertion_type: Option<String>,
    client_assertion: Option<String>,
}

impl TokenInspectionForm {
    pub fn prepare(self, headers: &HeaderMap) -> Result<TokenRevocationParams, AppError> {
        if self.token.is_empty() {
            return Err(AppError::from_code(TokenErrorCode::RefreshTokenInvalid));
        }
        let basic = parse_basic_client_auth(headers);
        if headers.contains_key(header::AUTHORIZATION) && basic.is_none() {
            return Err(AppError::from_code(
                TokenErrorCode::ClientCredentialsInvalid,
            ));
        }
        if basic.is_some()
            && (self.client_secret.is_some()
                || self.client_assertion.is_some()
                || self.client_id.as_ref().is_some_and(|id| {
                    Some(id.as_str()) != basic.as_ref().map(|(id, _)| id.as_str())
                }))
        {
            return Err(AppError::from_code(TokenErrorCode::RefreshTokenInvalid));
        }
        let credentials = ClientCredentials::resolve(
            headers,
            self.client_id,
            self.client_secret,
            self.client_assertion_type,
        )?;
        Ok(TokenRevocationParams {
            token: self.token,
            client_id: credentials.client_id,
            client_secret: credentials.client_secret,
            client_secret_basic: credentials.basic,
            client_assertion_type: credentials.assertion_type,
            client_assertion: self.client_assertion,
        })
    }
}
