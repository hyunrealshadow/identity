use identity_domain::openid_connect::ClientAssertionType;

#[derive(Debug, Clone)]
pub struct AuthorizationCodeGrantParams {
    pub resources: Vec<String>,
    pub code: String,
    pub redirect_uri: Option<String>,
    pub client_id: Option<String>,
    pub code_verifier: Option<String>,
    pub client_secret: Option<String>,
    pub client_secret_basic: bool,
    pub client_assertion_type: Option<ClientAssertionType>,
    pub client_assertion: Option<String>,
}

#[derive(Debug, Clone)]
pub struct DeviceCodeGrantParams {
    pub resources: Vec<String>,
    pub device_code: String,
    pub client_id: Option<String>,
    pub client_secret: Option<String>,
    pub client_secret_basic: bool,
    pub client_assertion_type: Option<ClientAssertionType>,
    pub client_assertion: Option<String>,
}

#[derive(Debug, Clone)]
pub struct RefreshTokenGrantParams {
    pub resources: Vec<String>,
    pub refresh_token: String,
    /// Optional narrowing of the originally granted scope (RFC 6749 §6).
    pub scope: Option<String>,
    pub client_id: Option<String>,
    pub client_secret: Option<String>,
    pub client_secret_basic: bool,
    pub client_assertion_type: Option<ClientAssertionType>,
    pub client_assertion: Option<String>,
}

#[derive(Debug, Clone)]
pub struct ClientCredentialsGrantParams {
    pub resources: Vec<String>,
    pub scope: Option<String>,
    pub client_id: Option<String>,
    pub client_secret: Option<String>,
    pub client_secret_basic: bool,
    pub client_assertion_type: Option<ClientAssertionType>,
    pub client_assertion: Option<String>,
}

#[derive(Debug, Clone)]
pub struct TokenRevocationParams {
    pub token: String,
    pub client_id: Option<String>,
    pub client_secret: Option<String>,
    pub client_secret_basic: bool,
    pub client_assertion_type: Option<ClientAssertionType>,
    pub client_assertion: Option<String>,
}

/// Introspection uses the same confidential client credentials as revocation.
pub type TokenIntrospectionParams = TokenRevocationParams;

#[derive(Debug, Clone, serde::Serialize)]
pub struct TokenResponse {
    pub access_token: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id_token: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub refresh_token: Option<String>,
    pub token_type: TokenType,
    pub expires_in: i32,
    pub scope: String,
}

#[derive(Debug, Clone, Copy, serde::Serialize)]
pub enum TokenType {
    #[serde(rename = "Bearer")]
    Bearer,
}
