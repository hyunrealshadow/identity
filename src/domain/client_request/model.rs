use std::{fmt, str::FromStr};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::domain::client::model::ClientOid;

pub type ClientRequestOid = Uuid;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClientRequestType {
    AuthorizationRequest,
    AuthorizationCode,
    RefreshToken,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParseClientRequestTypeError;

impl fmt::Display for ParseClientRequestTypeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("invalid client request type")
    }
}

impl std::error::Error for ParseClientRequestTypeError {}

impl fmt::Display for ClientRequestType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::AuthorizationRequest => "authorization_request",
            Self::AuthorizationCode => "authorization_code",
            Self::RefreshToken => "refresh_token",
        })
    }
}

impl FromStr for ClientRequestType {
    type Err = ParseClientRequestTypeError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(match s {
            "authorization_request" => Self::AuthorizationRequest,
            "authorization_code" => Self::AuthorizationCode,
            "refresh_token" => Self::RefreshToken,
            _ => return Err(ParseClientRequestTypeError),
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AuthorizationCodeData {
    pub scope: String,
    pub nonce: Option<String>,
    pub code_challenge: Option<String>,
    pub code_challenge_method: Option<String>,
    pub user_oid: String,
    pub session_oid: String,
    pub acr: Option<String>,
    pub redirect_uri: String,
    pub auth_time: Option<i64>,
    pub claims: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RefreshTokenData {
    pub token: String,
    pub scope: String,
    pub user_oid: String,
    pub session_oid: String,
    pub rotated_from: Option<String>,
}

#[derive(Debug, Clone)]
pub struct ClientRequest {
    pub oid: ClientRequestOid,
    pub client_oid: ClientOid,
    pub type_: ClientRequestType,
    pub data: serde_json::Value,
    pub expires_at: DateTime<Utc>,
    pub revoked_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub updated_at: Option<DateTime<Utc>>,
}

#[cfg(test)]
mod tests {
    use super::{AuthorizationCodeData, ClientRequestType, RefreshTokenData};
    use std::str::FromStr;

    #[test]
    fn client_request_type_from_str() {
        assert_eq!(
            ClientRequestType::from_str("authorization_request").unwrap(),
            ClientRequestType::AuthorizationRequest
        );
        assert_eq!(
            ClientRequestType::from_str("authorization_code").unwrap(),
            ClientRequestType::AuthorizationCode
        );
    }

    #[test]
    fn authorization_code_data_serialization() {
        let data = AuthorizationCodeData {
            scope: "openid profile".to_string(),
            nonce: Some("nonce123".to_string()),
            code_challenge: Some("challenge123".to_string()),
            code_challenge_method: Some("S256".to_string()),
            user_oid: uuid::Uuid::nil().to_string(),
            session_oid: uuid::Uuid::nil().to_string(),
            acr: Some("urn:mfa".to_string()),
            redirect_uri: "https://client.example.com/callback".to_string(),
            auth_time: Some(1234567890),
            claims: None,
        };

        let json = serde_json::to_string(&data).unwrap();
        let parsed: AuthorizationCodeData = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.scope, "openid profile");
    }

    #[test]
    fn refresh_token_data_serialization() {
        let data = RefreshTokenData {
            token: "refresh-123".to_string(),
            scope: "openid offline_access profile".to_string(),
            user_oid: uuid::Uuid::nil().to_string(),
            session_oid: uuid::Uuid::nil().to_string(),
            rotated_from: Some("refresh-old".to_string()),
        };

        let json = serde_json::to_string(&data).unwrap();
        let parsed: RefreshTokenData = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.token, "refresh-123");
        assert_eq!(parsed.rotated_from.as_deref(), Some("refresh-old"));
    }
}
