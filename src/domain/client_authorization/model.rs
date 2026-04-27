use std::{fmt, str::FromStr};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::domain::client::model::ClientOid;

pub type ClientAuthorizationOid = Uuid;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClientAuthorizationType {
    AuthorizationRequest,
    AuthorizationCode,
    AccessToken,
    RefreshToken,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParseClientAuthorizationTypeError;

impl fmt::Display for ParseClientAuthorizationTypeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("invalid client authorization type")
    }
}

impl std::error::Error for ParseClientAuthorizationTypeError {}

impl fmt::Display for ClientAuthorizationType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::AuthorizationRequest => "authorization_request",
            Self::AuthorizationCode => "authorization_code",
            Self::AccessToken => "access_token",
            Self::RefreshToken => "refresh_token",
        })
    }
}

impl FromStr for ClientAuthorizationType {
    type Err = ParseClientAuthorizationTypeError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(match s {
            "authorization_request" => Self::AuthorizationRequest,
            "authorization_code" => Self::AuthorizationCode,
            "access_token" => Self::AccessToken,
            "refresh_token" => Self::RefreshToken,
            _ => return Err(ParseClientAuthorizationTypeError),
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
    pub scope: String,
    pub user_oid: String,
    pub session_oid: String,
    pub rotated_from: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AccessTokenData {
    pub scope: String,
    pub user_oid: String,
    pub session_oid: String,
    pub authorization_code_oid: Option<String>,
}

#[derive(Debug, Clone)]
pub struct ClientAuthorization {
    pub oid: ClientAuthorizationOid,
    pub client_oid: ClientOid,
    pub type_: ClientAuthorizationType,
    pub data: serde_json::Value,
    pub expires_at: DateTime<Utc>,
    pub revoked_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub updated_at: Option<DateTime<Utc>>,
}

#[cfg(test)]
mod tests {
    use super::{
        AccessTokenData, AuthorizationCodeData, ClientAuthorizationType, RefreshTokenData,
    };
    use std::str::FromStr;

    #[test]
    fn client_authorization_type_from_str() {
        assert_eq!(
            ClientAuthorizationType::from_str("authorization_request").unwrap(),
            ClientAuthorizationType::AuthorizationRequest
        );
        assert_eq!(
            ClientAuthorizationType::from_str("authorization_code").unwrap(),
            ClientAuthorizationType::AuthorizationCode
        );
        assert_eq!(
            ClientAuthorizationType::from_str("access_token").unwrap(),
            ClientAuthorizationType::AccessToken
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
            scope: "openid offline_access profile".to_string(),
            user_oid: uuid::Uuid::nil().to_string(),
            session_oid: uuid::Uuid::nil().to_string(),
            rotated_from: Some(uuid::Uuid::nil().to_string()),
        };

        let json = serde_json::to_string(&data).unwrap();
        let parsed: RefreshTokenData = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.scope, "openid offline_access profile");
        let rotated_from = uuid::Uuid::nil().to_string();
        assert_eq!(parsed.rotated_from.as_deref(), Some(rotated_from.as_str()));
    }

    #[test]
    fn access_token_data_serialization() {
        let data = AccessTokenData {
            scope: "openid profile".to_string(),
            user_oid: uuid::Uuid::nil().to_string(),
            session_oid: uuid::Uuid::nil().to_string(),
            authorization_code_oid: Some(uuid::Uuid::nil().to_string()),
        };

        let json = serde_json::to_string(&data).unwrap();
        let parsed: AccessTokenData = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.scope, "openid profile");
        assert!(parsed.authorization_code_oid.is_some());
    }
}
