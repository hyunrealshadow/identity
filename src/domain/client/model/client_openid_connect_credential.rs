use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::fmt::Display;
use std::str::FromStr;
use thiserror::Error;

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ClientOpenIdConnectCredentialType {
    ClientSecret,
    ClientPublicKey,
    ClientJsonWebKeySet,
}

#[derive(Debug, Error)]
#[error("unknown key type: {value}")]
pub struct ParseClientOpenIdConnectCredentialTypeError {
    value: String,
}
impl Display for ClientOpenIdConnectCredentialType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ClientSecret => write!(f, "client_secret"),
            Self::ClientPublicKey => write!(f, "client_public_key"),
            Self::ClientJsonWebKeySet => write!(f, "client_json_web_key_set"),
        }
    }
}

impl FromStr for ClientOpenIdConnectCredentialType {
    type Err = ParseClientOpenIdConnectCredentialTypeError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "client_secret" => Ok(Self::ClientSecret),
            "client_public_key" => Ok(Self::ClientPublicKey),
            "client_json_web_key_set" => Ok(Self::ClientJsonWebKeySet),
            _ => Err(ParseClientOpenIdConnectCredentialTypeError {
                value: s.to_string(),
            }),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct OpenIdConnectClientSecret {
    secret: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct OpenIdConnectClientPublicKey {
    public_key: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct OpenIdConnectClientJsonWebKeySet {
    jwks_uri: String,
    last_updated: DateTime<Utc>,
    expires_at: DateTime<Utc>,
    public_keys: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ClientOpenIdConnectCredentialData {
    ClientSecret(OpenIdConnectClientSecret),
    ClientPublicKey(OpenIdConnectClientPublicKey),
    ClientJsonWebKeySet(OpenIdConnectClientJsonWebKeySet),
}
