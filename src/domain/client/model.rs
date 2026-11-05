use std::{error::Error, fmt, str::FromStr};

use chrono::{DateTime, Utc};
use uuid::Uuid;

use crate::rbac::LocalizedText;

pub type ClientOid = Uuid;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClientProtocol {
    OpenIdConnect,
    Other(String),
}

impl fmt::Display for ClientProtocol {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::OpenIdConnect => f.write_str("openid_connect"),
            Self::Other(value) => f.write_str(value),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParseClientProtocolError;

impl fmt::Display for ParseClientProtocolError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("invalid client protocol")
    }
}

impl Error for ParseClientProtocolError {}

impl FromStr for ClientProtocol {
    type Err = ParseClientProtocolError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.is_empty() {
            Err(ParseClientProtocolError)
        } else {
            Ok(match s {
                "openid_connect" => Self::OpenIdConnect,
                other => Self::Other(other.to_string()),
            })
        }
    }
}

#[derive(Debug, Clone)]
pub struct Client {
    pub oid: ClientOid,
    pub protocol: ClientProtocol,
    /// Independent default display name.
    pub name: String,
    /// Optional translations of `name`; viewers choose the language.
    pub names: Vec<LocalizedText>,
    pub description: Option<String>,
    /// Optional translations of `description`.
    pub descriptions: Vec<LocalizedText>,
    pub built_in: bool,
    pub enabled: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: Option<DateTime<Utc>>,
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use super::ClientProtocol;

    #[test]
    fn parses_openid_connect_protocol() {
        let protocol = ClientProtocol::from_str("openid_connect").unwrap();
        assert_eq!(protocol, ClientProtocol::OpenIdConnect);
    }

    #[test]
    fn preserves_unknown_protocols() {
        let protocol = ClientProtocol::from_str("custom-protocol").unwrap();
        assert_eq!(
            protocol,
            ClientProtocol::Other("custom-protocol".to_string())
        );
    }

    #[test]
    fn rejects_empty_protocols() {
        assert!(ClientProtocol::from_str("").is_err());
    }
}
