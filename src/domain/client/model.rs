use chrono::{DateTime, Utc};
use std::{fmt, str::FromStr};
use uuid::Uuid;

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

impl std::error::Error for ParseClientProtocolError {}

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
    pub name: String,
    pub names: Vec<String>,
    pub description: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: Option<DateTime<Utc>>,
}

#[cfg(test)]
mod tests {
    use super::ClientProtocol;
    use std::str::FromStr;

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
