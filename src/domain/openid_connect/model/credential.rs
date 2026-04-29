use chrono::{DateTime, Utc};
use std::fmt::Display;
use std::str::FromStr;
use thiserror::Error;
use url::Url;

use crate::client::model::ClientOid;

pub type OpenIdConnectCredentialOid = uuid::Uuid;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum OpenIdConnectCredentialType {
    ClientSecret,
    ClientPublicKey,
    ClientJsonWebKeySet,
}

#[derive(Debug, Error)]
#[error("unknown credential type: {value}")]
pub struct ParseOpenIdConnectCredentialTypeError {
    value: String,
}

impl Display for OpenIdConnectCredentialType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ClientSecret => write!(f, "client_secret"),
            Self::ClientPublicKey => write!(f, "client_public_key"),
            Self::ClientJsonWebKeySet => write!(f, "client_json_web_key_set"),
        }
    }
}

impl FromStr for OpenIdConnectCredentialType {
    type Err = ParseOpenIdConnectCredentialTypeError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "client_secret" => Ok(Self::ClientSecret),
            "client_public_key" => Ok(Self::ClientPublicKey),
            "client_json_web_key_set" => Ok(Self::ClientJsonWebKeySet),
            _ => Err(ParseOpenIdConnectCredentialTypeError {
                value: s.to_string(),
            }),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OpenIdConnectCredentialData {
    ClientSecret {
        secret: String,
    },
    ClientPublicKey {
        public_key: String,
    },
    ClientJsonWebKeySet {
        jwks_uri: Url,
        last_updated: DateTime<Utc>,
        expires_at: DateTime<Utc>,
        public_keys: Vec<String>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpenIdConnectCredential {
    pub oid: OpenIdConnectCredentialOid,
    pub client_oid: ClientOid,
    pub r#type: OpenIdConnectCredentialType,
    pub hint: String,
    pub data: OpenIdConnectCredentialData,
    pub expires_at: DateTime<Utc>,
    pub revoked_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub updated_at: Option<DateTime<Utc>>,
}

#[cfg(test)]
mod tests {
    use super::{
        OpenIdConnectCredential, OpenIdConnectCredentialData, OpenIdConnectCredentialType,
    };
    use chrono::Utc;
    use std::str::FromStr;
    use url::Url;
    use uuid::Uuid;

    #[test]
    fn parses_credential_type() {
        assert_eq!(
            OpenIdConnectCredentialType::from_str("client_secret").unwrap(),
            OpenIdConnectCredentialType::ClientSecret
        );
    }

    #[test]
    fn retains_jwks_public_keys() {
        let data = OpenIdConnectCredentialData::ClientJsonWebKeySet {
            jwks_uri: Url::parse("https://rp.example.com/jwks.json").unwrap(),
            last_updated: Utc::now(),
            expires_at: Utc::now(),
            public_keys: vec!["-----BEGIN PUBLIC KEY-----".to_string()],
        };

        match data {
            OpenIdConnectCredentialData::ClientJsonWebKeySet { public_keys, .. } => {
                assert_eq!(public_keys, vec!["-----BEGIN PUBLIC KEY-----".to_string()]);
            }
            _ => panic!("unexpected variant"),
        }
    }

    #[test]
    fn credential_carries_client_oid() {
        let credential = OpenIdConnectCredential {
            oid: Uuid::nil(),
            client_oid: Uuid::new_v4(),
            r#type: OpenIdConnectCredentialType::ClientSecret,
            hint: "login".to_string(),
            data: OpenIdConnectCredentialData::ClientSecret {
                secret: "secret".to_string(),
            },
            expires_at: Utc::now(),
            revoked_at: None,
            created_at: Utc::now(),
            updated_at: None,
        };

        assert_eq!(credential.hint, "login");
    }
}
