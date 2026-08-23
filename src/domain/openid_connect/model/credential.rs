use chrono::{DateTime, Utc};
use std::str::FromStr;
use strum::{AsRefStr, Display, EnumIter, IntoEnumIterator};
use thiserror::Error;
use url::Url;

use crate::client::model::ClientOid;
use crate::key::PublicJwk;

pub type OpenIdConnectCredentialOid = uuid::Uuid;

#[derive(Debug, Clone, PartialEq, Eq, Hash, Display, AsRefStr, EnumIter)]
#[strum(serialize_all = "snake_case")]
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

impl FromStr for OpenIdConnectCredentialType {
    type Err = ParseOpenIdConnectCredentialTypeError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::iter()
            .find(|variant| variant.as_ref() == s)
            .ok_or_else(|| ParseOpenIdConnectCredentialTypeError {
                value: s.to_string(),
            })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OpenIdConnectCredentialData {
    ClientSecret {
        secret: String,
    },
    ClientPublicKey {
        public_key: String,
        jwk: Option<PublicJwk>,
    },
    ClientJsonWebKeySet {
        jwks_uri: Url,
        last_updated: DateTime<Utc>,
        expires_at: DateTime<Utc>,
        public_keys: Vec<String>,
        jwks: Vec<PublicJwk>,
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
    use super::OpenIdConnectCredentialType;
    use std::str::FromStr;

    #[test]
    fn parses_credential_type() {
        assert_eq!(
            OpenIdConnectCredentialType::from_str("client_secret").unwrap(),
            OpenIdConnectCredentialType::ClientSecret
        );
    }
}
