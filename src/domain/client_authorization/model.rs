use std::{error::Error, fmt, str::FromStr};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use strum::{AsRefStr, Display, EnumIter, IntoEnumIterator};
use uuid::Uuid;

use crate::{
    auth::model::SessionOid,
    client::model::ClientOid,
    openid_connect::{
        AuthorizationRequestData, ClaimsRequest, CodeChallengeMethod,
        model::authorization_request::AuthorizationRequestParams,
    },
};

pub use super::device::{
    DeviceAuthorizationApproval, DeviceAuthorizationData, DeviceAuthorizationRequestData,
    DevicePollOutcome, DeviceRequestStatus, DeviceRequestTransitionError,
    SLOW_DOWN_INCREMENT_SECONDS, USER_CODE_ALPHABET, USER_CODE_LENGTH, device_code_digest,
    format_user_code, normalize_user_code,
};

pub type ClientAuthorizationOid = Uuid;

#[derive(Debug, Clone, PartialEq, Eq, Display, AsRefStr, EnumIter)]
#[strum(serialize_all = "snake_case")]
pub enum ClientAuthorizationType {
    PushedAuthorizationRequest,
    AuthorizationRequest,
    AuthorizationCode,
    AccessToken,
    RefreshToken,
    RegistrationAccessToken,
    DeviceAuthorizationRequest,
    DeviceAuthorization,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParseClientAuthorizationTypeError;

impl fmt::Display for ParseClientAuthorizationTypeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("invalid client authorization type")
    }
}

impl Error for ParseClientAuthorizationTypeError {}

impl FromStr for ClientAuthorizationType {
    type Err = ParseClientAuthorizationTypeError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::iter()
            .find(|variant| variant.as_ref() == s)
            .ok_or(ParseClientAuthorizationTypeError)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AuthorizationCodeData {
    pub scope: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub resources: Vec<String>,
    pub nonce: Option<String>,
    pub code_challenge: Option<String>,
    pub code_challenge_method: Option<CodeChallengeMethod>,
    pub user_oid: String,
    pub session_oid: SessionOid,
    #[serde(default)]
    pub protected_session_id: Option<String>,
    pub acr: Option<String>,
    #[serde(default)]
    pub amr: Vec<String>,
    pub redirect_uri: String,
    #[serde(default = "default_redirect_uri_was_supplied")]
    pub redirect_uri_was_supplied: bool,
    pub auth_time: Option<i64>,
    pub claims: Option<ClaimsRequest>,
}

fn default_redirect_uri_was_supplied() -> bool {
    true
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RefreshTokenData {
    pub scope: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub resources: Vec<String>,
    pub user_oid: String,
    /// Browser session the token was issued from; `None` for device issued
    /// tokens, which are bound to a device authorization relation instead.
    #[serde(default)]
    pub session_oid: Option<SessionOid>,
    #[serde(default)]
    pub protected_session_id: Option<String>,
    pub auth_time: Option<i64>,
    pub acr: Option<String>,
    #[serde(default)]
    pub amr: Vec<String>,
    pub rotated_from: Option<String>,
    #[serde(default)]
    pub authorization_code_oid: Option<String>,
    /// Device authorization relation this token belongs to, when the token was
    /// not issued from a browser session.
    #[serde(default)]
    pub device_authorization_oid: Option<String>,
    /// Bound to the authentication mode used when this token was issued.
    /// Legacy records omit this field.
    #[serde(default)]
    pub client_authentication_mode: Option<ClientAuthenticationMode>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AccessTokenData {
    pub scope: String,
    pub user_oid: String,
    /// Browser session the token was issued from. `None` for tokens issued
    /// from a device authorization relation, which is independent of the
    /// browser session that approved it (ADR 0004).
    #[serde(default)]
    pub session_oid: Option<SessionOid>,
    #[serde(default)]
    pub protected_session_id: Option<String>,
    pub authorization_code_oid: Option<String>,
    #[serde(default)]
    pub refresh_token_oid: Option<String>,
    /// Device authorization relation the token was issued from, when the
    /// token was not issued from a browser session.
    #[serde(default)]
    pub device_authorization_oid: Option<String>,
    #[serde(default)]
    pub client_authentication_mode: Option<ClientAuthenticationMode>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ClientAuthenticationMode {
    Public,
    Confidential,
}

impl ClientAuthenticationMode {
    #[must_use]
    pub const fn from_credentials(has_credentials: bool) -> Self {
        if has_credentials {
            Self::Confidential
        } else {
            Self::Public
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RegistrationAccessTokenData {
    pub token: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct StoredAuthorizationRequest {
    pub request: AuthorizationRequestData,
    #[serde(default)]
    pub interaction: AuthorizationInteractionState,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PushedAuthorizationRequestData {
    pub request_uri_digest: String,
    pub parameters: AuthorizationRequestParams,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClientAuthorizationData {
    PushedAuthorizationRequest(PushedAuthorizationRequestData),
    AuthorizationRequest(StoredAuthorizationRequest),
    AuthorizationCode(AuthorizationCodeData),
    AccessToken(AccessTokenData),
    RefreshToken(RefreshTokenData),
    RegistrationAccessToken(RegistrationAccessTokenData),
    DeviceAuthorizationRequest(DeviceAuthorizationRequestData),
    DeviceAuthorization(DeviceAuthorizationData),
}

impl ClientAuthorizationData {
    #[must_use]
    pub const fn authorization_type(&self) -> ClientAuthorizationType {
        match self {
            Self::PushedAuthorizationRequest(_) => {
                ClientAuthorizationType::PushedAuthorizationRequest
            }
            Self::AuthorizationRequest(_) => ClientAuthorizationType::AuthorizationRequest,
            Self::AuthorizationCode(_) => ClientAuthorizationType::AuthorizationCode,
            Self::AccessToken(_) => ClientAuthorizationType::AccessToken,
            Self::RefreshToken(_) => ClientAuthorizationType::RefreshToken,
            Self::RegistrationAccessToken(_) => ClientAuthorizationType::RegistrationAccessToken,
            Self::DeviceAuthorizationRequest(_) => {
                ClientAuthorizationType::DeviceAuthorizationRequest
            }
            Self::DeviceAuthorization(_) => ClientAuthorizationType::DeviceAuthorization,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct AuthorizationInteractionState {
    pub selected_session_oid: Option<SessionOid>,
    #[serde(default)]
    pub selected_protected_session_id: Option<String>,
    pub selected_user_oid: Option<String>,
    pub selection_source: Option<SelectionSource>,
    #[serde(default)]
    pub consent_state: ConsentState,
    pub consent_decided_at: Option<String>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Display, AsRefStr)]
#[serde(rename_all = "snake_case")]
#[strum(serialize_all = "snake_case")]
pub enum SelectionSource {
    Auto,
    AccountPicker,
    FreshLogin,
    Reauthentication,
}

impl SelectionSource {
    /// Prevents a weaker interaction from replacing a completed login selection.
    pub fn can_replace(self, current: Option<Self>) -> bool {
        match current {
            Some(Self::Reauthentication) => self == Self::Reauthentication,
            Some(Self::FreshLogin) => self != Self::AccountPicker,
            _ => true,
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default, Display, AsRefStr)]
#[serde(rename_all = "snake_case")]
#[strum(serialize_all = "snake_case")]
pub enum ConsentState {
    #[default]
    Pending,
    Approved,
    Denied,
}

#[derive(Debug, Clone)]
pub struct ClientAuthorization {
    pub oid: ClientAuthorizationOid,
    pub client_oid: ClientOid,
    pub type_: ClientAuthorizationType,
    pub data: ClientAuthorizationData,
    pub expires_at: DateTime<Utc>,
    pub completed_at: Option<DateTime<Utc>>,
    pub revoked_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub updated_at: Option<DateTime<Utc>>,
}

#[cfg(test)]
mod tests {
    use super::SelectionSource::{AccountPicker, Auto, FreshLogin, Reauthentication};

    #[test]
    fn selection_transitions_preserve_stronger_authentication() {
        let incoming = [Auto, AccountPicker, FreshLogin, Reauthentication];
        for (current, expected) in [
            (None, [true, true, true, true]),
            (Some(Auto), [true, true, true, true]),
            (Some(AccountPicker), [true, true, true, true]),
            (Some(FreshLogin), [true, false, true, true]),
            (Some(Reauthentication), [false, false, false, true]),
        ] {
            for (next, allowed) in incoming.into_iter().zip(expected) {
                assert_eq!(
                    next.can_replace(current),
                    allowed,
                    "{current:?} -> {next:?}"
                );
            }
        }
    }
}
