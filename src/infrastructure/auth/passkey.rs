//! WebAuthn SDK adapter. No SDK types cross the application boundary.
use std::sync::Arc;

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use identity_application::{
    auth::passkey::{PasskeyAuthenticator, PasskeyCeremony, StoredPasskey, VerifiedPasskey},
    error::{AppError, codes::auth::AuthErrorCode},
    setting::{LoginDomainSetting, SettingsSource},
    user::UserOid,
};
use serde_json::Value;
use webauthn_rs::prelude::*;

pub struct WebAuthnAuthenticator {
    settings: Arc<dyn SettingsSource>,
}
impl WebAuthnAuthenticator {
    pub fn new(settings: Arc<dyn SettingsSource>) -> Self {
        Self { settings }
    }
    fn webauthn(&self) -> Result<Webauthn, AppError> {
        let origin = self
            .settings
            .snapshot()
            .get::<LoginDomainSetting>()
            .ok_or_else(invalid)?;
        let origin = Url::parse(&origin).map_err(AppError::internal)?;
        let rp = origin.host_str().ok_or_else(invalid)?;
        WebauthnBuilder::new(rp, &origin)
            .map_err(AppError::internal)?
            .rp_name("Identity")
            .build()
            .map_err(AppError::internal)
    }
}
fn keys(credentials: &[StoredPasskey]) -> Result<Vec<Passkey>, AppError> {
    credentials
        .iter()
        .map(|credential| {
            serde_json::from_value(credential.data.key.clone()).map_err(AppError::internal)
        })
        .collect()
}
fn ceremony(options: Value, state: Value) -> Result<PasskeyCeremony, AppError> {
    Ok(PasskeyCeremony {
        public_key: options.get("publicKey").cloned().ok_or_else(invalid)?,
        state,
    })
}
fn invalid() -> AppError {
    AppError::from_code(AuthErrorCode::InvalidCredential)
}
impl PasskeyAuthenticator for WebAuthnAuthenticator {
    fn start_registration(
        &self,
        user: UserOid,
        username: &str,
        credentials: &[StoredPasskey],
    ) -> Result<PasskeyCeremony, AppError> {
        let excluded = keys(credentials)?
            .iter()
            .map(|key| key.cred_id().clone())
            .collect();
        let (options, state) = self
            .webauthn()?
            .start_passkey_registration(user.into(), username, username, Some(excluded))
            .map_err(AppError::internal)?;
        ceremony(
            serde_json::to_value(options).map_err(AppError::internal)?,
            serde_json::to_value(state).map_err(AppError::internal)?,
        )
    }
    fn finish_registration(
        &self,
        state: Value,
        credential: Value,
    ) -> Result<VerifiedPasskey, AppError> {
        let state = serde_json::from_value(state).map_err(AppError::internal)?;
        let credential = serde_json::from_value(credential).map_err(|_| invalid())?;
        let key = self
            .webauthn()?
            .finish_passkey_registration(&credential, &state)
            .map_err(|_| invalid())?;
        Ok(VerifiedPasskey {
            credential_id: URL_SAFE_NO_PAD.encode(key.cred_id()),
            key: serde_json::to_value(key).map_err(AppError::internal)?,
            user_verified: true,
        })
    }
    fn start_authentication(
        &self,
        credentials: &[StoredPasskey],
    ) -> Result<PasskeyCeremony, AppError> {
        let (options, state) = self
            .webauthn()?
            .start_passkey_authentication(&keys(credentials)?)
            .map_err(|_| invalid())?;
        ceremony(
            serde_json::to_value(options).map_err(AppError::internal)?,
            serde_json::to_value(state).map_err(AppError::internal)?,
        )
    }
    fn finish_authentication(
        &self,
        state: Value,
        credential: Value,
        credentials: &[StoredPasskey],
    ) -> Result<VerifiedPasskey, AppError> {
        let state = serde_json::from_value(state).map_err(AppError::internal)?;
        let credential = serde_json::from_value(credential).map_err(|_| invalid())?;
        let result = self
            .webauthn()?
            .finish_passkey_authentication(&credential, &state)
            .map_err(|_| invalid())?;
        let mut key = keys(credentials)?
            .into_iter()
            .find(|key| key.cred_id() == result.cred_id())
            .ok_or_else(invalid)?;
        key.update_credential(&result).ok_or_else(invalid)?;
        Ok(VerifiedPasskey {
            credential_id: URL_SAFE_NO_PAD.encode(result.cred_id()),
            key: serde_json::to_value(key).map_err(AppError::internal)?,
            user_verified: result.user_verified(),
        })
    }
}
#[cfg(test)]
pub(crate) mod tests;
