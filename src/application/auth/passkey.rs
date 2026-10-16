//! Account-bound Passkey use cases. Cryptographic verification and persistence are ports.
use std::sync::Arc;

use chrono::Utc;
use identity_domain::auth::challenge::{
    AuthenticationChallenge, ChallengeBinding, ChallengeContext, ChallengeMethod, ChallengePurpose,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use uuid::Uuid;

pub use crate::user::credential::StoredPasskey;
use crate::{
    auth::challenge::ChallengeRepository,
    error::{AppError, codes::auth::AuthErrorCode},
    observability::{BusinessEvent, EventSink, EventValue, NoopEventSink},
    user::{UserOid, credential::PasskeyCredentialData, repository::PasskeyCredentialRepository},
};

pub struct PasskeyCeremony {
    pub public_key: Value,
    pub state: Value,
}

pub struct VerifiedPasskey {
    pub credential_id: String,
    pub key: Value,
    pub user_verified: bool,
}

/// SDK-independent cryptographic operations, implemented by the WebAuthn adapter.
pub trait PasskeyAuthenticator: Send + Sync {
    fn start_registration(
        &self,
        user: UserOid,
        username: &str,
        credentials: &[StoredPasskey],
    ) -> Result<PasskeyCeremony, AppError>;
    fn finish_registration(
        &self,
        state: Value,
        credential: Value,
    ) -> Result<VerifiedPasskey, AppError>;
    fn start_authentication(
        &self,
        credentials: &[StoredPasskey],
    ) -> Result<PasskeyCeremony, AppError>;
    fn finish_authentication(
        &self,
        state: Value,
        credential: Value,
        credentials: &[StoredPasskey],
    ) -> Result<VerifiedPasskey, AppError>;
}

#[derive(Serialize)]
pub struct PasskeyOptions {
    pub challenge_id: Uuid,
    pub public_key: Value,
}

#[derive(Deserialize)]
pub struct PasskeyAssertion {
    pub challenge_id: Uuid,
    pub credential: Value,
}

#[derive(Serialize, Deserialize)]
struct AuthenticationState {
    ceremony: Value,
    credentials: Vec<StoredPasskey>,
}

pub struct PasskeyService {
    credentials: Arc<dyn PasskeyCredentialRepository>,
    challenges: Arc<dyn ChallengeRepository>,
    authenticator: Arc<dyn PasskeyAuthenticator>,
    events: Arc<dyn EventSink>,
}

impl PasskeyService {
    pub fn new(
        credentials: Arc<dyn PasskeyCredentialRepository>,
        challenges: Arc<dyn ChallengeRepository>,
        authenticator: Arc<dyn PasskeyAuthenticator>,
    ) -> Self {
        Self {
            credentials,
            challenges,
            authenticator,
            events: Arc::new(NoopEventSink),
        }
    }

    #[must_use]
    pub fn with_events(mut self, events: Arc<dyn EventSink>) -> Self {
        self.events = events;
        self
    }

    fn record_change(&self, user: UserOid, action: &str) {
        self.events.emit(
            BusinessEvent::audit("account.credential.changed")
                .outcome("success")
                .attribute("change_category", EventValue::Text(action.to_owned()))
                .attribute(
                    "user_oid",
                    EventValue::Pseudonymized {
                        purpose: "user_oid",
                        value: Uuid::from(user).to_string(),
                    },
                ),
        );
    }

    pub async fn list(&self, user: UserOid) -> Result<Vec<StoredPasskey>, AppError> {
        self.credentials.list(user).await
    }

    pub async fn begin_registration(
        &self,
        user: UserOid,
        session: Uuid,
        username: &str,
    ) -> Result<PasskeyOptions, AppError> {
        let credentials = self.credentials.list(user).await?;
        let ceremony = self
            .authenticator
            .start_registration(user, username, &credentials)?;
        let challenge = new_challenge(ceremony.state);
        let id = challenge.id;
        self.challenges
            .store(registration_context(user, session), challenge)
            .await?;
        Ok(PasskeyOptions {
            challenge_id: id,
            public_key: ceremony.public_key,
        })
    }

    pub async fn finish_registration(
        &self,
        user: UserOid,
        session: Uuid,
        challenge: Uuid,
        name: &str,
        credential: Value,
    ) -> Result<(), AppError> {
        let state = self
            .challenges
            .take(registration_context(user, session), challenge)
            .await?
            .ok_or_else(invalid)?;
        let name = name.trim();
        if name.is_empty() || name.chars().count() > 100 {
            return Err(invalid());
        }
        let verified = self
            .authenticator
            .finish_registration(state.state, credential)?;
        self.credentials
            .insert(
                user,
                StoredPasskey {
                    id: Uuid::new_v4(),
                    data: PasskeyCredentialData {
                        name: name.to_owned(),
                        credential_id: verified.credential_id,
                        key: verified.key,
                    },
                },
            )
            .await?;
        self.record_change(user, "passkey_registered");
        Ok(())
    }

    pub async fn begin_authentication(
        &self,
        user: UserOid,
        login: Uuid,
    ) -> Result<PasskeyOptions, AppError> {
        let credentials = self.credentials.list(user).await?;
        if credentials.is_empty() {
            return Err(invalid());
        }
        let ceremony = self.authenticator.start_authentication(&credentials)?;
        let challenge = new_challenge(
            serde_json::to_value(AuthenticationState {
                ceremony: ceremony.state,
                credentials,
            })
            .map_err(AppError::internal)?,
        );
        let id = challenge.id;
        self.challenges
            .store(authentication_context(user, login), challenge)
            .await?;
        Ok(PasskeyOptions {
            challenge_id: id,
            public_key: ceremony.public_key,
        })
    }

    pub async fn authenticate(
        &self,
        user: UserOid,
        login: Uuid,
        assertion: &str,
    ) -> Result<(), AppError> {
        let assertion: PasskeyAssertion = serde_json::from_str(assertion).map_err(|_| invalid())?;
        let challenge = self
            .challenges
            .take(authentication_context(user, login), assertion.challenge_id)
            .await?
            .ok_or_else(invalid)?;
        let state: AuthenticationState =
            serde_json::from_value(challenge.state).map_err(AppError::internal)?;
        let result = self.authenticator.finish_authentication(
            state.ceremony,
            assertion.credential,
            &state.credentials,
        )?;
        if !result.user_verified {
            return Err(invalid());
        }
        let before = self
            .credentials
            .list(user)
            .await?
            .into_iter()
            .find(|key| key.data.credential_id == result.credential_id)
            .ok_or_else(invalid)?;
        let original = state
            .credentials
            .iter()
            .find(|key| key.id == before.id)
            .ok_or_else(invalid)?;
        // Reject a revoked key or a credential snapshot superseded by another ceremony.
        if original != &before {
            return Err(invalid());
        }
        let mut after = before.clone();
        after.data.key = result.key;
        if !self.credentials.update(user, &before, &after).await? {
            return Err(invalid());
        }
        Ok(())
    }

    pub async fn delete(&self, user: UserOid, id: Uuid) -> Result<bool, AppError> {
        let deleted = self.credentials.delete(user, id).await?;
        if deleted {
            self.record_change(user, "passkey_deleted");
        }
        Ok(deleted)
    }
}

fn registration_context(user: UserOid, session: Uuid) -> ChallengeContext {
    ChallengeContext {
        user_oid: user.0,
        binding: ChallengeBinding::Session(session),
        method: ChallengeMethod::Passkey,
        purpose: ChallengePurpose::CredentialRegistration,
    }
}

fn authentication_context(user: UserOid, login: Uuid) -> ChallengeContext {
    ChallengeContext {
        user_oid: user.0,
        binding: ChallengeBinding::Login(login),
        method: ChallengeMethod::Passkey,
        purpose: ChallengePurpose::Authentication,
    }
}

fn new_challenge(state: Value) -> AuthenticationChallenge {
    AuthenticationChallenge {
        id: Uuid::new_v4(),
        state,
        expires_at: Utc::now() + chrono::Duration::minutes(5),
    }
}

fn invalid() -> AppError {
    AppError::from_code(AuthErrorCode::InvalidCredential)
}

#[cfg(test)]
pub(super) mod tests;
