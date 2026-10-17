use crate::{
    auth::{
        challenge::ChallengeRepository,
        passkey::{
            PasskeyAuthenticator, PasskeyCeremony, PasskeyOptions, PasskeyService, StoredPasskey,
            VerifiedPasskey,
        },
    },
    error::{AppError, code::AppErrorCode as _, codes::auth::AuthErrorCode},
    user::{
        UserOid,
        credential::{MAX_PASSKEYS_PER_USER, PasskeyCredentialData},
        repository::PasskeyCredentialRepository,
    },
};
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use identity_domain::auth::challenge::{AuthenticationChallenge, ChallengeContext};
use serde_json::{Value, json};
use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};
use uuid::Uuid;

fn invalid() -> AppError {
    AppError::from_code(AuthErrorCode::InvalidCredential)
}
type Challenge = (ChallengeContext, Value, DateTime<Utc>);
#[derive(Default)]
struct MemoryRepo {
    keys: Mutex<HashMap<UserOid, Vec<StoredPasskey>>>,
    challenges: Mutex<HashMap<Uuid, Challenge>>,
}
#[async_trait]
impl PasskeyCredentialRepository for MemoryRepo {
    async fn list(&self, user: UserOid) -> Result<Vec<StoredPasskey>, AppError> {
        Ok(self
            .keys
            .lock()
            .unwrap()
            .get(&user)
            .cloned()
            .unwrap_or_default())
    }
    async fn insert(&self, user: UserOid, key: StoredPasskey) -> Result<(), AppError> {
        let mut keys = self.keys.lock().unwrap();
        if keys
            .values()
            .flatten()
            .any(|existing| existing.data.credential_id == key.data.credential_id)
        {
            return Err(invalid());
        }
        let owned = keys.entry(user).or_default();
        if owned.len() >= MAX_PASSKEYS_PER_USER {
            return Err(AppError::from_code(AuthErrorCode::PasskeyLimitReached));
        }
        owned.push(key);
        Ok(())
    }
    async fn update(
        &self,
        user: UserOid,
        before: &StoredPasskey,
        after: &StoredPasskey,
    ) -> Result<bool, AppError> {
        let mut keys = self.keys.lock().unwrap();
        let Some(key) = keys
            .get_mut(&user)
            .and_then(|keys| keys.iter_mut().find(|key| key.id == before.id))
        else {
            return Ok(false);
        };
        if key != before {
            return Ok(false);
        }
        *key = after.clone();
        Ok(true)
    }
    async fn delete(&self, user: UserOid, id: Uuid) -> Result<bool, AppError> {
        let mut keys = self.keys.lock().unwrap();
        let keys = keys.entry(user).or_default();
        let len = keys.len();
        keys.retain(|key| key.id != id);
        Ok(keys.len() != len)
    }
}
#[async_trait]
impl ChallengeRepository for MemoryRepo {
    async fn store(
        &self,
        context: ChallengeContext,
        challenge: AuthenticationChallenge,
    ) -> Result<(), AppError> {
        self.challenges.lock().unwrap().insert(
            challenge.id,
            (context, challenge.state, challenge.expires_at),
        );
        Ok(())
    }
    async fn take(
        &self,
        context: ChallengeContext,
        id: Uuid,
    ) -> Result<Option<AuthenticationChallenge>, AppError> {
        let mut challenges = self.challenges.lock().unwrap();
        Ok(
            if challenges
                .get(&id)
                .is_some_and(|item| item.0 == context && item.2 > Utc::now())
            {
                challenges.remove(&id).map(|item| AuthenticationChallenge {
                    id,
                    state: item.1,
                    expires_at: item.2,
                })
            } else {
                None
            },
        )
    }
}

struct FakeAuthenticator;
impl PasskeyAuthenticator for FakeAuthenticator {
    fn start_registration(
        &self,
        _: UserOid,
        _: &str,
        _: &[StoredPasskey],
    ) -> Result<PasskeyCeremony, AppError> {
        Ok(PasskeyCeremony {
            public_key: json!({}),
            state: Value::Null,
        })
    }
    fn finish_registration(&self, _: Value, _: Value) -> Result<VerifiedPasskey, AppError> {
        Ok(VerifiedPasskey {
            credential_id: "test-key".into(),
            key: json!({}),
            user_verified: true,
        })
    }
    fn start_authentication(&self, _: &[StoredPasskey]) -> Result<PasskeyCeremony, AppError> {
        Ok(PasskeyCeremony {
            public_key: json!({}),
            state: Value::Null,
        })
    }
    fn finish_authentication(
        &self,
        _: Value,
        credential: Value,
        _: &[StoredPasskey],
    ) -> Result<VerifiedPasskey, AppError> {
        Ok(VerifiedPasskey {
            credential_id: "test-key".into(),
            key: json!({}),
            user_verified: credential["uv"] == true,
        })
    }
}
pub(in crate::auth) async fn enrolled_passkey(
    user: UserOid,
) -> (Arc<PasskeyService>, impl Fn(&PasskeyOptions) -> String) {
    let repo = Arc::new(MemoryRepo::default());
    repo.insert(
        user,
        StoredPasskey {
            id: Uuid::new_v4(),
            data: PasskeyCredentialData {
                name: "Laptop".into(),
                credential_id: "test-key".into(),
                key: json!({}),
            },
        },
    )
    .await
    .unwrap();
    let service = Arc::new(PasskeyService::new(
        repo.clone(),
        repo,
        Arc::new(FakeAuthenticator),
    ));
    (service, |options| {
        json!({"challenge_id": options.challenge_id, "credential": {"uv": true}}).to_string()
    })
}

#[tokio::test]
async fn requires_user_verification_and_consumes_failed_assertions() {
    let user = UserOid(Uuid::new_v4());
    let login = Uuid::new_v4();
    let (service, _) = enrolled_passkey(user).await;
    let options = service.begin_authentication(user, login).await.unwrap();
    assert!(
        service
            .authenticate(
                user,
                login,
                &json!({"challenge_id":options.challenge_id,"credential":{"uv":false}}).to_string()
            )
            .await
            .is_err()
    );
    assert!(
        service
            .authenticate(
                user,
                login,
                &json!({"challenge_id":options.challenge_id,"credential":{"uv":true}}).to_string()
            )
            .await
            .is_err()
    );
}

#[tokio::test]
async fn new_options_keep_each_login_challenge_independent() {
    let user = UserOid(Uuid::new_v4());
    let login = Uuid::new_v4();
    let (service, assertion) = enrolled_passkey(user).await;
    let old = service.begin_authentication(user, login).await.unwrap();
    let latest = service.begin_authentication(user, login).await.unwrap();
    service
        .authenticate(user, login, &assertion(&old))
        .await
        .unwrap();
    service
        .authenticate(user, login, &assertion(&latest))
        .await
        .unwrap();
}

fn registration_with_keys(count: usize) -> (PasskeyService, Arc<MemoryRepo>, UserOid) {
    let user = UserOid(Uuid::new_v4());
    let repo = Arc::new(MemoryRepo::default());
    repo.keys.lock().unwrap().insert(
        user,
        (0..count)
            .map(|index| StoredPasskey {
                id: Uuid::new_v4(),
                data: PasskeyCredentialData {
                    name: format!("Key {index}"),
                    credential_id: format!("existing-{index}"),
                    key: json!({}),
                },
            })
            .collect(),
    );
    (
        PasskeyService::new(repo.clone(), repo.clone(), Arc::new(FakeAuthenticator)),
        repo,
        user,
    )
}

#[tokio::test]
async fn passkey_registration_stops_at_five_before_creating_a_challenge() {
    let (service, repo, user) = registration_with_keys(MAX_PASSKEYS_PER_USER);
    let error = service
        .begin_registration(user, Uuid::new_v4(), "owner")
        .await
        .err()
        .unwrap();
    assert_eq!(error.code(), AuthErrorCode::PasskeyLimitReached.code());
    assert!(repo.challenges.lock().unwrap().is_empty());
}

#[tokio::test]
async fn passkey_registration_allows_a_fifth_and_reopens_after_deletion() {
    let (service, repo, user) = registration_with_keys(MAX_PASSKEYS_PER_USER - 1);
    let session = Uuid::new_v4();
    let options = service
        .begin_registration(user, session, "owner")
        .await
        .unwrap();
    service
        .finish_registration(user, session, options.challenge_id, "New key", json!({}))
        .await
        .unwrap();
    assert_eq!(repo.list(user).await.unwrap().len(), MAX_PASSKEYS_PER_USER);
    assert!(
        service
            .begin_registration(user, session, "owner")
            .await
            .is_err()
    );

    let key = repo
        .list(user)
        .await
        .unwrap()
        .into_iter()
        .find(|key| key.data.name == "New key")
        .unwrap();
    assert!(service.delete(user, key.id).await.unwrap());
    assert!(
        service
            .begin_registration(user, session, "owner")
            .await
            .is_ok()
    );
}
