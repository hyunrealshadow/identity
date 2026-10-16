use async_trait::async_trait;
use chrono::{DateTime, Utc};
use identity_application::{
    auth::{
        challenge::ChallengeRepository,
        passkey::{PasskeyOptions, PasskeyService, StoredPasskey},
    },
    error::{AppError, codes::auth::AuthErrorCode},
    user::{UserOid, repository::PasskeyCredentialRepository},
};
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
        keys.entry(user).or_default().push(key);
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

use super::WebAuthnAuthenticator;
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use identity_application::setting::{LoginDomainSetting, SettingsSnapshot};
use openssl::{
    bn::BigNumContext,
    ec::{EcGroup, EcKey, PointConversionForm},
    hash::MessageDigest,
    nid::Nid,
    pkey::{PKey, Private},
    sign::Signer,
};
use sha2::{Digest, Sha256};
// A software ES256 authenticator produces genuine attestation and assertion bytes.
// Production verification always runs through webauthn-rs, including origin and UV.
pub(crate) struct Authenticator {
    key: PKey<Private>,
    id: Vec<u8>,
}
impl Authenticator {
    pub(crate) fn new() -> Self {
        let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
        Self {
            key: PKey::from_ec_key(EcKey::generate(&group).unwrap()).unwrap(),
            id: Uuid::new_v4().as_bytes().to_vec(),
        }
    }
    fn client_data(options: &PasskeyOptions, kind: &str, origin: &str) -> Vec<u8> {
        serde_json::to_vec(&json!({"type": kind, "challenge": options.public_key["challenge"], "origin": origin, "crossOrigin": false})).unwrap()
    }
    fn authenticator_data(&self, flags: u8, counter: u32) -> Vec<u8> {
        let mut bytes = Sha256::digest(b"login.example.com").to_vec();
        bytes.push(flags);
        bytes.extend(counter.to_be_bytes());
        bytes
    }
    pub(crate) fn registration(&self, options: &PasskeyOptions) -> Value {
        let ec = self.key.ec_key().unwrap();
        let point = ec
            .public_key()
            .to_bytes(
                ec.group(),
                PointConversionForm::UNCOMPRESSED,
                &mut BigNumContext::new().unwrap(),
            )
            .unwrap();
        let mut cose = vec![0xa5, 0x01, 0x02, 0x03, 0x26, 0x20, 0x01, 0x21];
        cbor_bytes(&mut cose, &point[1..33]);
        cose.push(0x22);
        cbor_bytes(&mut cose, &point[33..65]);
        let mut auth = self.authenticator_data(0x45, 0);
        auth.extend([0; 16]);
        auth.extend((self.id.len() as u16).to_be_bytes());
        auth.extend(&self.id);
        auth.extend(cose);
        let mut attestation = vec![
            0xa3, 0x63, b'f', b'm', b't', 0x64, b'n', b'o', b'n', b'e', 0x67,
        ];
        attestation.extend(b"attStmt");
        attestation.push(0xa0);
        attestation.push(0x68);
        attestation.extend(b"authData");
        cbor_bytes(&mut attestation, &auth);
        json!({"id": URL_SAFE_NO_PAD.encode(&self.id), "rawId": URL_SAFE_NO_PAD.encode(&self.id), "type": "public-key", "clientExtensionResults": {}, "response": {"clientDataJSON": URL_SAFE_NO_PAD.encode(Self::client_data(options, "webauthn.create", "https://login.example.com")), "attestationObject": URL_SAFE_NO_PAD.encode(attestation), "transports": ["internal"]}})
    }
    pub(crate) fn assertion(
        &self,
        options: &PasskeyOptions,
        origin: &str,
        uv: bool,
        counter: u32,
    ) -> String {
        let client = Self::client_data(options, "webauthn.get", origin);
        let auth = self.authenticator_data(if uv { 0x05 } else { 0x01 }, counter);
        let mut signer = Signer::new(MessageDigest::sha256(), &self.key).unwrap();
        signer.update(&auth).unwrap();
        signer.update(&Sha256::digest(&client)).unwrap();
        let signature = signer.sign_to_vec().unwrap();
        json!({"challenge_id": options.challenge_id, "credential": {"id": URL_SAFE_NO_PAD.encode(&self.id), "rawId": URL_SAFE_NO_PAD.encode(&self.id), "type": "public-key", "clientExtensionResults": {}, "response": {"clientDataJSON": URL_SAFE_NO_PAD.encode(client), "authenticatorData": URL_SAFE_NO_PAD.encode(auth), "signature": URL_SAFE_NO_PAD.encode(signature), "userHandle": null}}}).to_string()
    }
}
fn cbor_bytes(out: &mut Vec<u8>, bytes: &[u8]) {
    if bytes.len() < 24 {
        out.push(0x40 | bytes.len() as u8);
    } else if bytes.len() <= 255 {
        out.extend([0x58, bytes.len() as u8]);
    } else {
        out.push(0x59);
        out.extend((bytes.len() as u16).to_be_bytes());
    }
    out.extend(bytes);
}

fn fixture() -> (
    PasskeyService,
    Arc<MemoryRepo>,
    UserOid,
    Uuid,
    Authenticator,
) {
    let repo = Arc::new(MemoryRepo::default());
    let settings = SettingsSnapshot::default()
        .with::<LoginDomainSetting>(Some("https://login.example.com".to_owned()));
    (
        PasskeyService::new(
            repo.clone(),
            repo.clone(),
            Arc::new(WebAuthnAuthenticator::new(Arc::new(settings))),
        ),
        repo,
        UserOid(Uuid::new_v4()),
        Uuid::new_v4(),
        Authenticator::new(),
    )
}

#[tokio::test]
async fn concurrent_ceremonies_cannot_accept_a_stale_counter_snapshot() {
    let (service, _, user, session, authenticator) = fixture();
    let registration = service
        .begin_registration(user, session, "person@example.com")
        .await
        .unwrap();
    service
        .finish_registration(
            user,
            session,
            registration.challenge_id,
            "Laptop",
            authenticator.registration(&registration),
        )
        .await
        .unwrap();
    let first_login = Uuid::new_v4();
    let second_login = Uuid::new_v4();
    let first = service
        .begin_authentication(user, first_login)
        .await
        .unwrap();
    let second = service
        .begin_authentication(user, second_login)
        .await
        .unwrap();
    service
        .authenticate(
            user,
            first_login,
            &authenticator.assertion(&first, "https://login.example.com", true, 2),
        )
        .await
        .unwrap();
    assert!(
        service
            .authenticate(
                user,
                second_login,
                &authenticator.assertion(&second, "https://login.example.com", true, 1)
            )
            .await
            .is_err()
    );
}

#[tokio::test]
async fn passkeys_without_signature_counters_can_authenticate_repeatedly() {
    let (service, _, user, session, authenticator) = fixture();
    let registration = service
        .begin_registration(user, session, "person@example.com")
        .await
        .unwrap();
    service
        .finish_registration(
            user,
            session,
            registration.challenge_id,
            "Synced passkey",
            authenticator.registration(&registration),
        )
        .await
        .unwrap();
    let login = Uuid::new_v4();
    for _ in 0..2 {
        let options = service.begin_authentication(user, login).await.unwrap();
        service
            .authenticate(
                user,
                login,
                &authenticator.assertion(&options, "https://login.example.com", true, 0),
            )
            .await
            .unwrap();
    }
}

#[tokio::test]
async fn registration_and_signed_login_are_bound_and_single_use() {
    let (service, _, user, session, authenticator) = fixture();
    let registration = service
        .begin_registration(user, session, "person@example.com")
        .await
        .unwrap();
    let credential = authenticator.registration(&registration);
    assert!(
        service
            .finish_registration(
                user,
                Uuid::new_v4(),
                registration.challenge_id,
                "Laptop",
                credential.clone()
            )
            .await
            .is_err()
    );
    service
        .finish_registration(
            user,
            session,
            registration.challenge_id,
            "Laptop",
            credential.clone(),
        )
        .await
        .unwrap();
    assert!(
        service
            .finish_registration(
                user,
                session,
                registration.challenge_id,
                "Laptop",
                credential
            )
            .await
            .is_err()
    );
    let login = Uuid::new_v4();
    let options = service.begin_authentication(user, login).await.unwrap();
    assert_eq!(
        options.public_key["allowCredentials"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
    let assertion = authenticator.assertion(&options, "https://login.example.com", true, 1);
    assert!(
        service
            .authenticate(UserOid(Uuid::new_v4()), login, &assertion)
            .await
            .is_err()
    );
    assert!(
        service
            .authenticate(user, Uuid::new_v4(), &assertion)
            .await
            .is_err()
    );
    service.authenticate(user, login, &assertion).await.unwrap();
    assert!(service.authenticate(user, login, &assertion).await.is_err());
    let stored = service.list(user).await.unwrap().pop().unwrap();
    assert!(
        !service
            .delete(UserOid(Uuid::new_v4()), stored.id)
            .await
            .unwrap()
    );
    assert_eq!(service.list(user).await.unwrap().len(), 1);
    let options = service.begin_authentication(user, login).await.unwrap();
    service.delete(user, stored.id).await.unwrap();
    assert!(
        service
            .authenticate(
                user,
                login,
                &authenticator.assertion(&options, "https://login.example.com", true, 2)
            )
            .await
            .is_err()
    );
    assert!(service.begin_authentication(user, login).await.is_err());
}

#[tokio::test]
async fn rejects_origin_uv_signature_counter_and_expired_challenges() {
    let (service, repo, user, session, authenticator) = fixture();
    let options = service
        .begin_registration(user, session, "person@example.com")
        .await
        .unwrap();
    service
        .finish_registration(
            user,
            session,
            options.challenge_id,
            "Laptop",
            authenticator.registration(&options),
        )
        .await
        .unwrap();
    let login = Uuid::new_v4();
    for (origin, uv) in [
        ("https://evil.example.com", true),
        ("https://login.example.com", false),
    ] {
        let options = service.begin_authentication(user, login).await.unwrap();
        assert!(
            service
                .authenticate(
                    user,
                    login,
                    &authenticator.assertion(&options, origin, uv, 1)
                )
                .await
                .is_err()
        );
    }
    let options = service.begin_authentication(user, login).await.unwrap();
    let mut assertion: Value = serde_json::from_str(&authenticator.assertion(
        &options,
        "https://login.example.com",
        true,
        1,
    ))
    .unwrap();
    assertion["credential"]["response"]["signature"] = json!(URL_SAFE_NO_PAD.encode([0_u8; 64]));
    assert!(
        service
            .authenticate(user, login, &assertion.to_string())
            .await
            .is_err()
    );
    let options = service.begin_authentication(user, login).await.unwrap();
    service
        .authenticate(
            user,
            login,
            &authenticator.assertion(&options, "https://login.example.com", true, 2),
        )
        .await
        .unwrap();
    let options = service.begin_authentication(user, login).await.unwrap();
    assert!(
        service
            .authenticate(
                user,
                login,
                &authenticator.assertion(&options, "https://login.example.com", true, 1)
            )
            .await
            .is_err()
    );
    let options = service.begin_authentication(user, login).await.unwrap();
    repo.challenges
        .lock()
        .unwrap()
        .get_mut(&options.challenge_id)
        .unwrap()
        .2 = Utc::now() - chrono::Duration::seconds(1);
    assert!(
        service
            .authenticate(
                user,
                login,
                &authenticator.assertion(&options, "https://login.example.com", true, 3)
            )
            .await
            .is_err()
    );
}
