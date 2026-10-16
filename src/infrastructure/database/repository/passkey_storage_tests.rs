//! Opt-in integration test against a disposable, dedicated PostgreSQL database.
use super::{
    challenge::ChallengeRepositoryImpl, login::LoginRepositoryImpl,
    user_credential::UserCredentialRepositoryImpl,
};
use chrono::{Duration, Utc};
use identity_application::{
    auth::challenge::ChallengeRepository,
    user::{
        CredentialData, CredentialType, UserOid,
        credential::{PasskeyCredentialData, StoredPasskey},
        repository::{PasskeyCredentialRepository, UserCredentialRepository},
    },
};
use identity_domain::auth::{
    LoginStatus,
    challenge::{
        AuthenticationChallenge, ChallengeBinding, ChallengeContext, ChallengeMethod,
        ChallengePurpose,
    },
    repository::{LoginRepository, SessionRepository},
};
use migration::MigratorTrait;
use sea_orm::{ConnectionTrait, Database, DatabaseConnection, DbBackend, Statement, Value};
use serde_json::json;
use uuid::Uuid;

async fn insert_ids(db: &DatabaseConnection, sql: &str, values: Vec<Value>) -> (i64, Uuid) {
    let row = db
        .query_one_raw(Statement::from_sql_and_values(
            DbBackend::Postgres,
            sql,
            values,
        ))
        .await
        .unwrap()
        .unwrap();
    (
        row.try_get("", "id").unwrap(),
        row.try_get("", "oid").unwrap(),
    )
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
fn challenge() -> AuthenticationChallenge {
    AuthenticationChallenge {
        id: Uuid::new_v4(),
        state: json!({"server_state":"bound"}),
        expires_at: Utc::now() + Duration::minutes(5),
    }
}
fn credential(id: &str) -> StoredPasskey {
    StoredPasskey {
        id: Uuid::new_v4(),
        data: PasskeyCredentialData {
            name: "Laptop".into(),
            credential_id: id.into(),
            key: json!({"counter":0}),
        },
    }
}
async fn execute(db: &DatabaseConnection, sql: &str, values: Vec<Value>) {
    db.execute_raw(Statement::from_sql_and_values(
        DbBackend::Postgres,
        sql,
        values,
    ))
    .await
    .unwrap();
}

#[tokio::test]
#[ignore = "requires a disposable IDENTITY_PASSKEY_TEST_DATABASE_URL"]
async fn shared_challenges_and_passkey_credentials_persist_safely() {
    let url = std::env::var("IDENTITY_PASSKEY_TEST_DATABASE_URL")
        .expect("disposable database URL required");
    assert_eq!(
        url,
        "postgres://identity_passkey_test@127.0.0.1:55439/identity_passkey_test"
    );
    let db = Database::connect(&url).await.unwrap();
    migration::Migrator::fresh(&db).await.unwrap();
    let (user_id, user_oid) = insert_ids(&db, r#"INSERT INTO "user" (name,name_normalized,email,email_normalized) VALUES ('owner','OWNER','owner@example.test','OWNER@EXAMPLE.TEST') RETURNING id,oid"#, vec![]).await;
    let (_, other_oid) = insert_ids(&db, r#"INSERT INTO "user" (name,name_normalized,email,email_normalized) VALUES ('other','OTHER','other@example.test','OTHER@EXAMPLE.TEST') RETURNING id,oid"#, vec![]).await;
    let user = UserOid(user_oid);
    let other = UserOid(other_oid);
    let credentials = UserCredentialRepositoryImpl::new(db.clone());
    let key = credential("credential-one");
    credentials.insert(user, key.clone()).await.unwrap();
    assert_eq!(credentials.list(user).await.unwrap(), vec![key.clone()]);
    assert!(
        matches!(&credentials.find_by_user_oid_and_type(user, CredentialType::Passkey).await.unwrap()[0].data, CredentialData::Passkey(data) if data == &key.data)
    );
    assert!(
        credentials
            .insert(other, credential("credential-one"))
            .await
            .is_err()
    );
    let (one, two) = tokio::join!(
        credentials.insert(user, credential("concurrent-key")),
        credentials.insert(other, credential("concurrent-key"))
    );
    assert_ne!(
        one.is_ok(),
        two.is_ok(),
        "a credential cannot belong to two accounts"
    );
    let mut updated = key.clone();
    updated.data.key = json!({"counter":1});
    let (one, two) = tokio::join!(
        credentials.update(user, &key, &updated),
        credentials.update(user, &key, &updated)
    );
    assert_ne!(
        one.unwrap(),
        two.unwrap(),
        "only one counter update can win"
    );
    assert!(!credentials.delete(other, key.id).await.unwrap());
    assert!(credentials.delete(user, key.id).await.unwrap());
    assert!(
        !credentials.update(user, &updated, &key).await.unwrap(),
        "a revoked key cannot be restored"
    );
    let expired_key = credential("expired-key");
    credentials.insert(user, expired_key.clone()).await.unwrap();
    execute(
        &db,
        "UPDATE user_credential SET expires_at = now() - interval '1 second' WHERE oid = $1",
        vec![expired_key.id.into()],
    )
    .await;
    assert!(
        !credentials
            .list(user)
            .await
            .unwrap()
            .iter()
            .any(|key| key.id == expired_key.id)
    );
    assert!(
        !credentials
            .update(user, &expired_key, &expired_key)
            .await
            .unwrap()
    );

    let (_, session) = insert_ids(&db, "INSERT INTO session (user_id,status,amr,last_active_at,expires_at) VALUES ($1,'active','[]',now(),now()+interval '1 hour') RETURNING id,oid", vec![user_id.into()]).await;
    let challenges = ChallengeRepositoryImpl::new(db.clone());
    let enrollment = challenge();
    challenges
        .store(registration_context(user, session), enrollment.clone())
        .await
        .unwrap();
    assert!(
        challenges
            .take(registration_context(other, session), enrollment.id)
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        challenges
            .take(registration_context(user, Uuid::new_v4()), enrollment.id)
            .await
            .unwrap()
            .is_none()
    );
    let (one, two) = tokio::join!(
        challenges.take(registration_context(user, session), enrollment.id),
        challenges.take(registration_context(user, session), enrollment.id)
    );
    assert_ne!(
        one.unwrap().is_some(),
        two.unwrap().is_some(),
        "enrollment is consumed once"
    );
    for method in [ChallengeMethod::SmsOtp, ChallengeMethod::EmailOtp] {
        let context = ChallengeContext {
            method,
            ..registration_context(user, session)
        };
        let mut otp = challenge();
        otp.state = json!({"protected_verifier":"test-digest","attempt_limit":5});
        challenges.store(context, otp.clone()).await.unwrap();
        assert!(
            challenges
                .take(registration_context(user, session), otp.id)
                .await
                .unwrap()
                .is_none()
        );
        assert!(
            challenges
                .take(
                    ChallengeContext {
                        purpose: ChallengePurpose::Authentication,
                        ..context
                    },
                    otp.id
                )
                .await
                .unwrap()
                .is_none()
        );
        assert_eq!(
            challenges
                .take(context, otp.id)
                .await
                .unwrap()
                .unwrap()
                .state,
            otp.state
        );
        assert!(challenges.take(context, otp.id).await.unwrap().is_none());
    }
    let old = challenge();
    let new = challenge();
    challenges
        .store(registration_context(user, session), old.clone())
        .await
        .unwrap();
    challenges
        .store(registration_context(user, session), new.clone())
        .await
        .unwrap();
    assert!(
        challenges
            .take(registration_context(user, session), old.id)
            .await
            .unwrap()
            .is_some()
    );
    assert!(
        challenges
            .take(registration_context(user, session), new.id)
            .await
            .unwrap()
            .is_some()
    );
    let mut expired = challenge();
    expired.expires_at = Utc::now() - Duration::seconds(1);
    challenges
        .store(registration_context(user, session), expired.clone())
        .await
        .unwrap();
    assert!(
        challenges
            .take(registration_context(user, session), expired.id)
            .await
            .unwrap()
            .is_none()
    );
    let pending = challenge();
    challenges
        .store(registration_context(user, session), pending.clone())
        .await
        .unwrap();
    let expired_rows = db
        .query_one_raw(Statement::from_sql_and_values(
            DbBackend::Postgres,
            "SELECT count(*) AS count FROM authentication_challenge WHERE oid = $1",
            [expired.id.into()],
        ))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        expired_rows.try_get::<i64>("", "count").unwrap(),
        0,
        "writes prune expired state"
    );
    super::session::SessionRepositoryImpl::new(db.clone())
        .revoke_by_oid(identity_domain::auth::SessionOid(session), Utc::now())
        .await
        .unwrap()
        .unwrap();
    assert!(
        challenges
            .take(registration_context(user, session), pending.id)
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        challenges
            .store(registration_context(user, session), challenge())
            .await
            .is_err()
    );

    let (client_id, client_oid) = insert_ids(
        &db,
        "INSERT INTO client (protocol,name) VALUES ('openid_connect','test') RETURNING id,oid",
        vec![],
    )
    .await;
    let (_, authorization_oid) = insert_ids(&db, "INSERT INTO client_authorization (client_id,type,data,expires_at) VALUES ($1,'authorization_request','{}',now()+interval '1 hour') RETURNING id,oid", vec![client_id.into()]).await;
    let logins = LoginRepositoryImpl::new(db.clone());
    let login = logins
        .create_pending(client_oid, authorization_oid, Some("aal2"))
        .await
        .unwrap();
    assert!(
        challenges
            .store(authentication_context(user, login.oid), challenge())
            .await
            .is_err(),
        "identifier must be verified first"
    );
    logins.bind_user(login.oid, user_oid).await.unwrap();
    assert!(
        challenges
            .store(authentication_context(other, login.oid), challenge())
            .await
            .is_err()
    );
    let old = challenge();
    let new = challenge();
    challenges
        .store(authentication_context(user, login.oid), old.clone())
        .await
        .unwrap();
    challenges
        .store(authentication_context(user, login.oid), new.clone())
        .await
        .unwrap();
    assert!(
        challenges
            .take(authentication_context(user, login.oid), old.id)
            .await
            .unwrap()
            .is_some()
    );
    assert!(
        challenges
            .take(authentication_context(other, login.oid), new.id)
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        challenges
            .take(authentication_context(user, Uuid::new_v4()), new.id)
            .await
            .unwrap()
            .is_none()
    );
    logins.reset_failed_attempts(login.oid).await.unwrap();
    let (one, two) = tokio::join!(
        challenges.take(authentication_context(user, login.oid), new.id),
        challenges.take(authentication_context(user, login.oid), new.id)
    );
    let one = one.unwrap();
    let two = two.unwrap();
    assert_ne!(
        one.is_some(),
        two.is_some(),
        "login assertion is consumed once"
    );
    assert_eq!(one.or(two).unwrap().state, new.state);
    challenges
        .store(authentication_context(user, login.oid), expired.clone())
        .await
        .unwrap();
    assert!(
        challenges
            .take(authentication_context(user, login.oid), expired.id)
            .await
            .unwrap()
            .is_none()
    );
    let pending = challenge();
    challenges
        .store(authentication_context(user, login.oid), pending.clone())
        .await
        .unwrap();
    logins
        .update_status(login.oid, LoginStatus::MFA_REQUIRED, None, None)
        .await
        .unwrap();
    assert!(
        challenges
            .take(authentication_context(user, login.oid), pending.id)
            .await
            .unwrap()
            .is_none(),
        "password completion clears old options"
    );
    let pending = challenge();
    challenges
        .store(authentication_context(user, login.oid), pending.clone())
        .await
        .unwrap();
    logins.reset_identity(login.oid).await.unwrap();
    assert!(
        challenges
            .take(authentication_context(user, login.oid), pending.id)
            .await
            .unwrap()
            .is_none()
    );
    logins.bind_user(login.oid, user_oid).await.unwrap();
    assert!(
        challenges
            .take(authentication_context(user, login.oid), pending.id)
            .await
            .unwrap()
            .is_none()
    );
    challenges
        .store(authentication_context(user, login.oid), pending.clone())
        .await
        .unwrap();
    execute(
        &db,
        "UPDATE login SET expires_at=now()-interval '1 second' WHERE oid=$1",
        vec![login.oid.into()],
    )
    .await;
    assert!(
        challenges
            .take(authentication_context(user, login.oid), pending.id)
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        challenges
            .store(authentication_context(user, login.oid), challenge())
            .await
            .is_err()
    );

    // Complete genuine WebAuthn ceremonies through the application service and
    // the actual credential/challenge repositories, without port fakes.
    let (signer_user_id, signer_user_oid) = insert_ids(&db, r#"INSERT INTO "user" (name,name_normalized,email,email_normalized) VALUES ('signer','SIGNER','signer@example.test','SIGNER@EXAMPLE.TEST') RETURNING id,oid"#, vec![]).await;
    let signer_user = UserOid(signer_user_oid);
    let (_, signer_session) = insert_ids(&db, "INSERT INTO session (user_id,status,amr,last_active_at,expires_at) VALUES ($1,'active','[]',now(),now()+interval '1 hour') RETURNING id,oid", vec![signer_user_id.into()]).await;
    let settings = identity_application::setting::SettingsSnapshot::default()
        .with::<identity_application::setting::LoginDomainSetting>(Some(
        "https://login.example.com".to_owned(),
    ));
    let service = identity_application::auth::passkey::PasskeyService::new(
        std::sync::Arc::new(UserCredentialRepositoryImpl::new(db.clone())),
        std::sync::Arc::new(ChallengeRepositoryImpl::new(db.clone())),
        std::sync::Arc::new(crate::auth::passkey::WebAuthnAuthenticator::new(
            std::sync::Arc::new(settings),
        )),
    );
    let authenticator = crate::auth::passkey::tests::Authenticator::new();
    let enrollment = service
        .begin_registration(signer_user, signer_session, "signer@example.test")
        .await
        .unwrap();
    service
        .finish_registration(
            signer_user,
            signer_session,
            enrollment.challenge_id,
            "Real signed key",
            authenticator.registration(&enrollment),
        )
        .await
        .unwrap();
    let signed_login = logins
        .create_pending(client_oid, authorization_oid, Some("aal2"))
        .await
        .unwrap();
    logins
        .bind_user(signed_login.oid, signer_user_oid)
        .await
        .unwrap();
    let options = service
        .begin_authentication(signer_user, signed_login.oid)
        .await
        .unwrap();
    let assertion = authenticator.assertion(&options, "https://login.example.com", true, 1);
    service
        .authenticate(signer_user, signed_login.oid, &assertion)
        .await
        .unwrap();
    assert!(
        service
            .authenticate(signer_user, signed_login.oid, &assertion)
            .await
            .is_err()
    );
    let stored = credentials
        .find_by_user_oid_and_type(signer_user, CredentialType::Passkey)
        .await
        .unwrap();
    assert_eq!(stored.len(), 1);
    assert!(
        matches!(&stored[0].data, CredentialData::Passkey(data) if data.name == "Real signed key")
    );

    let tables = db.query_one_raw(Statement::from_string(DbBackend::Postgres, "SELECT to_regclass('passkey') IS NULL AND to_regclass('passkey_challenge') IS NULL AS absent")).await.unwrap().unwrap();
    assert!(tables.try_get::<bool>("", "absent").unwrap());
    let shared = db
        .query_one_raw(Statement::from_string(
            DbBackend::Postgres,
            "SELECT to_regclass('authentication_challenge') IS NOT NULL AS present",
        ))
        .await
        .unwrap()
        .unwrap();
    assert!(shared.try_get::<bool>("", "present").unwrap());
    let fields = db.query_one_raw(Statement::from_string(DbBackend::Postgres,
        "SELECT count(*) AS count FROM information_schema.columns WHERE table_schema='public' AND ((table_name='login' AND column_name='authentication_challenge') OR (table_name='session' AND column_name='registration_challenge'))")).await.unwrap().unwrap();
    assert_eq!(fields.try_get::<i64>("", "count").unwrap(), 0);
    assert!(db.execute_raw(Statement::from_sql_and_values(DbBackend::Postgres,
        "INSERT INTO authentication_challenge (user_id,method,purpose,state,expires_at) VALUES ($1,'email_otp','authentication','{}',now()+interval '1 minute')", [user_id.into()])).await.is_err(), "an unbound challenge is invalid");
    migration::Migrator::down(&db, Some(1)).await.unwrap();
    let shared = db
        .query_one_raw(Statement::from_string(
            DbBackend::Postgres,
            "SELECT to_regclass('authentication_challenge') IS NULL AS absent",
        ))
        .await
        .unwrap()
        .unwrap();
    assert!(shared.try_get::<bool>("", "absent").unwrap());
    let fields = db.query_one_raw(Statement::from_string(DbBackend::Postgres, "SELECT count(*) AS count FROM information_schema.columns WHERE table_schema='public' AND ((table_name='login' AND column_name='authentication_challenge') OR (table_name='session' AND column_name='registration_challenge'))")).await.unwrap().unwrap();
    assert_eq!(fields.try_get::<i64>("", "count").unwrap(), 0);
    migration::Migrator::up(&db, None).await.unwrap();
}
