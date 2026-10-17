//! Real PostgreSQL tests; run against a disposable database, never a deployment.
use super::{session::SessionRepositoryImpl, user_credential::UserCredentialRepositoryImpl};
use identity_application::user::{
    CredentialType,
    model::{Argon2Options, Argon2Password, Argon2Variant, Argon2Version, Password},
    repository::UserCredentialRepository,
};
use identity_domain::auth::{
    SessionOid,
    repository::{CreateSessionInput, SessionRepository},
};
use migration::MigratorTrait;
use sea_orm::{
    ConnectionTrait, Database, DatabaseConnection, DbBackend, Statement, TransactionTrait,
};
use std::{sync::Arc, time::Duration};
use uuid::Uuid;

async fn sql(db: &DatabaseConnection, query: &str) {
    db.execute_unprepared(query).await.unwrap();
}
async fn scalar(db: &DatabaseConnection, query: &str) -> i64 {
    db.query_one_raw(Statement::from_string(
        DbBackend::Postgres,
        query.to_owned(),
    ))
    .await
    .unwrap()
    .unwrap()
    .try_get("", "n")
    .unwrap()
}
fn password(hash: &str) -> Password {
    Password::Argon2(Argon2Password {
        hash: hash.into(),
        salt: "test-salt".into(),
        options: Argon2Options {
            variant: Argon2Variant::Argon2id,
            version: Argon2Version::Argon2013,
            time_cost: 1,
            memory_cost: 8,
            parallelism: 1,
        },
    })
}
fn input(user_oid: Uuid) -> CreateSessionInput {
    CreateSessionInput {
        user_oid,
        device_name: None,
        device_type: None,
        os_name: None,
        os_version: None,
        browser_name: None,
        browser_version: None,
        user_agent: None,
        ip_address: None,
        expires_at: Some(chrono::Utc::now() + chrono::Duration::days(7)),
        acr: Some("aal1".into()),
        acr_expires_at: Some(chrono::Utc::now() + chrono::Duration::minutes(5)),
        amr: vec!["pwd".into()],
    }
}

#[tokio::test]
#[ignore = "requires IDENTITY_SECURITY_TEST_DATABASE_URL for a disposable PostgreSQL database"]
async fn postgres_password_revocation_and_audit_are_atomic() {
    let url = std::env::var("IDENTITY_SECURITY_TEST_DATABASE_URL")
        .expect("disposable database URL required");
    let db = Database::connect(&url).await.unwrap();
    migration::Migrator::up(&db, None).await.unwrap();
    let user = Uuid::new_v4();
    let credential = Uuid::new_v4();
    let keep = Uuid::new_v4();
    let old_session = Uuid::new_v4();
    let pending_login = Uuid::new_v4();
    let client = Uuid::new_v4();
    let relation = Uuid::new_v4();
    let old = password("OLD-HASH");
    let new = password("NEW-HASH");
    let repo = Arc::new(UserCredentialRepositoryImpl::new(db.clone()));
    sql(&db, &format!(r#"
        INSERT INTO "user" (oid,name,name_normalized,email,email_normalized) VALUES ('{user}','{user}','{user}','{user}@example.test','{user}@example.test');
        INSERT INTO client (oid,name,protocol) VALUES ('{client}','security-test','openid_connect');
        INSERT INTO user_credential (oid,user_id,type,data) SELECT '{credential}',id,'password','{}'::jsonb FROM "user" WHERE oid='{user}';
        INSERT INTO session (oid,user_id,status,amr,last_active_at,authenticated_at,expires_at)
          SELECT s,id,'active','["pwd"]',now(),now(),now()+interval '7 days' FROM "user",unnest(ARRAY['{keep}'::uuid,'{old_session}'::uuid]) s WHERE oid='{user}';
        INSERT INTO client_authorization (oid,client_id,type,data,expires_at)
          SELECT '{relation}',id,'device_authorization','{{"user_oid":"{user}"}}',now()+interval '1 day' FROM client WHERE oid='{client}';
        INSERT INTO client_authorization (client_id,type,data,expires_at)
          SELECT id,'access_token','{{"session_oid":"{old_session}"}}',now()+interval '1 day' FROM client WHERE oid='{client}';
        INSERT INTO client_authorization (client_id,type,data,expires_at)
          SELECT id,'refresh_token','{{"device_authorization_oid":"{relation}"}}',now()+interval '1 day' FROM client WHERE oid='{client}';
        INSERT INTO login (oid,client_id,client_authorization_id,user_id,status,expires_at)
          SELECT '{pending_login}',c.id,a.id,u.id,'identifier_verified',now()+interval '5 minutes' FROM client c,client_authorization a,"user" u
          WHERE c.oid='{client}' AND a.oid='{relation}' AND u.oid='{user}';
    "#, serde_json::to_string(&old).unwrap())).await;

    // The production completion path creates/renews sessions and consumes its login.
    let fresh_login = Uuid::new_v4();
    sql(&db, &format!(r#"INSERT INTO login (oid,client_id,client_authorization_id,user_id,status,expires_at)
        SELECT '{fresh_login}',c.id,a.id,u.id,'identifier_verified',now()+interval '5 minutes' FROM client c,client_authorization a,"user" u
        WHERE c.oid='{client}' AND a.oid='{relation}' AND u.oid='{user}'"#)).await;
    let sessions = SessionRepositoryImpl::new(db.clone());
    let established = sessions
        .complete_authentication(fresh_login, None, input(user))
        .await
        .unwrap();
    assert_eq!(established.user_oid, user);
    assert!(
        sessions
            .complete_authentication(fresh_login, None, input(user))
            .await
            .is_err()
    );

    let reauth_login = Uuid::new_v4();
    sql(&db, &format!(r#"INSERT INTO login (oid,client_id,client_authorization_id,user_id,session_id,status,expires_at)
        SELECT '{reauth_login}',c.id,a.id,u.id,s.id,'identifier_verified',now()+interval '5 minutes' FROM client c,client_authorization a,"user" u,session s
        WHERE c.oid='{client}' AND a.oid='{relation}' AND u.oid='{user}' AND s.oid='{keep}'"#)).await;
    let renewed = sessions
        .complete_authentication(reauth_login, Some(SessionOid(keep)), input(user))
        .await
        .unwrap();
    assert_eq!(renewed.oid, SessionOid(keep));
    assert!(
        repo.change_password_and_revoke(
            user.into(),
            credential.into(),
            &old,
            &new,
            Some(SessionOid(Uuid::new_v4()))
        )
        .await
        .is_err()
    );

    // A journal insertion failure aborts the business change rather than dropping its audit.
    sql(&db, &format!(r#"
      CREATE FUNCTION security_test_reject_audit() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN
        IF NEW.resource_oid='{credential}' THEN RAISE EXCEPTION 'injected audit failure'; END IF; RETURN NEW; END; $$;
      CREATE TRIGGER security_test_audit_failure BEFORE INSERT ON security_audit FOR EACH ROW EXECUTE FUNCTION security_test_reject_audit();
    "#)).await;
    assert!(
        repo.change_password_and_revoke(
            user.into(),
            credential.into(),
            &old,
            &new,
            Some(SessionOid(keep))
        )
        .await
        .is_err()
    );
    let unchanged = repo
        .find_by_user_oid_and_type(user.into(), CredentialType::Password)
        .await
        .unwrap();
    assert!(
        matches!(&unchanged[0].data, identity_application::user::CredentialData::Password(p) if serde_json::to_value(p).unwrap() == serde_json::to_value(&old).unwrap())
    );
    sql(&db, "DROP TRIGGER security_test_audit_failure ON security_audit; DROP FUNCTION security_test_reject_audit();").await;

    // A late revocation error must roll back the password AND its audit records.
    sql(&db, &format!(r#"
      CREATE FUNCTION security_test_reject_revoke() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN
        IF NEW.oid='{old_session}' AND NEW.status='revoked' THEN RAISE EXCEPTION 'injected revocation failure'; END IF; RETURN NEW; END; $$;
      CREATE TRIGGER security_test_failure BEFORE UPDATE ON session FOR EACH ROW EXECUTE FUNCTION security_test_reject_revoke();
    "#)).await;
    let audit_before = scalar(&db, "SELECT count(*)::bigint n FROM security_audit").await;
    assert!(
        repo.change_password_and_revoke(
            user.into(),
            credential.into(),
            &old,
            &new,
            Some(SessionOid(keep))
        )
        .await
        .is_err()
    );
    let stored = repo
        .find_by_user_oid_and_type(user.into(), CredentialType::Password)
        .await
        .unwrap();
    assert_eq!(
        serde_json::to_value(&stored[0].data).unwrap(),
        serde_json::to_value(identity_application::user::CredentialData::Password(
            old.clone()
        ))
        .unwrap()
    );
    assert_eq!(
        scalar(&db, "SELECT count(*)::bigint n FROM security_audit").await,
        audit_before
    );
    sql(&db, "DROP TRIGGER security_test_failure ON session; DROP FUNCTION security_test_reject_revoke();").await;

    // Queue password replacement before login completion on the same account lock.
    let blocker = db.begin().await.unwrap();
    super::shared::lock_user_credentials(&blocker, user.into())
        .await
        .unwrap();
    let change = tokio::spawn({
        let repo = repo.clone();
        let old = old.clone();
        let new = new.clone();
        async move {
            repo.change_password_and_revoke(
                user.into(),
                credential.into(),
                &old,
                &new,
                Some(SessionOid(keep)),
            )
            .await
        }
    });
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if scalar(
                &db,
                "SELECT count(*)::bigint n FROM pg_locks WHERE locktype='advisory' AND NOT granted",
            )
            .await
                > 0
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    let complete = tokio::spawn({
        let db = db.clone();
        async move {
            SessionRepositoryImpl::new(db)
                .complete_authentication(pending_login, None, input(user))
                .await
        }
    });
    blocker.commit().await.unwrap();
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(10), change)
            .await
            .unwrap()
            .unwrap()
            .unwrap(),
        2
    );
    assert!(
        tokio::time::timeout(Duration::from_secs(10), complete)
            .await
            .unwrap()
            .unwrap()
            .is_err()
    );
    assert_eq!(scalar(&db, &format!("SELECT count(*)::bigint n FROM session WHERE user_id=(SELECT id FROM \"user\" WHERE oid='{user}') AND status='active'")).await, 1);
    assert_eq!(scalar(&db, &format!("SELECT count(*)::bigint n FROM client_authorization WHERE revoked_at IS NULL AND (data->>'session_oid'='{old_session}' OR data->>'device_authorization_oid'='{relation}' OR oid='{relation}')")).await, 0);
    // Rehashing a stale credential may never resurrect the old password.
    assert!(
        repo.update_password_by_oid(credential.into(), &old, &password("STALE-REHASH"))
            .await
            .is_err()
    );
    assert!(
        repo.change_password_and_revoke(
            user.into(),
            credential.into(),
            &old,
            &new,
            Some(SessionOid(keep))
        )
        .await
        .is_err()
    );
    assert_eq!(scalar(&db, "SELECT count(*)::bigint n FROM security_audit a WHERE to_jsonb(a)::text LIKE '%OLD-HASH%'").await, 0);
    assert!(
        db.execute_unprepared("DELETE FROM security_audit")
            .await
            .is_err()
    );
    assert!(
        db.execute_unprepared("TRUNCATE security_audit")
            .await
            .is_err()
    );
    db.close().await.unwrap();
}
