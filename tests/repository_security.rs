//! PostgreSQL credential revocation and transactional audit verification.
#[path = "repository_security/client_management.rs"]
mod client_management;
mod common;
use chrono::{Duration as ChronoDuration, Utc};
use identity_application::user::{
    CredentialData, CredentialType,
    model::{Argon2Options, Argon2Password, Argon2Variant, Argon2Version, Password},
    repository::UserCredentialRepository,
};
use identity_domain::{
    auth::{
        LoginStatus, SessionOid,
        repository::{CreateSessionInput, LoginRepository, SessionRepository},
    },
    authorization::{ActorContext, HumanAuthenticationContext, RequestId},
    user::UserOid,
};
use identity_infrastructure::database::{
    audit,
    repository::{
        login::LoginRepositoryImpl, session::SessionRepositoryImpl, shared,
        user::UserRepositoryImpl, user_credential::UserCredentialRepositoryImpl,
    },
};
use sea_orm::{ConnectionTrait, DatabaseConnection, DbBackend, Statement, TransactionTrait};
use std::{sync::Arc, time::Duration};
use tokio::time;
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

struct SemanticAudit {
    action: String,
    target_type: String,
    actor_type: String,
    actor_oid: Option<Uuid>,
    request_id: Option<String>,
}

async fn latest_semantic_audit(db: &DatabaseConnection, target_oid: Uuid) -> Option<SemanticAudit> {
    let row = db
        .query_one_raw(Statement::from_sql_and_values(
            DbBackend::Postgres,
            "SELECT action,target_type,actor_type,actor_oid,request_id FROM security_audit \
             WHERE target_oid=$1 AND event_kind='semantic' ORDER BY id DESC LIMIT 1",
            [target_oid.into()],
        ))
        .await
        .unwrap()?;
    Some(SemanticAudit {
        action: row.try_get("", "action").unwrap(),
        target_type: row.try_get("", "target_type").unwrap(),
        actor_type: row.try_get("", "actor_type").unwrap(),
        actor_oid: row.try_get("", "actor_oid").unwrap(),
        request_id: row.try_get("", "request_id").unwrap(),
    })
}

async fn semantic_count_for_request(db: &DatabaseConnection, request_id: &str) -> i64 {
    db.query_one_raw(Statement::from_sql_and_values(
        DbBackend::Postgres,
        "SELECT count(*)::bigint n FROM security_audit \
         WHERE request_id=$1 AND event_kind='semantic'",
        [request_id.to_owned().into()],
    ))
    .await
    .unwrap()
    .unwrap()
    .try_get("", "n")
    .unwrap()
}

async fn semantic_count_for_target(db: &DatabaseConnection, target_oid: Uuid, action: &str) -> i64 {
    db.query_one_raw(Statement::from_sql_and_values(
        DbBackend::Postgres,
        "SELECT count(*)::bigint n FROM security_audit \
         WHERE target_oid=$1 AND action=$2 AND event_kind='semantic'",
        [target_oid.into(), action.to_owned().into()],
    ))
    .await
    .unwrap()
    .unwrap()
    .try_get("", "n")
    .unwrap()
}

async fn assert_latest_action(
    db: &DatabaseConnection,
    target_oid: Uuid,
    target_type: &str,
    action: &str,
) {
    let audit = latest_semantic_audit(db, target_oid)
        .await
        .expect("semantic audit fact");
    assert_eq!(audit.action, action);
    assert_eq!(audit.target_type, target_type);
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
        expires_at: Some(Utc::now() + ChronoDuration::days(7)),
        acr: Some("aal1".into()),
        acr_expires_at: Some(Utc::now() + ChronoDuration::minutes(5)),
        amr: vec!["pwd".into()],
    }
}

#[tokio::test]
#[ignore = "requires explicitly configured PostgreSQL test database"]
async fn postgres_password_revocation_and_audit_are_atomic() {
    common::isolated(|db| async move {
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
    let complete_audit = latest_semantic_audit(&db, Uuid::from(established.oid))
        .await
        .expect("complete_login semantic fact");
    assert_eq!(complete_audit.action, "session.complete_login");
    assert_eq!(complete_audit.target_type, "session");
    assert_eq!(complete_audit.actor_type, "unknown");
    assert_eq!(complete_audit.actor_oid, None);
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

    // Direct repository paths record their own semantic facts.
    let direct = sessions.create(input(user)).await.unwrap();
    let created_audit = latest_semantic_audit(&db, Uuid::from(direct.oid))
        .await
        .expect("session.created semantic fact");
    assert_eq!(created_audit.action, "session.created");
    assert_eq!(created_audit.target_type, "session");

    let reauth_request_id = format!("reauth-{}", Uuid::from(direct.oid));
    let actor = ActorContext::for_user(
        UserOid(user),
        HumanAuthenticationContext::aal1(None),
        RequestId::new(reauth_request_id.clone()).unwrap(),
        None,
    );
    let reauthenticated = audit::with_actor(
        actor,
        sessions.reauthenticate_by_oid(
            direct.oid,
            user,
            "aal2",
            Utc::now() + ChronoDuration::hours(1),
            &["pwd".to_owned()],
        ),
    )
    .await
    .unwrap();
    assert_eq!(reauthenticated.oid, direct.oid);
    let reauth_audit = latest_semantic_audit(&db, Uuid::from(direct.oid))
        .await
        .expect("session.reauthenticate_by_oid semantic fact");
    assert_eq!(reauth_audit.action, "session.reauthenticate_by_oid");
    assert_eq!(reauth_audit.target_type, "session");
    assert_eq!(reauth_audit.actor_type, "user");
    assert_eq!(reauth_audit.actor_oid, Some(user));
    assert_eq!(
        reauth_audit.request_id.as_deref(),
        Some(reauth_request_id.as_str())
    );

    let revoked = sessions
        .revoke_by_oid(direct.oid, Utc::now())
        .await
        .unwrap();
    assert!(revoked.is_some());
    let revoke_audit = latest_semantic_audit(&db, Uuid::from(direct.oid))
        .await
        .expect("session.revoke_by_oid semantic fact");
    assert_eq!(revoke_audit.action, "session.revoke_by_oid");
    assert_eq!(revoke_audit.target_type, "session");
    // Re-revoking the same session is a no-op for the journal.
    assert!(
        sessions
            .revoke_by_oid(direct.oid, Utc::now())
            .await
            .unwrap()
            .is_some()
    );
    assert_eq!(
        semantic_count_for_target(&db, Uuid::from(direct.oid), "session.revoke_by_oid").await,
        1
    );

    // Direct login transitions record their own semantic facts without creating sessions.
    let logins = LoginRepositoryImpl::new(db.clone());
    let login = logins.create_pending(client, relation, None).await.unwrap();
    assert_latest_action(&db, login.oid, "login", "login.created").await;

    logins.bind_user(login.oid, user).await.unwrap();
    assert_latest_action(&db, login.oid, "login", "login.identifier_verified").await;

    logins
        .update_status(login.oid, LoginStatus::MFA_REQUIRED, None, None)
        .await
        .unwrap();
    assert_latest_action(&db, login.oid, "login", "login.mfa_required").await;

    assert_eq!(
        logins
            .increment_failed_attempts(login.oid, None)
            .await
            .unwrap(),
        1
    );
    assert_latest_action(&db, login.oid, "login", "login.failed_attempt").await;

    logins.reset_failed_attempts(login.oid).await.unwrap();
    assert_latest_action(&db, login.oid, "login", "login.failed_attempts_reset").await;

    logins.reset_identity(login.oid).await.unwrap();
    assert_latest_action(&db, login.oid, "login", "login.identity_reset").await;

    logins
        .bind_session(login.oid, SessionOid(keep))
        .await
        .unwrap();
    assert_latest_action(&db, login.oid, "login", "login.session_bound").await;

    let second = logins.create_pending(client, relation, None).await.unwrap();
    logins.bind_user(second.oid, user).await.unwrap();
    logins
        .update_status(
            second.oid,
            LoginStatus::AUTHENTICATED,
            Some(SessionOid(keep)),
            Some("aal1"),
        )
        .await
        .unwrap();
    assert_latest_action(&db, second.oid, "login", "login.authenticated").await;

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
    let audit_failure_request = format!("audit-fail-{credential}");
    sql(
        &db,
        &format!(
            r#"
      ALTER TABLE security_audit ADD CONSTRAINT security_test_audit_failure
        CHECK (request_id IS DISTINCT FROM '{audit_failure_request}') NOT VALID;
    "#
        ),
    )
    .await;
    let actor = ActorContext::for_user(
        UserOid(user),
        HumanAuthenticationContext::aal1(None),
        RequestId::new(audit_failure_request.clone()).unwrap(),
        None,
    );
    let audit_failed = audit::with_actor(
        actor,
        repo.change_password_and_revoke(
            user.into(),
            credential.into(),
            &old,
            &new,
            Some(SessionOid(keep)),
        ),
    )
    .await;
    assert!(audit_failed.is_err());
    assert_eq!(
        semantic_count_for_request(&db, &audit_failure_request).await,
        0
    );
    let unchanged = repo
        .find_by_user_oid_and_type(user.into(), CredentialType::Password)
        .await
        .unwrap();
    assert!(
        matches!(&unchanged[0].data, CredentialData::Password(p) if serde_json::to_value(p).unwrap() == serde_json::to_value(&old).unwrap())
    );
    sql(
        &db,
        "ALTER TABLE security_audit DROP CONSTRAINT security_test_audit_failure",
    )
    .await;

    // A late revocation error must roll back the password AND its audit records.
    sql(
        &db,
        &format!(
            r#"
      ALTER TABLE session ADD CONSTRAINT security_test_failure
        CHECK (oid <> '{old_session}'::uuid OR status <> 'revoked') NOT VALID;
    "#
        ),
    )
    .await;
    let late_failure_request = format!("late-fail-{credential}");
    let actor = ActorContext::for_user(
        UserOid(user),
        HumanAuthenticationContext::aal1(None),
        RequestId::new(late_failure_request.clone()).unwrap(),
        None,
    );
    let late_failed = audit::with_actor(
        actor,
        repo.change_password_and_revoke(
            user.into(),
            credential.into(),
            &old,
            &new,
            Some(SessionOid(keep)),
        ),
    )
    .await;
    assert!(late_failed.is_err());
    let stored = repo
        .find_by_user_oid_and_type(user.into(), CredentialType::Password)
        .await
        .unwrap();
    assert_eq!(
        serde_json::to_value(&stored[0].data).unwrap(),
        serde_json::to_value(CredentialData::Password(
            old.clone()
        ))
        .unwrap()
    );
    assert_eq!(
        semantic_count_for_request(&db, &late_failure_request).await,
        0
    );
    sql(
        &db,
        "ALTER TABLE session DROP CONSTRAINT security_test_failure",
    )
    .await;

    // Queue password replacement before login completion on the same account lock.
    let blocker = db.begin().await.unwrap();
    shared::lock_user_credentials(&blocker, user.into())
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
    time::timeout(Duration::from_secs(5), async {
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
            time::sleep(Duration::from_millis(10)).await;
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
        time::timeout(Duration::from_secs(10), change)
            .await
            .unwrap()
            .unwrap()
            .unwrap(),
        2
    );
    assert!(
        time::timeout(Duration::from_secs(10), complete)
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
    }).await;
}

#[tokio::test]
#[ignore = "requires explicitly configured PostgreSQL test database"]
async fn profile_audit_survives_dropped_events_and_rolls_back_with_the_write() {
    use identity_application::auth::account::AccountService;
    use identity_domain::{
        authorization::{ActorContext, HumanAuthenticationContext, RequestId},
        user::{UserOid, repository::UserProfilePatch},
    };
    use sea_orm::{ConnectionTrait, DbBackend, Statement};
    use std::sync::Arc;
    common::isolated(|db| async move {
    let oid = Uuid::new_v4();
    let name = format!("audit-{oid}");
    db.execute_raw(Statement::from_sql_and_values(DbBackend::Postgres,
        "INSERT INTO \"user\"(oid,name,name_normalized,email,email_normalized) VALUES($1,$2,$2,$3,$3)",
        [oid.into(),name.clone().into(),format!("{name}@example.test").into()])).await.unwrap();
    let service = AccountService::new(Arc::new(UserRepositoryImpl::new(db.clone()))); // NoopEventSink
    let request_id = format!("audit-{oid}");
    let actor = ActorContext::for_user(
        UserOid(oid),
        HumanAuthenticationContext::aal1(None),
        RequestId::new(request_id.clone()).unwrap(),
        None,
    );
    audit::with_actor(
        actor,
        service.update_profile(
            UserOid(oid),
            UserProfilePatch {
                nickname: Some(Some("durable".into())),
                ..Default::default()
            },
        ),
    )
    .await
    .unwrap();
    let row=db.query_one_raw(Statement::from_sql_and_values(DbBackend::Postgres,
        "SELECT actor_oid,target_oid,action FROM security_audit WHERE request_id=$1 AND event_kind='semantic'",[request_id.into()])).await.unwrap().unwrap();
    assert_eq!(row.try_get::<Uuid>("", "actor_oid").unwrap(), oid);
    assert_eq!(row.try_get::<Uuid>("", "target_oid").unwrap(), oid);
    assert_eq!(
        row.try_get::<String>("", "action").unwrap(),
        "account.update_profile"
    );
    let failed_id = format!("fail-{oid}");
    db.execute_unprepared(&format!("ALTER TABLE security_audit ADD CONSTRAINT identity_test_fail_audit CHECK (request_id IS DISTINCT FROM '{failed_id}') NOT VALID")).await.unwrap();
    let actor = ActorContext::for_user(
        UserOid(oid),
        HumanAuthenticationContext::aal1(None),
        RequestId::new(failed_id).unwrap(),
        None,
    );
    let result = audit::with_actor(
        actor,
        service.update_profile(
            UserOid(oid),
            UserProfilePatch {
                nickname: Some(Some("must-rollback".into())),
                ..Default::default()
            },
        ),
    )
    .await;
    db.execute_unprepared(
        "ALTER TABLE security_audit DROP CONSTRAINT identity_test_fail_audit",
    )
    .await
    .unwrap();
    assert!(result.is_err());
    let row = db
        .query_one_raw(Statement::from_sql_and_values(
            DbBackend::Postgres,
            "SELECT nickname FROM \"user\" WHERE oid=$1",
            [oid.into()],
        ))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(row.try_get::<String>("", "nickname").unwrap(), "durable");
    }).await;
}
