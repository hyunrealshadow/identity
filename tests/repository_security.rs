//! PostgreSQL credential revocation and transactional audit verification.
#[path = "repository_security/client_management.rs"]
mod client_management;
mod common;
#[path = "repository_security/email_verification.rs"]
mod email_verification;
#[path = "repository_security/instance_management.rs"]
mod instance_management;
#[path = "repository_security/onboarding.rs"]
mod onboarding;
use chrono::{Duration as ChronoDuration, Utc};
use identity_application::user::repository::{PasswordReplacement, PasswordReplacementKind};
use identity_application::user::{
    CredentialData, CredentialType,
    model::{Argon2Options, Argon2Password, Argon2Variant, Argon2Version, Password},
    repository::UserCredentialRepository,
};
use identity_domain::{
    audit::AuditAction,
    auth::{
        AuthenticationContextClass, LoginFailureReason, LoginStatus, SessionOid,
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
    target_kind: Option<String>,
    actor_kind: String,
    actor_oid: Option<Uuid>,
    failure_reason: Option<String>,
    auth_methods: Option<serde_json::Value>,
}

async fn latest_semantic_audit(db: &DatabaseConnection, target_oid: Uuid) -> Option<SemanticAudit> {
    let row = db
        .query_one_raw(Statement::from_sql_and_values(
            DbBackend::Postgres,
            "SELECT action,target_kind,actor_kind,actor_oid,failure_reason,auth_methods FROM audit \
             WHERE target_oid=$1 ORDER BY id DESC LIMIT 1",
            [target_oid.into()],
        ))
        .await
        .unwrap()?;
    Some(SemanticAudit {
        action: row.try_get("", "action").unwrap(),
        target_kind: row.try_get("", "target_kind").unwrap(),
        actor_kind: row.try_get("", "actor_kind").unwrap(),
        actor_oid: row.try_get("", "actor_oid").unwrap(),
        failure_reason: row.try_get("", "failure_reason").unwrap(),
        auth_methods: row.try_get("", "auth_methods").unwrap(),
    })
}

async fn semantic_count_for_request(db: &DatabaseConnection, request_id: &str) -> i64 {
    db.query_one_raw(Statement::from_sql_and_values(
        DbBackend::Postgres,
        "SELECT count(*)::bigint n FROM audit WHERE request_id=$1",
        [request_id.to_owned().into()],
    ))
    .await
    .unwrap()
    .unwrap()
    .try_get("", "n")
    .unwrap()
}

async fn semantic_count_for_target(
    db: &DatabaseConnection,
    target_oid: Uuid,
    action: Option<AuditAction>,
) -> i64 {
    db.query_one_raw(Statement::from_sql_and_values(
        DbBackend::Postgres,
        "SELECT count(*)::bigint n FROM audit WHERE target_oid=$1 AND ($2::text IS NULL OR action=$2)",
        [
            target_oid.into(),
            action.map(|action| action.to_string()).into(),
        ],
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
        client_oid: None,
        device_name: None,
        device_type: None,
        os_name: None,
        os_version: None,
        browser_name: None,
        browser_version: None,
        user_agent: None,
        ip_address: None,
        expires_at: Some(Utc::now() + ChronoDuration::days(7)),
        acr: Some(AuthenticationContextClass::SingleFactor),
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
    // Completing a login records one sign-in by the user, with its methods.
    let complete_audit = latest_semantic_audit(&db, user)
        .await
        .expect("sign-in fact");
    assert_eq!(complete_audit.action, AuditAction::SignIn.to_string());
    assert_eq!(complete_audit.target_kind.as_deref(), Some("user"));
    assert_eq!(complete_audit.actor_kind, "user");
    assert_eq!(complete_audit.actor_oid, Some(user));
    assert_eq!(complete_audit.auth_methods, Some(serde_json::json!(["password"])));
    assert_eq!(semantic_count_for_target(&db, Uuid::from(established.oid), None).await, 0);
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
    let reauth_audit = latest_semantic_audit(&db, keep)
        .await
        .expect("reauthentication fact");
    assert_eq!(reauth_audit.action, AuditAction::SessionReauthenticate.to_string());
    assert_eq!(reauth_audit.actor_oid, Some(user));

    // Session bookkeeping outside sign-in is not an audit fact; revocation is.
    let direct = sessions.create(input(user)).await.unwrap();
    sessions
        .reauthenticate_by_oid(
            direct.oid,
            user,
            AuthenticationContextClass::MultiFactor,
            Utc::now() + ChronoDuration::hours(1),
            &["pwd".to_owned()],
        )
        .await
        .unwrap();
    assert_eq!(semantic_count_for_target(&db, Uuid::from(direct.oid), None).await, 0);

    let revoked = sessions
        .revoke_by_oid(direct.oid, Utc::now(), None)
        .await
        .unwrap();
    assert!(revoked.is_some());
    let revoke_audit = latest_semantic_audit(&db, Uuid::from(direct.oid))
        .await
        .expect("session revocation fact");
    assert_eq!(revoke_audit.action, AuditAction::SessionRevoke.to_string());
    assert_eq!(revoke_audit.target_kind.as_deref(), Some("session"));
    // Without an authenticated request the session owner signed out.
    assert_eq!(revoke_audit.actor_kind, "user");
    assert_eq!(revoke_audit.actor_oid, Some(user));
    // Re-revoking the same session is a no-op for the journal.
    assert!(
        sessions
            .revoke_by_oid(direct.oid, Utc::now(), None)
            .await
            .unwrap()
            .is_some()
    );
    assert_eq!(
        semantic_count_for_target(&db, Uuid::from(direct.oid), Some(AuditAction::SessionRevoke))
            .await,
        1
    );

    // Login state transitions are protocol steps, not audit facts; only a
    // failed attempt is, as an anonymous sign-in failure against the account.
    let logins = LoginRepositoryImpl::new(db.clone());
    let login = logins.create_pending(client, relation, &[]).await.unwrap();
    logins.bind_user(login.oid, user).await.unwrap();
    logins
        .update_status(login.oid, LoginStatus::MFA_REQUIRED, None, None)
        .await
        .unwrap();
    let sign_ins_before = semantic_count_for_target(&db, user, Some(AuditAction::SignIn)).await;
    assert_eq!(
        logins
            .increment_failed_attempts(login.oid, Some(LoginFailureReason::InvalidOtp))
            .await
            .unwrap(),
        1
    );
    let failure = latest_semantic_audit(&db, user).await.expect("failed sign-in fact");
    assert_eq!(failure.action, AuditAction::SignIn.to_string());
    assert_eq!(failure.actor_kind, "anonymous");
    assert_eq!(failure.failure_reason.as_deref(), Some("invalid_otp"));
    assert_eq!(
        semantic_count_for_target(&db, user, Some(AuditAction::SignIn)).await,
        sign_ins_before + 1
    );
    logins.reset_failed_attempts(login.oid).await.unwrap();
    logins.reset_identity(login.oid).await.unwrap();
    logins
        .bind_session(login.oid, SessionOid(keep))
        .await
        .unwrap();
    assert_eq!(semantic_count_for_target(&db, login.oid, None).await, 0);

    assert!(
        repo.replace_password(
user.into(),
credential.into(),
&old,
&new,
PasswordReplacement { kind: PasswordReplacementKind::Change { keep: Some(SessionOid(Uuid::new_v4())) }, keep_history: 0 },
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
      ALTER TABLE audit ADD CONSTRAINT security_test_audit_failure
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
        repo.replace_password(
user.into(),
credential.into(),
&old,
&new,
PasswordReplacement { kind: PasswordReplacementKind::Change { keep: Some(SessionOid(keep)) }, keep_history: 0 },
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
        "ALTER TABLE audit DROP CONSTRAINT security_test_audit_failure",
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
        repo.replace_password(
user.into(),
credential.into(),
&old,
&new,
PasswordReplacement { kind: PasswordReplacementKind::Change { keep: Some(SessionOid(keep)) }, keep_history: 0 },
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
            repo.replace_password(
user.into(),
credential.into(),
&old,
&new,
PasswordReplacement { kind: PasswordReplacementKind::Change { keep: Some(SessionOid(keep)) }, keep_history: 0 },
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
        repo.replace_password(
user.into(),
credential.into(),
&old,
&new,
PasswordReplacement { kind: PasswordReplacementKind::Change { keep: Some(SessionOid(keep)) }, keep_history: 0 },
)
        .await
        .is_err()
    );
    assert_eq!(scalar(&db, "SELECT count(*)::bigint n FROM audit a WHERE to_jsonb(a)::text LIKE '%OLD-HASH%'").await, 0);
    }).await;
}

#[tokio::test]
#[ignore = "requires explicitly configured PostgreSQL test database"]
async fn profile_audit_survives_dropped_events_and_rolls_back_with_the_write() {
    use identity_application::authentication::account::AccountService;
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
        "SELECT actor_oid,target_oid,action,changes FROM audit WHERE request_id=$1",[request_id.into()])).await.unwrap().unwrap();
    assert_eq!(row.try_get::<Uuid>("", "actor_oid").unwrap(), oid);
    assert_eq!(row.try_get::<Uuid>("", "target_oid").unwrap(), oid);
    assert_eq!(
        row.try_get::<String>("", "action").unwrap(),
        AuditAction::AccountProfileUpdate.to_string()
    );
    assert_eq!(
        row.try_get::<serde_json::Value>("", "changes").unwrap(),
        serde_json::json!([{ "field": "nickname", "type": "value", "new": "durable" }])
    );
    let failed_id = format!("fail-{oid}");
    db.execute_unprepared(&format!("ALTER TABLE audit ADD CONSTRAINT identity_test_fail_audit CHECK (request_id IS DISTINCT FROM '{failed_id}') NOT VALID")).await.unwrap();
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
        "ALTER TABLE audit DROP CONSTRAINT identity_test_fail_audit",
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

#[tokio::test]
#[ignore = "requires explicitly configured PostgreSQL test database"]
async fn mfa_enrollment_login_keeps_its_registration_until_authenticated() {
    use identity_application::auth::challenge::ChallengeRepository;
    use identity_domain::auth::challenge::{
        AuthenticationChallenge, ChallengeBinding, ChallengeContext, ChallengeMethod,
        ChallengePurpose,
    };
    use identity_infrastructure::database::repository::challenge::ChallengeRepositoryImpl;

    common::isolated(|db| async move {
        let user = Uuid::new_v4();
        let client = Uuid::new_v4();
        let relation = Uuid::new_v4();
        let login = Uuid::new_v4();
        sql(&db, &format!(r#"
            INSERT INTO "user" (oid,name,name_normalized,email,email_normalized) VALUES ('{user}','{user}','{user}','{user}@example.test','{user}@example.test');
            INSERT INTO client (oid,name,protocol) VALUES ('{client}','enrollment-test','openid_connect');
            INSERT INTO client_authorization (oid,client_id,type,data,expires_at)
              SELECT '{relation}',id,'authorization_request','{{}}',now()+interval '1 day' FROM client WHERE oid='{client}';
            INSERT INTO login (oid,client_id,client_authorization_id,user_id,status,requested_acr_values,expires_at)
              SELECT '{login}',c.id,a.id,u.id,'identifier_verified','["aal2"]'::jsonb,now()+interval '5 minutes' FROM client c,client_authorization a,"user" u
              WHERE c.oid='{client}' AND a.oid='{relation}' AND u.oid='{user}';
        "#)).await;
        let logins = LoginRepositoryImpl::new(db.clone());
        let challenges = ChallengeRepositoryImpl::new(db.clone());
        let registration = ChallengeContext {
            user_oid: user,
            binding: ChallengeBinding::Login(login),
            method: ChallengeMethod::Totp,
            purpose: ChallengePurpose::CredentialRegistration,
        };
        let challenge = |token: &str| AuthenticationChallenge {
            id: Uuid::new_v4(),
            state: serde_json::json!({ "enrollment_token": token }),
            expires_at: Utc::now() + ChronoDuration::minutes(5),
        };

        logins
            .update_status(login, LoginStatus::MFA_ENROLLMENT_REQUIRED, None, None)
            .await
            .unwrap();
        assert_eq!(semantic_count_for_target(&db, login, None).await, 0);

        challenges.store(registration, challenge("first")).await.unwrap();
        let second = challenge("second");
        challenges.store(registration, second.clone()).await.unwrap();
        // Reading the pending registration does not consume it, so a reload or
        // a rejected code resumes the same secret.
        for _ in 0..2 {
            let latest = challenges.latest(registration).await.unwrap().unwrap();
            assert_eq!(latest.id, second.id);
            assert_eq!(latest.state["enrollment_token"], "second");
        }
        let passkey_registration = ChallengeContext {
            method: ChallengeMethod::Passkey,
            ..registration
        };
        assert!(challenges.latest(passkey_registration).await.unwrap().is_none());
        let other_user = ChallengeContext {
            user_oid: Uuid::new_v4(),
            ..registration
        };
        assert!(challenges.latest(other_user).await.unwrap().is_none());

        // The enrollment phase may complete authentication, which ends the
        // registration together with the login.
        let sessions = SessionRepositoryImpl::new(db.clone());
        let session = sessions
            .complete_authentication(login, None, input(user))
            .await
            .unwrap();
        logins
            .update_status(login, LoginStatus::AUTHENTICATED, Some(session.oid), Some(AuthenticationContextClass::MultiFactor))
            .await
            .unwrap();
        assert!(challenges.latest(registration).await.unwrap().is_none());
        assert_eq!(
            scalar(&db, "SELECT count(*)::bigint n FROM authentication_challenge").await,
            0
        );
    })
    .await;
}

#[tokio::test]
#[ignore = "requires explicitly configured PostgreSQL test database"]
async fn credential_enrolled_during_sign_in_keeps_that_interaction() {
    use identity_application::user::{
        OtpAlgorithm, OtpCredentialData,
        credential::{PasskeyCredentialData, StoredPasskey},
        recovery_code::RecoveryCodeCredentialData,
        repository::PasskeyCredentialRepository,
    };

    for credential in ["totp", "passkey"] {
        for request_type in ["authorization_request", "device_authorization_request"] {
            common::isolated(move |db| async move {
                let case = format!("{credential} / {request_type}");
                let user = Uuid::new_v4();
                let client = Uuid::new_v4();
                let current = Uuid::new_v4();
                let other = Uuid::new_v4();
                let enrolling = Uuid::new_v4();
                let elsewhere = Uuid::new_v4();
                let token = Uuid::new_v4();
                // Both requests reference the user the way an interaction with
                // an existing browser session (or a claimed device request) does.
                let data = |login: Uuid| {
                    format!(
                        r#"{{"interaction":{{"selected_user_oid":"{user}"}},"claimed_login_oid":"{login}"}}"#
                    )
                };
                sql(&db, &format!(r#"
                    INSERT INTO "user" (oid,name,name_normalized,email,email_normalized) VALUES ('{user}','{user}','{user}','{user}@example.test','{user}@example.test');
                    INSERT INTO client (oid,name,protocol) VALUES ('{client}','enrollment-test','openid_connect');
                    INSERT INTO client_authorization (oid,client_id,type,data,expires_at)
                      SELECT '{current}',id,'{request_type}','{}',now()+interval '1 day' FROM client WHERE oid='{client}';
                    INSERT INTO client_authorization (oid,client_id,type,data,expires_at)
                      SELECT '{other}',id,'{request_type}','{}',now()+interval '1 day' FROM client WHERE oid='{client}';
                    INSERT INTO client_authorization (oid,client_id,type,data,expires_at)
                      SELECT '{token}',id,'access_token','{{"user_oid":"{user}"}}',now()+interval '1 day' FROM client WHERE oid='{client}';
                    INSERT INTO login (oid,client_id,client_authorization_id,user_id,status,requested_acr_values,expires_at)
                      SELECT l.oid,c.id,a.id,u.id,'mfa_enrollment_required','["aal2"]'::jsonb,now()+interval '5 minutes'
                      FROM client c,"user" u,(VALUES ('{enrolling}'::uuid,'{current}'::uuid),('{elsewhere}'::uuid,'{other}'::uuid)) l(oid,request),client_authorization a
                      WHERE c.oid='{client}' AND u.oid='{user}' AND a.oid=l.request;
                "#, data(enrolling), data(elsewhere))).await;

                let repo = UserCredentialRepositoryImpl::new(db.clone());
                let recovery = vec![RecoveryCodeCredentialData { hash: "recovery".to_owned() }];
                if credential == "totp" {
                    let enabled = repo
                        .enable_totp_if_disabled(
                            UserOid(user),
                            OtpCredentialData {
                                secret: "JBSWY3DPEHPK3PXP".to_owned(),
                                digits: 6,
                                period: 30,
                                algorithm: OtpAlgorithm::Sha256,
                                last_used_counter: Some(1),
                            },
                            recovery,
                            Some(enrolling),
                        )
                        .await
                        .unwrap();
                    assert!(enabled, "{case}");
                } else {
                    PasskeyCredentialRepository::insert(
                        &repo,
                        UserOid(user),
                        StoredPasskey {
                            id: Uuid::new_v4(),
                            data: PasskeyCredentialData {
                                name: "Laptop".to_owned(),
                                credential_id: user.simple().to_string(),
                                key: serde_json::json!({}),
                            },
                        },
                        recovery,
                        Some(enrolling),
                    )
                    .await
                    .unwrap();
                }

                let withdrawn = |oid: Uuid| {
                    format!(
                        "SELECT count(*)::bigint n FROM client_authorization WHERE oid='{oid}' \
                         AND (revoked_at IS NOT NULL OR data->>'_authority_withdrawn'='true')"
                    )
                };
                // The sign-in completing with the new credential continues.
                assert_eq!(scalar(&db, &withdrawn(current)).await, 0, "{case}");
                // Everything else issued under the earlier credential set is
                // gone, including another interaction waiting on the same user.
                assert_eq!(scalar(&db, &withdrawn(other)).await, 1, "{case}");
                assert_eq!(scalar(&db, &withdrawn(token)).await, 1, "{case}");
            })
            .await;
        }
    }
}

#[tokio::test]
#[ignore = "requires explicitly configured PostgreSQL test database"]
async fn token_revocation_audits_each_token_kind_once() {
    use identity_domain::client_authorization::ClientAuthorizationRepository;
    use identity_infrastructure::database::repository::client_authorization::ClientAuthorizationRepositoryImpl;

    common::isolated(|db| async move {
        let user = Uuid::new_v4();
        let client = Uuid::new_v4();
        let access = Uuid::new_v4();
        let refresh = Uuid::new_v4();
        let family_access = Uuid::new_v4();
        sql(&db, &format!(r#"
            INSERT INTO "user" (oid,name,name_normalized,email,email_normalized) VALUES ('{user}','{user}','{user}','{user}@example.test','{user}@example.test');
            INSERT INTO client (oid,name,protocol) VALUES ('{client}','revocation-test','openid_connect');
            INSERT INTO client_authorization (oid,client_id,type,data,expires_at)
              SELECT '{refresh}',id,'refresh_token','{{"user_oid":"{user}"}}',now()+interval '1 day' FROM client WHERE oid='{client}';
            INSERT INTO client_authorization (oid,client_id,type,data,expires_at)
              SELECT o,id,'access_token','{{"user_oid":"{user}","refresh_token_oid":"{refresh}"}}',now()+interval '1 hour'
              FROM client,unnest(ARRAY['{access}'::uuid,'{family_access}'::uuid]) o WHERE oid='{client}';
        "#)).await;
        let repo = ClientAuthorizationRepositoryImpl::new(db.clone());

        // A client signing out revokes its access token, then its refresh token.
        repo.revoke_access_token_for_client(access, client, Utc::now()).await.unwrap();
        repo.revoke_refresh_grant_for_client(refresh, client, Utc::now()).await.unwrap();
        assert_eq!(semantic_count_for_target(&db, user, Some(AuditAction::AccessTokenRevoke)).await, 1);
        assert_eq!(semantic_count_for_target(&db, user, Some(AuditAction::TokenRevoke)).await, 1);
        assert_eq!(
            scalar(&db, &format!(
                "SELECT count(*)::bigint n FROM client_authorization WHERE oid='{family_access}' AND revoked_at IS NOT NULL"
            )).await,
            1,
            "revoking the refresh grant withdraws the access tokens issued from it"
        );

        // Presenting the same tokens again changes nothing and is not a new event.
        repo.revoke_access_token_for_client(access, client, Utc::now()).await.unwrap();
        repo.revoke_refresh_grant_for_client(refresh, client, Utc::now()).await.unwrap();
        assert_eq!(semantic_count_for_target(&db, user, None).await, 2);
    })
    .await;
}

#[tokio::test]
#[ignore = "requires explicitly configured PostgreSQL test database"]
async fn existing_session_sign_in_is_audited_with_its_completion() {
    use identity_domain::client_authorization::ClientAuthorizationRepository;
    use identity_infrastructure::database::repository::client_authorization::ClientAuthorizationRepositoryImpl;

    common::isolated(|db| async move {
        let user = Uuid::new_v4();
        let client = Uuid::new_v4();
        let request = Uuid::new_v4();
        sql(&db, &format!(r#"
            INSERT INTO "user" (oid,name,name_normalized,email,email_normalized) VALUES ('{user}','{user}','{user}','{user}@example.test','{user}@example.test');
            INSERT INTO client (oid,name,protocol) VALUES ('{client}','sso-test','openid_connect');
            INSERT INTO client_authorization (oid,client_id,type,data,expires_at)
              SELECT '{request}',id,'authorization_request','{{}}'::jsonb,now()+interval '10 minutes' FROM client WHERE oid='{client}';
        "#)).await;
        let repo = ClientAuthorizationRepositoryImpl::new(db.clone());

        assert!(repo
            .complete_authorization_request_with_existing_session(request, Utc::now(), user, client)
            .await
            .unwrap());
        let audit = latest_semantic_audit(&db, client).await.expect("sign-in to the client is audited");
        assert_eq!(audit.action, AuditAction::SessionReuse.to_string());
        assert_eq!(audit.target_kind.as_deref(), Some("client"));
        assert_eq!(audit.actor_kind, "user");
        assert_eq!(audit.actor_oid, Some(user));
        assert_eq!(
            scalar(&db, &format!(
                "SELECT count(*)::bigint n FROM audit WHERE client_oid='{client}' AND action='session_reuse'"
            )).await,
            1
        );

        // A request completes once; a replayed completion neither succeeds nor audits.
        assert!(!repo
            .complete_authorization_request_with_existing_session(request, Utc::now(), user, client)
            .await
            .unwrap());
        assert_eq!(semantic_count_for_target(&db, client, None).await, 1);
    })
    .await;
}

#[tokio::test]
#[ignore = "requires explicitly configured PostgreSQL test database"]
async fn scheduled_key_rotation_is_audited_as_the_system() {
    use identity_application::key::rotation::{
        KeyRotationMaterialGenerator, KeyRotationRepository,
    };
    use identity_domain::key::{KeyData, SymmetricKeyAlgorithm, SymmetricKeyData};
    use identity_infrastructure::{
        crypto::key_rotation::KeyRotationMaterialGeneratorImpl,
        database::repository::key_rotation::KeyRotationRepositoryImpl,
    };

    common::isolated(|db| async move {
        let key = Uuid::new_v4();
        let data = serde_json::to_string(&KeyData::Symmetric(SymmetricKeyData {
            key: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=".into(),
            algorithm: SymmetricKeyAlgorithm::XChaCha20Poly1305,
        }))
        .unwrap();
        sql(
            &db,
            &format!(
                "INSERT INTO key(oid,type,data,expires_at,created_at) \
             VALUES('{key}','symmetric','{data}',now()+interval '30 days',now()-interval '61 days')"
            ),
        )
        .await;
        let repo = KeyRotationRepositoryImpl::new(db.clone());
        let now = Utc::now();
        let due = repo.list_due(now).await.unwrap();
        let previous = due
            .iter()
            .find(|candidate| Uuid::from(candidate.oid) == key)
            .unwrap();
        let material = KeyRotationMaterialGeneratorImpl.generate(previous).unwrap();

        assert!(
            repo.rotate_if_due(previous.oid, material, now)
                .await
                .unwrap()
        );
        let audit = latest_semantic_audit(&db, key)
            .await
            .expect("rotation is audited");
        assert_eq!(audit.action, AuditAction::KeyRotate.to_string());
        assert_eq!(audit.actor_kind, "system");
    })
    .await;
}

#[tokio::test]
#[ignore = "requires explicitly configured PostgreSQL test database"]
async fn logout_and_client_authentication_failure_name_their_client() {
    use identity_domain::{
        auth::repository::SessionRepository, openid_connect::OpenIdConnectCredentialRepository,
    };
    use identity_infrastructure::database::repository::openid_connect_credential::OpenIdConnectCredentialRepositoryImpl;

    common::isolated(|db| async move {
        let user = Uuid::new_v4();
        let client = Uuid::new_v4();
        let session = Uuid::new_v4();
        sql(&db, &format!(r#"
            INSERT INTO "user" (oid,name,name_normalized,email,email_normalized) VALUES ('{user}','{user}','{user}','{user}@example.test','{user}@example.test');
            INSERT INTO client (oid,name,protocol) VALUES ('{client}','logout-test','openid_connect');
            INSERT INTO session (oid,user_id,status,amr,last_active_at,authenticated_at,expires_at)
              SELECT '{session}',id,'active','["pwd"]',now(),now(),now()+interval '7 days' FROM "user" WHERE oid='{user}';
        "#)).await;

        // An RP-initiated logout records the client that asked for it.
        SessionRepositoryImpl::new(db.clone())
            .revoke_by_oid(SessionOid(session), Utc::now(), Some(client))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            scalar(&db, &format!(
                "SELECT count(*)::bigint n FROM audit WHERE action='session_revoke' \
                 AND target_oid='{session}' AND client_oid='{client}' AND actor_oid='{user}'"
            )).await,
            1
        );

        // A rejected client credential is a failed, anonymous attempt on that client.
        OpenIdConnectCredentialRepositoryImpl::new(db.clone())
            .record_authentication_failure(client)
            .await
            .unwrap();
        assert_eq!(
            scalar(&db, &format!(
                "SELECT count(*)::bigint n FROM audit WHERE action='client_authenticate' \
                 AND outcome='failure' AND failure_reason='invalid_credential' \
                 AND actor_kind='anonymous' AND target_oid='{client}' AND client_oid='{client}'"
            )).await,
            1
        );
    })
    .await;
}

#[tokio::test]
#[ignore = "requires explicitly configured PostgreSQL test database"]
async fn concealed_identifier_binding_persists_without_an_account_and_resets() {
    common::isolated(|db| async move {
        let client = Uuid::new_v4();
        let relation = Uuid::new_v4();
        let user = Uuid::new_v4();
        sql(&db, &format!(r#"
            INSERT INTO "user" (oid,name,name_normalized,email,email_normalized) VALUES ('{user}','{user}','{user}','{user}@example.test','{user}@example.test');
            INSERT INTO client (oid,name,protocol) VALUES ('{client}','concealment-test','openid_connect');
            INSERT INTO client_authorization (oid,client_id,type,data,expires_at)
              SELECT '{relation}',id,'device_authorization','{{}}',now()+interval '1 day' FROM client WHERE oid='{client}';
        "#)).await;
        let logins = LoginRepositoryImpl::new(db.clone());

        // No account matched: the interaction still advances and keeps only
        // the identifier as entered.
        let unknown = logins.create_pending(client, relation, &[]).await.unwrap();
        let bound = logins
            .bind_concealed_identifier(unknown.oid, "nobody@example.test", None)
            .await
            .unwrap();
        assert_eq!(bound.status, LoginStatus::IDENTIFIER_VERIFIED);
        assert_eq!(bound.user_oid, None);
        let stored = logins.find_by_oid(unknown.oid).await.unwrap().unwrap();
        assert_eq!(stored.concealed_identifier(), Some("nobody@example.test"));
        assert_eq!(stored.user_oid, None);
        // A second binding of the same interaction is refused.
        assert!(
            logins
                .bind_concealed_identifier(unknown.oid, "other@example.test", None)
                .await
                .is_err()
        );

        // A failed password without an account is an anonymous sign-in
        // failure with no target.
        let anonymous_before = scalar(
            &db,
            "SELECT count(*)::bigint n FROM audit WHERE action='sign_in' AND target_oid IS NULL",
        )
        .await;
        logins
            .increment_failed_attempts(unknown.oid, Some(LoginFailureReason::InvalidCredential))
            .await
            .unwrap();
        assert_eq!(
            scalar(
                &db,
                "SELECT count(*)::bigint n FROM audit WHERE action='sign_in' AND target_oid IS NULL",
            )
            .await,
            anonymous_before + 1
        );

        // Switching accounts forgets the entered identifier.
        logins.reset_identity(unknown.oid).await.unwrap();
        let reset = logins.find_by_oid(unknown.oid).await.unwrap().unwrap();
        assert_eq!(reset.status, LoginStatus::CREATED);
        assert_eq!(reset.submitted_identifier, None);

        // A matched account is bound alongside the identifier.
        let known = logins.create_pending(client, relation, &[]).await.unwrap();
        logins
            .bind_concealed_identifier(known.oid, "typed-name", Some(user))
            .await
            .unwrap();
        let stored = logins.find_by_oid(known.oid).await.unwrap().unwrap();
        assert_eq!(stored.user_oid, Some(user));
        assert_eq!(stored.concealed_identifier(), Some("typed-name"));
        // Once past the identifier step, the account is no longer concealed.
        logins
            .update_status(known.oid, LoginStatus::MFA_REQUIRED, None, None)
            .await
            .unwrap();
        let advanced = logins.find_by_oid(known.oid).await.unwrap().unwrap();
        assert_eq!(advanced.concealed_identifier(), None);
    })
    .await;
}

#[tokio::test]
#[ignore = "requires explicitly configured PostgreSQL test database"]
async fn email_code_admission_is_atomic_and_independent_of_the_account() {
    use identity_application::auth::challenge::ChallengeRepository;
    use identity_domain::auth::{
        AMR_EMAIL, LOGIN_EMAIL_DELIVERY, MAX_EMAIL_CODE_SENDS,
        challenge::{
            ChallengeBinding, ChallengeContext, ChallengeMethod, ChallengePurpose,
            DeliveryChallengeAdmission, DeliveryChallengeContext, DeliveryChallengeRequest,
        },
    };
    use identity_infrastructure::database::repository::challenge::ChallengeRepositoryImpl;

    common::isolated(|db| async move {
        let client = Uuid::new_v4();
        let relation = Uuid::new_v4();
        sql(
            &db,
            &format!(
                r#"
            INSERT INTO client (oid,name,protocol) VALUES ('{client}','email-code-test','openid_connect');
            INSERT INTO client_authorization (oid,client_id,type,data,expires_at)
              SELECT '{relation}',id,'device_authorization','{{}}',now()+interval '1 day' FROM client WHERE oid='{client}';
        "#
            ),
        )
        .await;
        let logins = Arc::new(LoginRepositoryImpl::new(db.clone()));
        let challenges = Arc::new(
            ChallengeRepositoryImpl::new(db.clone())
                .with_email_queue(common::email_queue(&db).await),
        );
        // Every request carries a message; only admitted ones may queue it.
        let email = || {
            Some(identity_domain::email::OutboundEmail {
                kind: "sign_in_code",
                message: identity_domain::email::EmailMessage {
                    to_address: "nobody@example.test".to_owned(),
                    to_name: None,
                    subject: "Code".to_owned(),
                    html: "code".to_owned(),
                },
                expires_at: Utc::now() + ChronoDuration::minutes(10),
            })
        };
        let login = logins.create_pending(client, relation, &[]).await.unwrap();
        let context = DeliveryChallengeContext {
            user_oid: None,
            binding: ChallengeBinding::Login(login.oid),
            method: ChallengeMethod::EmailOtp,
            purpose: ChallengePurpose::Authentication,
        };
        let make_request =
            |now: chrono::DateTime<Utc>, code_expires_at: chrono::DateTime<Utc>| {
            DeliveryChallengeRequest {
                now,
                policy: LOGIN_EMAIL_DELIVERY,
                code_expires_at,
                required_login_status: Some(LoginStatus::IDENTIFIER_VERIFIED),
                verifier: None,
                preserve_verifier: false,
                expected_email_normalized: None,
            }
        };

        // Not yet waiting for a first factor.
        assert_eq!(
            challenges
                .admit_delivery(context, make_request(Utc::now(), Utc::now()), email())
                .await
                .unwrap(),
            DeliveryChallengeAdmission::InvalidState
        );
        // No account matched; admission behaves the same.
        logins
            .bind_concealed_identifier(login.oid, "nobody@example.test", None)
            .await
            .unwrap();

        let now = Utc::now();
        let extended = now + ChronoDuration::minutes(10);
        let attempts = (0..8).map(|_| {
            let challenges = Arc::clone(&challenges);
            let request = make_request(now, extended);
            tokio::spawn(async move { challenges.admit_delivery(context, request, email()).await.unwrap() })
        });
        let mut admitted = 0;
        for attempt in attempts {
            match attempt.await.unwrap() {
                DeliveryChallengeAdmission::Admitted { send_count, .. } => {
                    assert_eq!(send_count, 1);
                    admitted += 1;
                }
                DeliveryChallengeAdmission::TooSoon { available_at } => {
                    assert!(available_at > now);
                }
                other => panic!("unexpected admission {other:?}"),
            }
        }
        assert_eq!(admitted, 1, "concurrent sends admit exactly one");
        let status = challenges
            .delivery_status(
                ChallengeBinding::Login(login.oid),
                ChallengeMethod::EmailOtp,
                ChallengePurpose::Authentication,
            )
            .await
            .unwrap()
            .expect("delivery status recorded for concealed login");
        assert_eq!(status.send_count, 1);
        let stored = logins.find_by_oid(login.oid).await.unwrap().unwrap();
        assert!(stored.expires_at >= extended - ChronoDuration::seconds(1));

        // A user-less challenge cannot be retrieved or consumed via user-bound queries.
        let user_bound = ChallengeContext {
            user_oid: Uuid::new_v4(),
            binding: ChallengeBinding::Login(login.oid),
            method: ChallengeMethod::EmailOtp,
            purpose: ChallengePurpose::Authentication,
        };
        assert!(challenges.latest(user_bound).await.unwrap().is_none());

        // After the interval, sends continue until the limit.
        let mut later = now;
        for expected_count in 2..=MAX_EMAIL_CODE_SENDS {
            later += ChronoDuration::minutes(2);
            match challenges
                .admit_delivery(
                    context,
                    make_request(later, later + ChronoDuration::minutes(10)),
                    email(),
                )
                .await
                .unwrap()
            {
                DeliveryChallengeAdmission::Admitted { send_count, .. } => {
                    assert_eq!(send_count, expected_count);
                }
                other => panic!("expected admission, got {other:?}"),
            }
        }
        later += ChronoDuration::minutes(2);
        assert_eq!(
            challenges
                .admit_delivery(
                    context,
                    make_request(later, later + ChronoDuration::minutes(10)),
                    email(),
                )
                .await
                .unwrap(),
            DeliveryChallengeAdmission::LimitReached
        );
        // One message per admitted send: the concurrent first send queued
        // once, the refused and over-limit sends never.
        assert_eq!(
            common::queued_emails(&db).await,
            i64::from(MAX_EMAIL_CODE_SENDS)
        );

        // Satisfied AMR and unverified challenge verifiers are cleared on identity reset,
        // while the delivery rate-limit counter remains intact.
        logins
            .record_amr(login.oid, &[AMR_EMAIL.to_owned()])
            .await
            .unwrap();
        assert_eq!(
            logins.find_by_oid(login.oid).await.unwrap().unwrap().amr,
            vec![AMR_EMAIL.to_owned()]
        );
        logins.reset_identity(login.oid).await.unwrap();
        assert!(
            logins
                .find_by_oid(login.oid)
                .await
                .unwrap()
                .unwrap()
                .amr
                .is_empty()
        );
        let status = challenges
            .delivery_status(
                ChallengeBinding::Login(login.oid),
                ChallengeMethod::EmailOtp,
                ChallengePurpose::Authentication,
            )
            .await
            .unwrap()
            .expect("delivery rate-limit state kept across account switch");
        assert_eq!(status.send_count, MAX_EMAIL_CODE_SENDS);
        logins
            .bind_concealed_identifier(login.oid, "another@example.test", None)
            .await
            .unwrap();
        assert_eq!(
            challenges
                .admit_delivery(
                    context,
                    make_request(later, later + ChronoDuration::minutes(10)),
                    email(),
                )
                .await
                .unwrap(),
            DeliveryChallengeAdmission::LimitReached
        );

        // Switching away from a real bound user also voids any previously issued verifier
        // while still keeping the login's delivery cadence limit.
        let switch_user = Uuid::new_v4();
        sql(
            &db,
            &format!(
                "INSERT INTO \"user\" (oid,name,name_normalized,email,email_normalized,email_verified) \
                 VALUES ('{switch_user}','switcher','switcher','switcher@example.test','switcher@example.test',true)"
            ),
        )
        .await;
        let switch_login = logins.create_pending(client, relation, &[]).await.unwrap();
        logins
            .update_status(
                switch_login.oid,
                LoginStatus::IDENTIFIER_VERIFIED,
                Some(switch_user.into()),
                None,
            )
            .await
            .unwrap();
        let switch_now = Utc::now();
        let switch_ctx = DeliveryChallengeContext {
            user_oid: Some(switch_user.into()),
            binding: ChallengeBinding::Login(switch_login.oid),
            method: ChallengeMethod::EmailOtp,
            purpose: ChallengePurpose::Authentication,
        };
        assert!(matches!(
            challenges
                .admit_delivery(
                    switch_ctx,
                    DeliveryChallengeRequest {
                        now: switch_now,
                        policy: LOGIN_EMAIL_DELIVERY,
                        code_expires_at: switch_now + ChronoDuration::minutes(10),
                        required_login_status: Some(LoginStatus::IDENTIFIER_VERIFIED),
                        verifier: Some(serde_json::json!({ "code": "123456" })),
                        preserve_verifier: false,
                        expected_email_normalized: Some("switcher@example.test".to_owned()),
                    },
                    email(),
                )
                .await
                .unwrap(),
            DeliveryChallengeAdmission::Admitted { .. }
        ));
        logins.reset_identity(switch_login.oid).await.unwrap();
        assert!(
            challenges
                .latest(ChallengeContext {
                    user_oid: switch_user,
                    binding: ChallengeBinding::Login(switch_login.oid),
                    method: ChallengeMethod::EmailOtp,
                    purpose: ChallengePurpose::Authentication,
                })
                .await
                .unwrap()
                .is_none()
        );
        logins
            .bind_concealed_identifier(switch_login.oid, "other@example.test", None)
            .await
            .unwrap();
        assert!(matches!(
            challenges
                .admit_delivery(
                    DeliveryChallengeContext {
                        user_oid: None,
                        binding: ChallengeBinding::Login(switch_login.oid),
                        method: ChallengeMethod::EmailOtp,
                        purpose: ChallengePurpose::Authentication,
                    },
                    make_request(switch_now + ChronoDuration::seconds(5), switch_now + ChronoDuration::minutes(10)),
                    email(),
                )
                .await
                .unwrap(),
            DeliveryChallengeAdmission::TooSoon { .. }
        ));
    })
    .await;
}

#[tokio::test]
#[ignore = "requires explicitly configured PostgreSQL test database"]
async fn required_password_change_keeps_active_interaction() {
    for request_type in ["authorization_request", "device_authorization_request"] {
        common::isolated(move |db| async move {
            let user = Uuid::new_v4();
            let credential = Uuid::new_v4();
            let client = Uuid::new_v4();
            let kept_request = Uuid::new_v4();
            let other_request = Uuid::new_v4();
            let token = Uuid::new_v4();
            let kept_login = Uuid::new_v4();
            let other_login = Uuid::new_v4();
            let kept_session = Uuid::new_v4();
            let other_session = Uuid::new_v4();
            let old = password("OLD-PASSWORD");
            let new = password("NEW-PASSWORD");
            let data = |login: Uuid| {
                format!(
                    r#"{{"interaction":{{"selected_user_oid":"{user}"}},"claimed_login_oid":"{login}"}}"#
                )
            };
            sql(&db, &format!(r#"
                INSERT INTO "user" (oid,name,name_normalized,email,email_normalized,required_actions)
                  VALUES ('{user}','{user}','{user}','{user}@example.test','{user}@example.test','["change_password"]');
                INSERT INTO client (oid,name,protocol) VALUES ('{client}','pw-change-test','openid_connect');
                INSERT INTO user_credential (oid,user_id,type,data)
                  SELECT '{credential}',id,'password','{}'::jsonb FROM "user" WHERE oid='{user}';
                INSERT INTO session (oid,user_id,status,amr,last_active_at,authenticated_at,expires_at)
                  SELECT s,id,'active','["pwd"]',now(),now(),now()+interval '7 days'
                  FROM "user",unnest(ARRAY['{kept_session}'::uuid,'{other_session}'::uuid]) s WHERE oid='{user}';
                INSERT INTO client_authorization (oid,client_id,type,data,expires_at)
                  SELECT '{kept_request}',id,'{request_type}','{}',now()+interval '1 day' FROM client WHERE oid='{client}';
                INSERT INTO client_authorization (oid,client_id,type,data,expires_at)
                  SELECT '{other_request}',id,'{request_type}','{}',now()+interval '1 day' FROM client WHERE oid='{client}';
                INSERT INTO client_authorization (oid,client_id,type,data,expires_at)
                  SELECT '{token}',id,'access_token','{{"user_oid":"{user}"}}',now()+interval '1 day' FROM client WHERE oid='{client}';
                INSERT INTO login (oid,client_id,client_authorization_id,user_id,session_id,status,requested_acr_values,expires_at)
                  SELECT l.oid,c.id,a.id,u.id,s.id,'password_change_required','["aal1"]'::jsonb,now()+interval '5 minutes'
                  FROM client c,"user" u,session s,
                    (VALUES ('{kept_login}'::uuid,'{kept_request}'::uuid),('{other_login}'::uuid,'{other_request}'::uuid)) l(oid,request),
                    client_authorization a
                  WHERE c.oid='{client}' AND u.oid='{user}' AND s.oid='{kept_session}' AND a.oid=l.request;
            "#, serde_json::to_string(&old).unwrap(), data(kept_login), data(other_login))).await;

            let repo = UserCredentialRepositoryImpl::new(db.clone());
            let revoked = repo
                .replace_password(
                    user.into(),
                    credential.into(),
                    &old,
                    &new,
                    PasswordReplacement {
                        kind: PasswordReplacementKind::Required {
                            login: kept_login,
                            keep: Some(SessionOid(kept_session)),
                        },
                        keep_history: 0,
                    },
                )
                .await
                .unwrap();
            assert_eq!(revoked, 1, "{request_type}");

            let withdrawn = |oid: Uuid| {
                format!(
                    "SELECT count(*)::bigint n FROM client_authorization WHERE oid='{oid}' \
                     AND (revoked_at IS NOT NULL OR data->>'_authority_withdrawn'='true')"
                )
            };
            assert_eq!(scalar(&db, &withdrawn(kept_request)).await, 0, "{request_type}");
            assert_eq!(scalar(&db, &withdrawn(other_request)).await, 1, "{request_type}");
            assert_eq!(scalar(&db, &withdrawn(token)).await, 1, "{request_type}");
            assert_eq!(
                scalar(
                    &db,
                    &format!("SELECT count(*)::bigint n FROM \"user\" WHERE oid='{user}' AND required_actions='[]'::jsonb"),
                )
                .await,
                1
            );
            assert_eq!(
                scalar(
                    &db,
                    &format!("SELECT count(*)::bigint n FROM session WHERE oid='{kept_session}' AND status='active'"),
                )
                .await,
                1
            );
            assert_eq!(
                scalar(
                    &db,
                    &format!("SELECT count(*)::bigint n FROM session WHERE oid='{other_session}' AND status='revoked'"),
                )
                .await,
                1
            );
        })
        .await;
    }
}

async fn user_mgmt_authority(
    db: &DatabaseConnection,
    request_id: &str,
) -> identity_application::user::management::UserManagementAuthority {
    use identity_application::user::management::UserManagementAuthority;
    use identity_domain::authorization::ManagementScope;

    let admin = client_management::administrator(db, &[ManagementScope::UsersWrite]).await;
    let mut actor = admin.actor;
    actor.request_id = RequestId::new(request_id).unwrap();
    UserManagementAuthority::new(
        actor,
        admin.token_scopes,
        admin.snapshot,
        admin.client_oid,
        admin.client_policy_version,
    )
}

#[tokio::test]
#[ignore = "requires explicitly configured PostgreSQL test database"]
async fn password_rehash_preserves_age_and_temporary_password_skips_history() {
    use identity_application::user::management::{
        UserManagementMutationOutcome, UserManagementRepository, UserStateTransaction,
    };
    use identity_infrastructure::database::{
        repository::user_management::UserManagementRepositoryImpl, seed,
    };

    common::isolated(|db| async move {
        seed::run_all(&db).await.unwrap();
        client_management::owner(&db).await;

        let target = Uuid::new_v4();
        let cred = Uuid::new_v4();
        let p1 = password("P1");
        let p1_rehash = password("P1-REHASH");
        let temp = password("TEMP");
        let temp_rehash = password("TEMP-REHASH");
        let p2 = password("P2");
        let p3 = password("P3");
        let p4 = password("P4");
        sql(&db, &format!(r#"
            INSERT INTO "user" (oid,name,name_normalized,email,email_normalized)
              VALUES ('{target}','policy-target','policy-target','policy-target@example.test','policy-target@example.test');
            INSERT INTO user_credential (oid,user_id,type,data,created_at,updated_at)
              SELECT '{cred}',id,'password','{}'::jsonb,now() - interval '60 days',NULL FROM "user" WHERE oid='{target}';
        "#, serde_json::to_string(&p1).unwrap())).await;

        let cred_repo = UserCredentialRepositoryImpl::new(db.clone());
        let before_age = cred_repo.password_set_at(target.into()).await.unwrap().unwrap();
        assert!(before_age < Utc::now() - ChronoDuration::days(59));

        // Transparent Argon2 rehash must not reset password age.
        cred_repo
            .update_password_by_oid(cred.into(), &p1, &p1_rehash)
            .await
            .unwrap();
        let after_age = cred_repo.password_set_at(target.into()).await.unwrap().unwrap();
        assert!(after_age < Utc::now() - ChronoDuration::days(59));

        // Admin reset archives the real password and marks the temporary one.
        let users = UserManagementRepositoryImpl::new(db.clone());
        let version: Uuid = db
            .query_one_raw(Statement::from_sql_and_values(
                DbBackend::Postgres,
                "SELECT version FROM \"user\" WHERE oid=$1",
                [target.into()],
            ))
            .await
            .unwrap()
            .unwrap()
            .try_get("", "version")
            .unwrap();
        let authority = user_mgmt_authority(&db, "policy-history-reset").await;
        let outcome = users
            .reset_user_password(
                UserStateTransaction {
                    user_oid: target.into(),
                    expected_version: version,
                    reason: String::new(),
                    authority,
                },
                temp.clone(),
                2,
            )
            .await
            .unwrap();
        assert!(matches!(outcome, UserManagementMutationOutcome::Success(_)));

        let active_cred = cred_repo
            .find_by_user_oid_and_type(target.into(), CredentialType::Password)
            .await
            .unwrap();
        assert_eq!(active_cred.len(), 1);
        assert_eq!(
            scalar(
                &db,
                &format!("SELECT count(*)::bigint n FROM user_credential WHERE oid='{}' AND data->>'temporary'='true'", active_cred[0].oid.0),
            )
            .await,
            1
        );

        // Rehash of a temporary password preserves the temporary marker.
        cred_repo
            .update_password_by_oid(active_cred[0].oid, &temp, &temp_rehash)
            .await
            .unwrap();
        assert_eq!(
            scalar(
                &db,
                &format!("SELECT count(*)::bigint n FROM user_credential WHERE oid='{}' AND data->>'temporary'='true'", active_cred[0].oid.0),
            )
            .await,
            1
        );

        // Replacing the temporary password does not push it into history.
        let login = Uuid::new_v4();
        let client = Uuid::new_v4();
        sql(&db, &format!(r#"
            INSERT INTO client (oid,name,protocol) VALUES ('{client}','history-test','openid_connect');
            INSERT INTO client_authorization (oid,client_id,type,data,expires_at)
              SELECT gen_random_uuid(),id,'authorization_request','{{}}'::jsonb,now()+interval '1 hour' FROM client WHERE oid='{client}';
            INSERT INTO login (oid,client_id,client_authorization_id,user_id,status,expires_at)
              SELECT '{login}',c.id,a.id,u.id,'password_change_required',now()+interval '5 minutes'
              FROM client c,client_authorization a,"user" u
              WHERE c.oid='{client}' AND a.client_id=c.id AND u.oid='{target}';
        "#)).await;

        cred_repo
            .replace_password(
                target.into(),
                active_cred[0].oid,
                &temp_rehash,
                &p2,
                PasswordReplacement {
                    kind: PasswordReplacementKind::Required {
                        login,
                        keep: None,
                    },
                    keep_history: 2,
                },
            )
            .await
            .unwrap();
        let history = cred_repo.password_history(target.into(), 5).await.unwrap();
        assert_eq!(history.len(), 1);
        assert_eq!(
            serde_json::to_value(&history[0]).unwrap(),
            serde_json::to_value(&p1_rehash).unwrap()
        );

        // Subsequent changes archive real passwords and prune past `keep_history = 2`.
        for (expected, next) in [(&p2, &p3), (&p3, &p4)] {
            let current = cred_repo
                .find_by_user_oid_and_type(target.into(), CredentialType::Password)
                .await
                .unwrap();
            cred_repo
                .replace_password(
                    target.into(),
                    current[0].oid,
                    expected,
                    next,
                    PasswordReplacement {
                        kind: PasswordReplacementKind::Change { keep: None },
                        keep_history: 2,
                    },
                )
                .await
                .unwrap();
        }
        let history = cred_repo.password_history(target.into(), 5).await.unwrap();
        assert_eq!(history.len(), 2);
        let hashes: Vec<_> = history
            .iter()
            .map(|p| match p {
                Password::Argon2(a) => a.hash.as_str(),
            })
            .collect();
        assert_eq!(hashes, vec!["P3", "P2"]);
    })
    .await;
}

#[tokio::test]
#[ignore = "requires explicitly configured PostgreSQL test database"]
async fn user_management_credential_and_delete_transactions() {
    use identity_application::user::management::{
        RevokeUserSessionsTransaction, UserManagementMutationOutcome, UserManagementRepository,
        UserManagementRepositoryError, UserStateTransaction,
    };
    use identity_infrastructure::database::{
        repository::user_management::UserManagementRepositoryImpl, seed,
    };

    common::isolated(|db| async move {
        seed::run_all(&db).await.unwrap();
        client_management::owner(&db).await;

        let target = Uuid::new_v4();
        let third = Uuid::new_v4();
        let passwordless = Uuid::new_v4();
        let client = Uuid::new_v4();
        let s1 = Uuid::new_v4();
        let s2 = Uuid::new_v4();
        let t1 = Uuid::new_v4();
        let t2 = Uuid::new_v4();
        let role = Uuid::new_v4();
        let group = Uuid::new_v4();

        sql(&db, &format!(r#"
            INSERT INTO "user" (oid,name,name_normalized,email,email_normalized) VALUES
              ('{target}','target-user','target-user','target@example.test','target@example.test'),
              ('{third}','third-user','third-user','third@example.test','third@example.test'),
              ('{passwordless}','passkey-only','passkey-only','passkey-only@example.test','passkey-only@example.test');
            INSERT INTO user_credential (oid,user_id,type,data)
              SELECT gen_random_uuid(),u.id,k.kind,'{{}}'::jsonb
              FROM "user" u, unnest(ARRAY['password','otp','recovery_code','passkey']) k(kind)
              WHERE u.oid='{target}';
            INSERT INTO user_credential (oid,user_id,type,data)
              SELECT gen_random_uuid(),id,'passkey','{{}}'::jsonb FROM "user" WHERE oid='{passwordless}';
            INSERT INTO client (oid,name,protocol) VALUES ('{client}','mgmt-test','openid_connect');
            INSERT INTO session (oid,user_id,status,amr,last_active_at,authenticated_at,expires_at)
              SELECT s,id,'active','["pwd"]',now(),now(),now()+interval '7 days'
              FROM "user", unnest(ARRAY['{s1}'::uuid,'{s2}'::uuid]) s WHERE oid='{target}';
            INSERT INTO client_authorization (oid,client_id,type,data,expires_at)
              SELECT '{t1}',id,'access_token','{{"session_oid":"{s1}"}}',now()+interval '1 hour' FROM client WHERE oid='{client}';
            INSERT INTO client_authorization (oid,client_id,type,data,expires_at)
              SELECT '{t2}',id,'refresh_token','{{"session_oid":"{s2}"}}',now()+interval '1 day' FROM client WHERE oid='{client}';
            INSERT INTO role (oid,name,names,enabled) VALUES ('{role}','Custom','{{"en-US":"Custom"}}',true);
            INSERT INTO user_group (oid,name,names,descriptions,enabled) VALUES ('{group}','Team','{{"en-US":"Team"}}','{{}}',true);
            INSERT INTO user_role (oid,user_id,role_id,granted_by_user_id,reason)
              SELECT gen_random_uuid(),u.id,r.id,NULL,'' FROM "user" u,role r WHERE u.oid='{target}' AND r.oid='{role}';
            INSERT INTO user_role (oid,user_id,role_id,granted_by_user_id,reason)
              SELECT gen_random_uuid(),u.id,r.id,g.id,'' FROM "user" u,role r,"user" g WHERE u.oid='{third}' AND r.oid='{role}' AND g.oid='{target}';
            INSERT INTO group_membership (oid,group_id,user_id,granted_by_user_id,reason)
              SELECT gen_random_uuid(),gp.id,u.id,NULL,'' FROM user_group gp,"user" u WHERE gp.oid='{group}' AND u.oid='{target}';
            INSERT INTO group_membership (oid,group_id,user_id,granted_by_user_id,reason)
              SELECT gen_random_uuid(),gp.id,u.id,g.id,'' FROM user_group gp,"user" u,"user" g WHERE gp.oid='{group}' AND u.oid='{third}' AND g.oid='{target}';
        "#)).await;

        let users = UserManagementRepositoryImpl::new(db.clone());
        let authority = user_mgmt_authority(&db, "user-mgmt-creds").await;

        // Passwordless user refuses MFA clear.
        let pwl_version = users.find_user(passwordless.into()).await.unwrap().unwrap().user.version;
        let outcome = users
            .reset_user_mfa(UserStateTransaction {
                user_oid: passwordless.into(),
                expected_version: pwl_version,
                reason: String::new(),
                authority: authority.clone(),
            })
            .await
            .unwrap();
        assert!(matches!(outcome, UserManagementMutationOutcome::NoPassword));

        // Reset MFA removes otp/recovery/passkey, keeps password, revokes sessions/tokens.
        let target_version = users.find_user(target.into()).await.unwrap().unwrap().user.version;
        let outcome = users
            .reset_user_mfa(UserStateTransaction {
                user_oid: target.into(),
                expected_version: target_version,
                reason: String::new(),
                authority: authority.clone(),
            })
            .await
            .unwrap();
        let UserManagementMutationOutcome::Success(record) = outcome else {
            panic!("expected reset_user_mfa success");
        };
        assert_ne!(record.user.version, target_version);
        assert_eq!(
            scalar(&db, &format!("SELECT count(*)::bigint n FROM user_credential uc JOIN \"user\" u ON u.id=uc.user_id WHERE u.oid='{target}' AND uc.type IN ('otp','recovery_code','passkey')")).await,
            0
        );
        assert_eq!(
            scalar(&db, &format!("SELECT count(*)::bigint n FROM user_credential uc JOIN \"user\" u ON u.id=uc.user_id WHERE u.oid='{target}' AND uc.type='password'")).await,
            1
        );
        assert_eq!(
            scalar(&db, &format!("SELECT count(*)::bigint n FROM session s JOIN \"user\" u ON u.id=s.user_id WHERE u.oid='{target}' AND s.status='active'")).await,
            0
        );
        assert_eq!(
            scalar(&db, &format!("SELECT count(*)::bigint n FROM client_authorization WHERE oid IN ('{t1}','{t2}') AND revoked_at IS NOT NULL")).await,
            2
        );
        assert_eq!(semantic_count_for_target(&db, target, Some(AuditAction::UserMfaReset)).await, 1);

        // Revoke sessions: one by OID, then all remaining.
        let s3 = Uuid::new_v4();
        let s4 = Uuid::new_v4();
        let t3 = Uuid::new_v4();
        let t4 = Uuid::new_v4();
        sql(&db, &format!(r#"
            INSERT INTO session (oid,user_id,status,amr,last_active_at,authenticated_at,expires_at)
              SELECT s,id,'active','["pwd"]',now(),now(),now()+interval '7 days'
              FROM "user", unnest(ARRAY['{s3}'::uuid,'{s4}'::uuid]) s WHERE oid='{target}';
            INSERT INTO client_authorization (oid,client_id,type,data,expires_at)
              SELECT '{t3}',id,'access_token','{{"session_oid":"{s3}"}}',now()+interval '1 hour' FROM client WHERE oid='{client}';
            INSERT INTO client_authorization (oid,client_id,type,data,expires_at)
              SELECT '{t4}',id,'access_token','{{"session_oid":"{s4}"}}',now()+interval '1 hour' FROM client WHERE oid='{client}';
        "#)).await;

        let outcome = users
            .revoke_user_sessions(RevokeUserSessionsTransaction {
                user_oid: target.into(),
                sessions: Some(vec![s3]),
                reason: String::new(),
                authority: authority.clone(),
            })
            .await
            .unwrap();
        assert!(matches!(outcome, UserManagementMutationOutcome::Success(_)));
        assert_eq!(scalar(&db, &format!("SELECT count(*)::bigint n FROM session WHERE oid='{s3}' AND status='revoked'")).await, 1);
        assert_eq!(scalar(&db, &format!("SELECT count(*)::bigint n FROM session WHERE oid='{s4}' AND status='active'")).await, 1);
        assert_eq!(scalar(&db, &format!("SELECT count(*)::bigint n FROM client_authorization WHERE oid='{t3}' AND revoked_at IS NOT NULL")).await, 1);
        assert_eq!(scalar(&db, &format!("SELECT count(*)::bigint n FROM client_authorization WHERE oid='{t4}' AND revoked_at IS NULL")).await, 1);

        let outcome = users
            .revoke_user_sessions(RevokeUserSessionsTransaction {
                user_oid: target.into(),
                sessions: None,
                reason: String::new(),
                authority: authority.clone(),
            })
            .await
            .unwrap();
        assert!(matches!(outcome, UserManagementMutationOutcome::Success(_)));
        assert_eq!(scalar(&db, &format!("SELECT count(*)::bigint n FROM session WHERE oid='{s4}' AND status='revoked'")).await, 1);
        assert_eq!(scalar(&db, &format!("SELECT count(*)::bigint n FROM client_authorization WHERE oid='{t4}' AND revoked_at IS NOT NULL")).await, 1);
        assert_eq!(semantic_count_for_target(&db, target, Some(AuditAction::UserSessionRevoke)).await, 2);

        // Delete requires disabled user; audit failure rolls back deletion.
        let version = users.find_user(target.into()).await.unwrap().unwrap().user.version;
        let outcome = users
            .delete_user(UserStateTransaction {
                user_oid: target.into(),
                expected_version: version,
                reason: String::new(),
                authority: authority.clone(),
            })
            .await
            .unwrap();
        assert!(matches!(outcome, UserManagementMutationOutcome::NotDisabled));

        let outcome = users
            .set_user_enabled(
                UserStateTransaction {
                    user_oid: target.into(),
                    expected_version: version,
                    reason: String::new(),
                    authority: authority.clone(),
                },
                false,
            )
            .await
            .unwrap();
        let UserManagementMutationOutcome::Success(disabled) = outcome else {
            panic!("expected disable success");
        };

        let failing_request = "audit-fail-delete";
        sql(
            &db,
            &format!(
                "ALTER TABLE audit ADD CONSTRAINT user_delete_audit_failure CHECK (request_id IS DISTINCT FROM '{failing_request}') NOT VALID"
            ),
        )
        .await;
        let failing_authority = user_mgmt_authority(&db, failing_request).await;
        let failed = users
            .delete_user(UserStateTransaction {
                user_oid: target.into(),
                expected_version: disabled.user.version,
                reason: String::new(),
                authority: failing_authority,
            })
            .await
            .unwrap_err();
        assert!(matches!(failed, UserManagementRepositoryError::AuditFailed(_)));
        assert_eq!(scalar(&db, &format!("SELECT count(*)::bigint n FROM \"user\" WHERE oid='{target}'")).await, 1);
        sql(&db, "ALTER TABLE audit DROP CONSTRAINT user_delete_audit_failure").await;

        let outcome = users
            .delete_user(UserStateTransaction {
                user_oid: target.into(),
                expected_version: disabled.user.version,
                reason: String::new(),
                authority: authority.clone(),
            })
            .await
            .unwrap();
        assert!(matches!(outcome, UserManagementMutationOutcome::Success(_)));
        assert_eq!(scalar(&db, &format!("SELECT count(*)::bigint n FROM \"user\" WHERE oid='{target}'")).await, 0);
        assert_eq!(scalar(&db, &format!("SELECT count(*)::bigint n FROM user_role ur JOIN \"user\" u ON u.id=ur.user_id WHERE u.oid='{third}' AND ur.granted_by_user_id IS NULL")).await, 1);
        assert_eq!(scalar(&db, &format!("SELECT count(*)::bigint n FROM group_membership gm JOIN \"user\" u ON u.id=gm.user_id WHERE u.oid='{third}' AND gm.granted_by_user_id IS NULL")).await, 1);
        assert_eq!(semantic_count_for_target(&db, target, Some(AuditAction::UserDelete)).await, 1);

        // Last recoverable authorization administrator cannot be disabled or deleted.
        let owner_oid: Uuid = db
            .query_one_raw(Statement::from_string(
                DbBackend::Postgres,
                r#"SELECT oid FROM "user" WHERE name='owner'"#.to_owned(),
            ))
            .await
            .unwrap()
            .unwrap()
            .try_get("", "oid")
            .unwrap();
        let owner_version = users.find_user(owner_oid.into()).await.unwrap().unwrap().user.version;
        let protected = users
            .set_user_enabled(
                UserStateTransaction {
                    user_oid: owner_oid.into(),
                    expected_version: owner_version,
                    reason: String::new(),
                    authority,
                },
                false,
            )
            .await
            .unwrap();
        assert!(matches!(protected, UserManagementMutationOutcome::LastOwnerProtected));
    })
    .await;
}
