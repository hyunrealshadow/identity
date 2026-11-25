//! Email verification against PostgreSQL: send admission, single-use links,
//! links voided by later address changes, concurrent confirmation, and the
//! audit written in the same transaction as the verified address.

use std::sync::Arc;

use chrono::{Duration, Utc};
use identity_domain::{
    audit::AuditAction,
    email::{EmailMessage, OutboundEmail},
    user::{
        UserOid,
        email_verification::{
            EmailVerificationAdmission, EmailVerificationOutcome, EmailVerificationRepository,
            EmailVerificationRequest, MAX_EMAIL_VERIFICATION_SENDS,
        },
        repository::UserIdentifierUpdate,
    },
};
use identity_infrastructure::database::repository::{
    email_verification::EmailVerificationRepositoryImpl, user::UserRepositoryImpl,
};
use sea_orm::{ConnectionTrait, DatabaseConnection, DbBackend, Statement};
use uuid::Uuid;

use crate::common;

async fn insert_user(db: &DatabaseConnection, email: &str, verified: bool) -> UserOid {
    let oid = Uuid::new_v4();
    let name = format!("verify-{}", &oid.simple().to_string()[..12]);
    db.execute_raw(Statement::from_sql_and_values(
        DbBackend::Postgres,
        "INSERT INTO \"user\"(oid,name,name_normalized,email,email_normalized,email_verified) VALUES($1,$2,$2,$3,$4,$5)",
        [
            oid.into(),
            name.into(),
            email.into(),
            email.to_lowercase().into(),
            verified.into(),
        ],
    ))
    .await
    .unwrap();
    UserOid(oid)
}

fn request(user: UserOid, email: &str, token: &str) -> EmailVerificationRequest {
    EmailVerificationRequest {
        user_oid: user,
        email: email.to_owned(),
        email_normalized: email.to_lowercase(),
        token_digest: format!("digest-{token}"),
        message: OutboundEmail {
            kind: "email_verification",
            message: EmailMessage {
                to_address: email.to_owned(),
                to_name: None,
                subject: "Verify".to_owned(),
                html: format!("link-{token}"),
            },
            expires_at: Utc::now() + Duration::hours(24),
        },
        now: Utc::now(),
    }
}

async fn stored_email(db: &DatabaseConnection, user: UserOid) -> (String, bool, Uuid) {
    let row = db
        .query_one_raw(Statement::from_sql_and_values(
            DbBackend::Postgres,
            "SELECT email,email_verified,version FROM \"user\" WHERE oid=$1",
            [Uuid::from(user).into()],
        ))
        .await
        .unwrap()
        .unwrap();
    (
        row.try_get("", "email").unwrap(),
        row.try_get("", "email_verified").unwrap(),
        row.try_get("", "version").unwrap(),
    )
}

/// Pretend the last email went out long enough ago to send another.
async fn age_last_send(db: &DatabaseConnection, user: UserOid) {
    db.execute_raw(Statement::from_sql_and_values(
        DbBackend::Postgres,
        "UPDATE authentication_challenge SET sent_at = sent_at - interval '2 minutes' \
         WHERE purpose = 'email_verification' AND user_id = (SELECT id FROM \"user\" WHERE oid=$1)",
        [Uuid::from(user).into()],
    ))
    .await
    .unwrap();
}

#[tokio::test]
#[ignore = "requires explicitly configured PostgreSQL test database"]
async fn sends_are_spaced_limited_and_refused_for_taken_or_verified_addresses() {
    common::isolated(|db| async move {
        let repository =
            EmailVerificationRepositoryImpl::new(db.clone(), common::email_queue(&db).await);
        let user = insert_user(&db, "ada@example.test", true).await;
        insert_user(&db, "taken@example.test", false).await;

        assert_eq!(
            repository
                .admit(request(user, "ada@example.test", "current"))
                .await
                .unwrap(),
            EmailVerificationAdmission::AlreadyVerified
        );
        assert_eq!(
            repository
                .admit(request(user, "Taken@example.test", "taken"))
                .await
                .unwrap(),
            EmailVerificationAdmission::EmailExists
        );
        // A refused request queues nothing.
        assert_eq!(common::queued_emails(&db).await, 0);

        let first = repository
            .admit(request(user, "Ada.New@example.test", "first"))
            .await
            .unwrap();
        let EmailVerificationAdmission::Admitted { verification, .. } = first else {
            panic!("first send should be admitted: {first:?}");
        };
        assert!(verification.changes_email);
        assert!(matches!(
            repository
                .admit(request(user, "ada.new@example.test", "too-soon"))
                .await
                .unwrap(),
            EmailVerificationAdmission::TooSoon { .. }
        ));

        for send in 2..=MAX_EMAIL_VERIFICATION_SENDS {
            age_last_send(&db, user).await;
            assert!(
                matches!(
                    repository
                        .admit(request(
                            user,
                            "ada.new@example.test",
                            &format!("send-{send}")
                        ))
                        .await
                        .unwrap(),
                    EmailVerificationAdmission::Admitted { .. }
                ),
                "send {send} should be admitted"
            );
        }
        age_last_send(&db, user).await;
        assert_eq!(
            repository
                .admit(request(user, "ada.new@example.test", "over-limit"))
                .await
                .unwrap(),
            EmailVerificationAdmission::LimitReached
        );
        // The refused requests left the address untouched, and only the
        // admitted ones queued their email.
        assert_eq!(stored_email(&db, user).await.0, "ada@example.test");
        assert_eq!(
            common::queued_emails(&db).await,
            i64::from(MAX_EMAIL_VERIFICATION_SENDS)
        );
    })
    .await;
}

#[tokio::test]
#[ignore = "requires explicitly configured PostgreSQL test database"]
async fn a_link_replaces_the_address_once_and_is_audited_with_it() {
    common::isolated(|db| async move {
        let repository =
            EmailVerificationRepositoryImpl::new(db.clone(), common::email_queue(&db).await);
        let user = insert_user(&db, "ada@example.test", true).await;
        let (_, _, version_before) = stored_email(&db, user).await;
        repository
            .admit(request(user, "Ada.New@example.test", "change"))
            .await
            .unwrap();
        assert!(
            repository
                .pending(user, Utc::now())
                .await
                .unwrap()
                .is_some()
        );

        // An expired link is refused like an unknown one.
        assert_eq!(
            repository
                .confirm("digest-change", Utc::now() + Duration::days(2))
                .await
                .unwrap(),
            EmailVerificationOutcome::Invalid
        );

        let outcome = repository
            .confirm("digest-change", Utc::now())
            .await
            .unwrap();
        assert_eq!(
            outcome,
            EmailVerificationOutcome::Verified {
                user_oid: user,
                email: "Ada.New@example.test".to_owned(),
                changed: true,
            }
        );
        let (email, verified, version_after) = stored_email(&db, user).await;
        assert_eq!(email, "Ada.New@example.test");
        assert!(verified);
        assert_ne!(version_before, version_after);
        assert!(
            repository
                .pending(user, Utc::now())
                .await
                .unwrap()
                .is_none()
        );

        let audit = db
            .query_one_raw(Statement::from_sql_and_values(
                DbBackend::Postgres,
                "SELECT actor_kind,actor_oid,changes FROM audit WHERE target_oid=$1 AND action=$2",
                [
                    Uuid::from(user).into(),
                    AuditAction::AccountEmailVerify.to_string().into(),
                ],
            ))
            .await
            .unwrap()
            .expect("the verified address is audited");
        assert_eq!(
            audit.try_get::<Uuid>("", "actor_oid").unwrap(),
            Uuid::from(user)
        );
        let changes: serde_json::Value = audit.try_get("", "changes").unwrap();
        assert!(changes.to_string().contains("\"email\""), "{changes}");

        // The link is single-use.
        assert_eq!(
            repository
                .confirm("digest-change", Utc::now())
                .await
                .unwrap(),
            EmailVerificationOutcome::Invalid
        );
    })
    .await;
}

#[tokio::test]
#[ignore = "requires explicitly configured PostgreSQL test database"]
async fn later_changes_void_older_links() {
    common::isolated(|db| async move {
        let repository =
            EmailVerificationRepositoryImpl::new(db.clone(), common::email_queue(&db).await);
        let users = UserRepositoryImpl::new(db.clone());
        let user = insert_user(&db, "ada@example.test", false).await;

        // A newer request replaces the older link.
        repository
            .admit(request(user, "ada@example.test", "older"))
            .await
            .unwrap();
        age_last_send(&db, user).await;
        repository
            .admit(request(user, "ada.new@example.test", "newer"))
            .await
            .unwrap();
        assert_eq!(
            repository
                .confirm("digest-older", Utc::now())
                .await
                .unwrap(),
            EmailVerificationOutcome::Invalid
        );

        // Changing the address directly discards the pending verification.
        users
            .update_identifier(
                user,
                UserIdentifierUpdate::Email {
                    value: "ada.other@example.test".to_owned(),
                    normalized: "ada.other@example.test".to_owned(),
                },
            )
            .await
            .unwrap();
        assert_eq!(
            repository
                .confirm("digest-newer", Utc::now())
                .await
                .unwrap(),
            EmailVerificationOutcome::Invalid
        );
        let (email, verified, _) = stored_email(&db, user).await;
        assert_eq!(email, "ada.other@example.test");
        assert!(!verified);

        // Another account taking the address before the link is followed.
        age_last_send(&db, user).await;
        repository
            .admit(request(user, "contested@example.test", "contested"))
            .await
            .unwrap();
        insert_user(&db, "contested@example.test", false).await;
        assert_eq!(
            repository
                .confirm("digest-contested", Utc::now())
                .await
                .unwrap(),
            EmailVerificationOutcome::EmailExists
        );
        assert_eq!(stored_email(&db, user).await.0, "ada.other@example.test");
    })
    .await;
}

#[tokio::test]
#[ignore = "requires explicitly configured PostgreSQL test database"]
async fn concurrent_confirmations_use_a_link_once() {
    common::isolated(|db| async move {
        let repository = Arc::new(EmailVerificationRepositoryImpl::new(
            db.clone(),
            common::email_queue(&db).await,
        ));
        let user = insert_user(&db, "ada@example.test", false).await;
        repository
            .admit(request(user, "ada@example.test", "race"))
            .await
            .unwrap();

        let attempts = (0..8).map(|_| {
            let repository = Arc::clone(&repository);
            tokio::spawn(async move { repository.confirm("digest-race", Utc::now()).await })
        });
        let mut verified = 0;
        for attempt in attempts {
            match attempt.await.unwrap().unwrap() {
                EmailVerificationOutcome::Verified { changed, .. } => {
                    assert!(!changed);
                    verified += 1;
                }
                EmailVerificationOutcome::Invalid => {}
                other => panic!("unexpected outcome {other:?}"),
            }
        }
        assert_eq!(verified, 1);
        let audits = db
            .query_one_raw(Statement::from_sql_and_values(
                DbBackend::Postgres,
                "SELECT count(*) AS n FROM audit WHERE target_oid=$1 AND action=$2",
                [
                    Uuid::from(user).into(),
                    AuditAction::AccountEmailVerify.to_string().into(),
                ],
            ))
            .await
            .unwrap()
            .unwrap()
            .try_get::<i64>("", "n")
            .unwrap();
        assert_eq!(audits, 1);
    })
    .await;
}

#[tokio::test]
#[ignore = "requires explicitly configured PostgreSQL test database"]
async fn a_failed_audit_keeps_the_address_and_the_link() {
    common::isolated(|db| async move {
        let repository =
            EmailVerificationRepositoryImpl::new(db.clone(), common::email_queue(&db).await);
        let user = insert_user(&db, "ada@example.test", true).await;
        repository
            .admit(request(user, "ada.new@example.test", "rollback"))
            .await
            .unwrap();

        db.execute_unprepared(&format!(
            "ALTER TABLE audit ADD CONSTRAINT identity_test_fail_audit \
             CHECK (action IS DISTINCT FROM '{}') NOT VALID",
            AuditAction::AccountEmailVerify
        ))
        .await
        .unwrap();
        let result = repository.confirm("digest-rollback", Utc::now()).await;
        db.execute_unprepared("ALTER TABLE audit DROP CONSTRAINT identity_test_fail_audit")
            .await
            .unwrap();

        assert!(result.is_err());
        let (email, verified, _) = stored_email(&db, user).await;
        assert_eq!(email, "ada@example.test");
        assert!(verified);
        // The link was not consumed and still works.
        assert!(matches!(
            repository
                .confirm("digest-rollback", Utc::now())
                .await
                .unwrap(),
            EmailVerificationOutcome::Verified { changed: true, .. }
        ));
    })
    .await;
}
