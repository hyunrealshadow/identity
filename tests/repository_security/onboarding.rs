//! Onboarding against PostgreSQL: an invitation created with the account,
//! resent, voided by an address change or a password, and accepted once;
//! and self-registration that creates the account in the same transaction
//! that uses up the login's link and binds the login to it.

use chrono::{Duration as ChronoDuration, Utc};
use identity_application::{
    authentication::{
        challenge::ChallengeRepository,
        login::{NewAccount, RegistrationOutcome, RegistrationRepository},
    },
    user::{
        invitation::{InvitationAcceptance, InvitationIssue, UserInvitationRepository},
        management::{
            CreateUserTransaction, SendUserInvitationTransaction, UserInvitationOutcome,
            UserManagementMutationOutcome, UserManagementRepository, UserStateTransaction,
        },
    },
};
use identity_domain::email::{EmailDeliveryFailure, EmailDeliveryReport, EmailDeliveryStatus};
use identity_domain::{
    audit::AuditAction,
    auth::{
        LoginStatus,
        challenge::{
            ChallengeBinding, ChallengeMethod, ChallengePurpose, DeliveryChallengeAdmission,
            DeliveryChallengeContext, DeliveryChallengeRequest,
        },
        repository::LoginRepository,
    },
};
use identity_infrastructure::database::{
    repository::{
        account_challenge::record_delivery, challenge::ChallengeRepositoryImpl,
        login::LoginRepositoryImpl, registration::RegistrationRepositoryImpl,
        user_invitation::UserInvitationRepositoryImpl,
        user_management::UserManagementRepositoryImpl,
    },
    seed,
};
use sea_orm::{ConnectionTrait, DatabaseConnection, DbBackend, Statement};
use uuid::Uuid;

use super::{
    client_management, common, latest_semantic_audit, password, scalar, sql, user_mgmt_authority,
};

/// A new invitation link whose email was written for `recipient`.
fn issue(digest: &str, recipient: &str) -> InvitationIssue {
    let now = Utc::now();
    let expires_at = now + ChronoDuration::days(7);
    InvitationIssue {
        token_digest: digest.to_owned(),
        email: identity_domain::email::OutboundEmail {
            kind: "user_invitation",
            message: identity_domain::email::EmailMessage {
                to_address: recipient.to_owned(),
                to_name: None,
                subject: "Invitation".to_owned(),
                html: format!("link-{digest}"),
            },
            expires_at,
        },
        recipient_normalized: recipient.to_owned(),
        sent_at: now,
        expires_at,
    }
}

async fn user_oid(db: &DatabaseConnection, name: &str) -> Uuid {
    db.query_one_raw(Statement::from_sql_and_values(
        DbBackend::Postgres,
        r#"SELECT oid FROM "user" WHERE name_normalized=$1"#,
        [name.into()],
    ))
    .await
    .unwrap()
    .unwrap()
    .try_get("", "oid")
    .unwrap()
}

/// The invitation each queued email reports to, oldest first.
async fn queued_reports(db: &DatabaseConnection) -> Vec<Uuid> {
    let schema: String = db
        .query_one_raw(Statement::from_string(
            DbBackend::Postgres,
            "SELECT current_schema() AS name".to_owned(),
        ))
        .await
        .unwrap()
        .unwrap()
        .try_get("", "name")
        .unwrap();
    db.query_all_raw(Statement::from_sql_and_values(
        DbBackend::Postgres,
        "SELECT (convert_from(job, 'UTF8')::jsonb ->> 'report_to')::uuid AS oid \
         FROM apalis.jobs WHERE job_type = $1 ORDER BY run_at, id",
        [format!("test.{schema}").into()],
    ))
    .await
    .unwrap()
    .into_iter()
    .map(|row| row.try_get("", "oid").unwrap())
    .collect()
}

async fn version(db: &DatabaseConnection, user: Uuid) -> Uuid {
    db.query_one_raw(Statement::from_sql_and_values(
        DbBackend::Postgres,
        r#"SELECT version FROM "user" WHERE oid=$1"#,
        [user.into()],
    ))
    .await
    .unwrap()
    .unwrap()
    .try_get("", "version")
    .unwrap()
}

async fn send(
    users: &UserManagementRepositoryImpl,
    db: &DatabaseConnection,
    user: Uuid,
    digest: &str,
    request: &str,
) -> UserInvitationOutcome {
    users
        .send_user_invitation(SendUserInvitationTransaction {
            user_oid: user.into(),
            invitation: issue(digest, "invitee@example.test"),
            delivery: identity_application::user::invitation::USER_INVITATION_DELIVERY,
            reason: String::new(),
            authority: user_mgmt_authority(db, request).await,
        })
        .await
        .unwrap()
}

#[tokio::test]
#[ignore = "requires explicitly configured PostgreSQL test database"]
async fn an_invitation_sets_the_first_password_once_and_only_for_its_address() {
    common::isolated(|db| async move {
        seed::run_all(&db).await.unwrap();
        client_management::owner(&db).await;
        let users = UserManagementRepositoryImpl::new(db.clone())
            .with_email_queue(common::email_queue(&db).await);
        let invitations = UserInvitationRepositoryImpl::new(db.clone());

        // Created without a password, with an invitation, in one write.
        let outcome = users
            .create_user(CreateUserTransaction {
                username: "invitee".to_owned(),
                username_normalized: "invitee".to_owned(),
                email: "Invitee@example.test".to_owned(),
                email_normalized: "invitee@example.test".to_owned(),
                password: None,
                invitation: Some(issue("digest-first", "invitee@example.test")),
                profile: identity_domain::user::repository::UserProfilePatch::default(),
                reason: String::new(),
                authority: user_mgmt_authority(&db, "invite-create").await,
            })
            .await
            .unwrap();
        assert!(matches!(outcome, UserManagementMutationOutcome::Success(_)));
        let invitee = user_oid(&db, "invitee").await;
        assert_eq!(
            scalar(&db, &format!("SELECT count(*)::bigint n FROM user_credential c JOIN \"user\" u ON u.id=c.user_id WHERE u.oid='{invitee}'")).await,
            0
        );
        assert_eq!(
            scalar(&db, &format!("SELECT count(*)::bigint n FROM audit WHERE target_oid='{invitee}' AND action IN ('user_create','user_invite')")).await,
            2
        );
        assert!(invitations.find_for_user(invitee.into()).await.unwrap().is_some());
        let shown = invitations
            .find_by_token("digest-first", Utc::now())
            .await
            .unwrap()
            .expect("the link shows its account");
        assert_eq!(shown.name, "invitee");

        // The invitation email was queued with the account.
        assert_eq!(common::queued_emails(&db).await, 1);

        // Another send within the interval is refused and queues nothing;
        // afterwards it replaces the link.
        assert!(matches!(
            send(&users, &db, invitee, "digest-too-soon", "invite-too-soon").await,
            UserInvitationOutcome::TooSoon { .. }
        ));
        assert_eq!(common::queued_emails(&db).await, 1);
        sql(&db, "UPDATE authentication_challenge SET sent_at = sent_at - interval '2 minutes' WHERE purpose = 'invitation'").await;
        assert!(matches!(
            send(&users, &db, invitee, "digest-second", "invite-resend").await,
            UserInvitationOutcome::Sent { .. }
        ));
        assert_eq!(common::queued_emails(&db).await, 2);
        assert!(invitations.find_by_token("digest-first", Utc::now()).await.unwrap().is_none());

        // Each queued email names the invitation it carries; the worker's
        // outcome shows on the invitation. A late outcome of the replaced
        // link's email changes nothing.
        let reported = queued_reports(&db).await;
        assert_eq!(reported.len(), 2);
        let status = |db: DatabaseConnection| async move {
            UserInvitationRepositoryImpl::new(db)
                .find_for_user(invitee.into())
                .await
                .unwrap()
                .expect("an invitation is pending")
                .delivery
        };
        assert_eq!(status(db.clone()).await.status, EmailDeliveryStatus::Queued);
        record_delivery(
            &db,
            reported[1],
            &EmailDeliveryReport::failed(EmailDeliveryFailure::InvalidAddress, Utc::now()),
        )
        .await
        .unwrap();
        let failed = status(db.clone()).await;
        assert_eq!(failed.status, EmailDeliveryStatus::Failed);
        assert_eq!(failed.failure, Some(EmailDeliveryFailure::InvalidAddress));
        record_delivery(&db, reported[0], &EmailDeliveryReport::delivered(Utc::now()))
            .await
            .unwrap();
        assert_eq!(status(db.clone()).await.status, EmailDeliveryStatus::Failed);

        // An email written for an address the account no longer has is
        // neither stored nor queued, so the old address never gets a link
        // that works for the account.
        sql(&db, "UPDATE authentication_challenge SET sent_at = sent_at - interval '2 minutes' WHERE purpose = 'invitation'").await;
        let stale = users
            .send_user_invitation(SendUserInvitationTransaction {
                user_oid: invitee.into(),
                invitation: issue("digest-stale-address", "old@example.test"),
                delivery: identity_application::user::invitation::USER_INVITATION_DELIVERY,
                reason: String::new(),
                authority: user_mgmt_authority(&db, "invite-stale-address").await,
            })
            .await
            .unwrap();
        assert!(matches!(stale, UserInvitationOutcome::AddressChanged { .. }));
        assert_eq!(common::queued_emails(&db).await, 2);
        assert!(invitations.find_by_token("digest-stale-address", Utc::now()).await.unwrap().is_none());
        assert!(invitations.find_by_token("digest-second", Utc::now()).await.unwrap().is_some());

        // Disabling the account ends its logins and sessions with their
        // challenges, but not the invitation, which needs neither. It works
        // again once the account is enabled.
        for (enabled, request) in [(false, "invite-disable"), (true, "invite-enable")] {
            let outcome = users
                .set_user_enabled(
                    UserStateTransaction {
                        user_oid: invitee.into(),
                        expected_version: version(&db, invitee).await,
                        reason: String::new(),
                        authority: user_mgmt_authority(&db, request).await,
                    },
                    enabled,
                )
                .await
                .unwrap();
            assert!(matches!(outcome, UserManagementMutationOutcome::Success(_)));
        }
        assert!(invitations.find_by_token("digest-second", Utc::now()).await.unwrap().is_some());
        assert_eq!(
            invitations
                .accept("digest-first", &password("STALE"), Utc::now())
                .await
                .unwrap(),
            InvitationAcceptance::Invalid
        );

        // A changed address voids the link.
        sql(&db, &format!("UPDATE \"user\" SET email_normalized='moved@example.test' WHERE oid='{invitee}'")).await;
        assert!(invitations.find_for_user(invitee.into()).await.unwrap().is_none());
        assert_eq!(
            invitations
                .accept("digest-second", &password("MOVED"), Utc::now())
                .await
                .unwrap(),
            InvitationAcceptance::Invalid
        );
        sql(&db, &format!("UPDATE \"user\" SET email_normalized='invitee@example.test' WHERE oid='{invitee}'")).await;

        // Accepting sets the password, verifies the address, and is audited.
        assert_eq!(
            invitations
                .accept("digest-second", &password("FIRST"), Utc::now())
                .await
                .unwrap(),
            InvitationAcceptance::Accepted {
                user_oid: invitee.into()
            }
        );
        assert_eq!(
            scalar(&db, &format!("SELECT count(*)::bigint n FROM user_credential c JOIN \"user\" u ON u.id=c.user_id WHERE u.oid='{invitee}' AND c.type='password' AND c.data->>'hash'='FIRST'")).await,
            1
        );
        assert_eq!(
            scalar(&db, &format!("SELECT count(*)::bigint n FROM \"user\" WHERE oid='{invitee}' AND email_verified")).await,
            1
        );
        assert_eq!(scalar(&db, "SELECT count(*)::bigint n FROM authentication_challenge WHERE purpose = 'invitation'").await, 0);
        let audit = latest_semantic_audit(&db, invitee).await.unwrap();
        assert_eq!(audit.action, AuditAction::AccountInvitationAccept.to_string());
        assert_eq!(audit.actor_oid, Some(invitee));
        assert_eq!(
            invitations
                .accept("digest-second", &password("AGAIN"), Utc::now())
                .await
                .unwrap(),
            InvitationAcceptance::Invalid
        );
        // With a password, nothing more can be sent.
        assert!(matches!(
            send(&users, &db, invitee, "digest-third", "invite-has-password").await,
            UserInvitationOutcome::HasPassword
        ));
    })
    .await;
}

#[tokio::test]
#[ignore = "requires explicitly configured PostgreSQL test database"]
async fn an_administrator_password_replaces_an_outstanding_invitation() {
    common::isolated(|db| async move {
        seed::run_all(&db).await.unwrap();
        client_management::owner(&db).await;
        let users = UserManagementRepositoryImpl::new(db.clone())
            .with_email_queue(common::email_queue(&db).await);
        let invitations = UserInvitationRepositoryImpl::new(db.clone());
        users
            .create_user(CreateUserTransaction {
                username: "pending".to_owned(),
                username_normalized: "pending".to_owned(),
                email: "pending@example.test".to_owned(),
                email_normalized: "pending@example.test".to_owned(),
                password: None,
                invitation: Some(issue("digest-pending", "pending@example.test")),
                profile: identity_domain::user::repository::UserProfilePatch::default(),
                reason: String::new(),
                authority: user_mgmt_authority(&db, "pending-create").await,
            })
            .await
            .unwrap();
        let pending = user_oid(&db, "pending").await;
        let outcome = users
            .reset_user_password(
                UserStateTransaction {
                    user_oid: pending.into(),
                    expected_version: version(&db, pending).await,
                    reason: String::new(),
                    authority: user_mgmt_authority(&db, "pending-reset").await,
                },
                password("TEMPORARY"),
                0,
            )
            .await
            .unwrap();
        assert!(matches!(outcome, UserManagementMutationOutcome::Success(_)));
        assert!(
            invitations
                .find_for_user(pending.into())
                .await
                .unwrap()
                .is_none()
        );
        assert_eq!(
            invitations
                .accept("digest-pending", &password("LATE"), Utc::now())
                .await
                .unwrap(),
            InvitationAcceptance::Invalid
        );
    })
    .await;
}

#[tokio::test]
#[ignore = "requires explicitly configured PostgreSQL test database"]
async fn registration_creates_a_verified_account_and_binds_its_login_once() {
    common::isolated(|db| async move {
        let client = Uuid::new_v4();
        let relation = Uuid::new_v4();
        sql(&db, &format!(r#"
            INSERT INTO "user" (oid,name,name_normalized,email,email_normalized)
              VALUES (gen_random_uuid(),'taken-name','taken-name','someone@example.test','someone@example.test');
            INSERT INTO client (oid,name,protocol) VALUES ('{client}','registration-test','openid_connect');
            INSERT INTO client_authorization (oid,client_id,type,data,expires_at)
              SELECT '{relation}',id,'authorization_request','{{}}'::jsonb,now()+interval '1 hour' FROM client WHERE oid='{client}';
        "#)).await;
        let logins = LoginRepositoryImpl::new(db.clone());
        let login = logins.create_pending(client, relation, &[]).await.unwrap();
        let challenges = ChallengeRepositoryImpl::new(db.clone());
        let registrations = RegistrationRepositoryImpl::new(db.clone());

        assert!(registrations.email_registered("someone@example.test").await.unwrap());
        assert!(!registrations.email_registered("new@example.test").await.unwrap());

        // The login has no account yet, so the challenge has none either.
        let now = Utc::now();
        let admitted = challenges
            .admit_delivery(
                DeliveryChallengeContext {
                    user_oid: None,
                    binding: ChallengeBinding::Login(login.oid),
                    method: ChallengeMethod::EmailOtp,
                    purpose: ChallengePurpose::Registration,
                },
                DeliveryChallengeRequest {
                    now,
                    policy: identity_domain::auth::LOGIN_EMAIL_DELIVERY,
                    code_expires_at: now + ChronoDuration::minutes(15),
                    required_login_status: Some(LoginStatus::CREATED),
                    verifier: Some(serde_json::json!({
                        "link": "digest",
                        "email": "New@example.test",
                        "email_normalized": "new@example.test",
                    })),
                    preserve_verifier: false,
                    expected_email_normalized: None,
                },
                None,
            )
            .await
            .unwrap();
        assert!(matches!(admitted, DeliveryChallengeAdmission::Admitted { .. }));
        let challenge = registrations
            .latest(login.oid)
            .await
            .unwrap()
            .expect("the registration challenge");

        let account = |username: &str| NewAccount {
            login_oid: login.oid,
            challenge_oid: challenge.id,
            username: username.to_owned(),
            username_normalized: username.to_lowercase(),
            email: "New@example.test".to_owned(),
            email_normalized: "new@example.test".to_owned(),
            password: password("REGISTERED"),
        };
        // A taken username rolls back, so the link stays usable.
        assert_eq!(
            registrations.register(account("Taken-Name")).await.unwrap(),
            RegistrationOutcome::UsernameExists
        );
        assert!(registrations.latest(login.oid).await.unwrap().is_some());

        assert_eq!(
            registrations.register(account("Newcomer")).await.unwrap(),
            RegistrationOutcome::Registered
        );
        let newcomer = user_oid(&db, "newcomer").await;
        assert_eq!(
            scalar(&db, &format!("SELECT count(*)::bigint n FROM \"user\" WHERE oid='{newcomer}' AND email_verified AND email='New@example.test'")).await,
            1
        );
        assert_eq!(
            scalar(&db, &format!("SELECT count(*)::bigint n FROM user_credential c JOIN \"user\" u ON u.id=c.user_id WHERE u.oid='{newcomer}' AND c.type='password'")).await,
            1
        );
        let bound = logins.find_by_oid(login.oid).await.unwrap().unwrap();
        assert_eq!(bound.status, LoginStatus::IDENTIFIER_VERIFIED);
        assert_eq!(bound.user_oid, Some(newcomer));
        let audit = latest_semantic_audit(&db, newcomer).await.unwrap();
        assert_eq!(audit.action, AuditAction::AccountRegister.to_string());
        assert_eq!(audit.actor_oid, Some(newcomer));

        // The link was used up with the account.
        assert!(registrations.latest(login.oid).await.unwrap().is_none());
        assert_eq!(
            registrations.register(account("Second")).await.unwrap(),
            RegistrationOutcome::LinkInvalid
        );
        assert_eq!(scalar(&db, "SELECT count(*)::bigint n FROM \"user\" WHERE name_normalized='second'").await, 0);
    })
    .await;
}

#[tokio::test]
#[ignore = "requires explicitly configured PostgreSQL test database"]
async fn invitation_guards_delivery_regression_email_updates_disabled_users_and_required_actions() {
    common::isolated(|db| async move {
        seed::run_all(&db).await.unwrap();
        client_management::owner(&db).await;
        let users = UserManagementRepositoryImpl::new(db.clone())
            .with_email_queue(common::email_queue(&db).await);
        let invitations = UserInvitationRepositoryImpl::new(db.clone());
        users
            .create_user(CreateUserTransaction {
                username: "invite-guard".to_owned(),
                username_normalized: "invite-guard".to_owned(),
                email: "guard@example.test".to_owned(),
                email_normalized: "guard@example.test".to_owned(),
                password: None,
                invitation: Some(issue("digest-guard-1", "guard@example.test")),
                profile: identity_domain::user::repository::UserProfilePatch::default(),
                reason: String::new(),
                authority: user_mgmt_authority(&db, "guard-create").await,
            })
            .await
            .unwrap();
        let target = user_oid(&db, "invite-guard").await;

        // Delivered status cannot regress to Failed on late retries.
        let reported = queued_reports(&db).await;
        assert_eq!(reported.len(), 1);
        record_delivery(
            &db,
            reported[0],
            &EmailDeliveryReport::delivered(Utc::now()),
        )
        .await
        .unwrap();
        record_delivery(
            &db,
            reported[0],
            &EmailDeliveryReport::failed(EmailDeliveryFailure::InvalidAddress, Utc::now()),
        )
        .await
        .unwrap();
        let delivery = invitations
            .find_for_user(target.into())
            .await
            .unwrap()
            .expect("invitation remains pending")
            .delivery;
        assert_eq!(delivery.status, EmailDeliveryStatus::Delivered);
        assert_eq!(delivery.failure, None);

        // Changing the user's email through management discards the pending invitation.
        let updated = users
            .update_user(
                identity_application::user::management::UpdateUserTransaction {
                    user_oid: target.into(),
                    username: None,
                    email: Some(
                        identity_application::user::management::UserIdentifierValue {
                            value: "moved-guard@example.test".to_owned(),
                            normalized: "moved-guard@example.test".to_owned(),
                        },
                    ),
                    email_verified: None,
                    required_actions: Some(identity_domain::user::RequiredActions::from_iter([
                        identity_domain::user::RequiredAction::ChangePassword,
                    ])),
                    profile: identity_domain::user::repository::UserProfilePatch::default(),
                    expected_version: version(&db, target).await,
                    reason: String::new(),
                    authority: user_mgmt_authority(&db, "guard-update-email").await,
                },
            )
            .await
            .unwrap();
        assert!(matches!(updated, UserManagementMutationOutcome::Success(_)));
        assert!(
            invitations
                .find_for_user(target.into())
                .await
                .unwrap()
                .is_none()
        );
        assert_eq!(
            invitations
                .accept("digest-guard-1", &password("MOVED"), Utc::now())
                .await
                .unwrap(),
            InvitationAcceptance::Invalid
        );

        // Disabled accounts refuse new invitations without queuing mail.
        let disabled = users
            .set_user_enabled(
                UserStateTransaction {
                    user_oid: target.into(),
                    expected_version: version(&db, target).await,
                    reason: String::new(),
                    authority: user_mgmt_authority(&db, "guard-disable").await,
                },
                false,
            )
            .await
            .unwrap();
        assert!(matches!(
            disabled,
            UserManagementMutationOutcome::Success(_)
        ));
        let disabled_outcome = users
            .send_user_invitation(SendUserInvitationTransaction {
                user_oid: target.into(),
                invitation: issue("digest-guard-disabled", "moved-guard@example.test"),
                delivery: identity_application::user::invitation::USER_INVITATION_DELIVERY,
                reason: String::new(),
                authority: user_mgmt_authority(&db, "guard-send-disabled").await,
            })
            .await
            .unwrap();
        assert!(matches!(
            disabled_outcome,
            UserInvitationOutcome::UserDisabled
        ));
        assert_eq!(common::queued_emails(&db).await, 1);

        // Re-enable, re-send, and verify acceptance clears CHANGE_PASSWORD.
        let enabled = users
            .set_user_enabled(
                UserStateTransaction {
                    user_oid: target.into(),
                    expected_version: version(&db, target).await,
                    reason: String::new(),
                    authority: user_mgmt_authority(&db, "guard-enable").await,
                },
                true,
            )
            .await
            .unwrap();
        assert!(matches!(enabled, UserManagementMutationOutcome::Success(_)));
        let resent = users
            .send_user_invitation(SendUserInvitationTransaction {
                user_oid: target.into(),
                invitation: issue("digest-guard-2", "moved-guard@example.test"),
                delivery: identity_application::user::invitation::USER_INVITATION_DELIVERY,
                reason: String::new(),
                authority: user_mgmt_authority(&db, "guard-resend").await,
            })
            .await
            .unwrap();
        assert!(matches!(resent, UserInvitationOutcome::Sent { .. }));
        assert_eq!(
            invitations
                .accept("digest-guard-2", &password("ACCEPTED"), Utc::now())
                .await
                .unwrap(),
            InvitationAcceptance::Accepted {
                user_oid: target.into()
            }
        );
        assert_eq!(
            scalar(
                &db,
                &format!(
                    "SELECT count(*)::bigint n FROM \"user\" \
                     WHERE oid='{target}' AND NOT (required_actions @> '[\"change_password\"]')"
                ),
            )
            .await,
            1
        );
    })
    .await;
}
