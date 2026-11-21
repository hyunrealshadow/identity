use std::{future::Future, pin::Pin, sync::Arc};

use chrono::{Duration, Utc};
use identity_application::{
    audit::{AuditEventCountRequest, AuditEventPageRequest, AuditQueryService},
    client::ClientManagementRepository,
    data_protection::DataProtector,
    error::codes::audit::AuditErrorCode,
};
use identity_domain::{
    audit::{
        AuditAction, AuditActor, AuditActorKind, AuditCategory, AuditChangeValue, AuditEventOid,
        AuditEventOrder, AuditEventOrderDirection, AuditEventOrderField, AuditField, AuditOutcome,
        AuditQueryRepository, AuditQueryRepositoryError, AuditRecord,
    },
    data_protection::DataProtectionError,
    global_id::{encode, kind},
};
use identity_infrastructure::database::{
    audit::{self, AuditRequestContext},
    repository::{
        audit_query::AuditQueryRepositoryImpl, client_management::ClientManagementRepositoryImpl,
    },
};
use sea_orm::TransactionTrait;
use serde_json::json;
use uuid::Uuid;

use super::{isolated, row, sql};

struct PassthroughTestProtector;

impl DataProtector for PassthroughTestProtector {
    fn protect<'life0, 'life1, 'life2, 'async_trait>(
        &'life0 self,
        purpose: &'life1 str,
        plaintext: &'life2 [u8],
    ) -> Pin<Box<dyn Future<Output = Result<String, DataProtectionError>> + Send + 'async_trait>>
    where
        'life0: 'async_trait,
        'life1: 'async_trait,
        'life2: 'async_trait,
        Self: 'async_trait,
    {
        let result = String::from_utf8(plaintext.to_vec())
            .map(|text| format!("{purpose}|{text}"))
            .map_err(|_| DataProtectionError::InvalidProtectedPayload);
        Box::pin(async move { result })
    }

    fn unprotect<'life0, 'life1, 'life2, 'async_trait>(
        &'life0 self,
        purpose: &'life1 str,
        token: &'life2 str,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<u8>, DataProtectionError>> + Send + 'async_trait>>
    where
        'life0: 'async_trait,
        'life1: 'async_trait,
        'life2: 'async_trait,
        Self: 'async_trait,
    {
        let prefix = format!("{purpose}|");
        let result = token
            .strip_prefix(&prefix)
            .ok_or(DataProtectionError::InvalidProtectedPayload)
            .map(|rest| rest.as_bytes().to_vec());
        Box::pin(async move { result })
    }
}

fn page(query: &str) -> AuditEventPageRequest {
    AuditEventPageRequest {
        query: Some(query.to_owned()),
        time_zone: None,
        order: AuditEventOrder::default(),
        first: Some(20),
        after: None,
        last: None,
        before: None,
    }
}

fn count(query: &str) -> AuditEventCountRequest {
    AuditEventCountRequest {
        query: Some(query.to_owned()),
        time_zone: None,
        snapshot_at: None,
    }
}

fn oids(result: &identity_application::audit::AuditEventPageResult) -> Vec<Uuid> {
    result
        .items
        .iter()
        .map(|item| item.event.oid.as_uuid())
        .collect()
}

#[tokio::test]
#[ignore = "requires explicitly configured PostgreSQL test database"]
async fn postgres_audit_query_supports_lucene_time_zones_enums_and_frozen_cursors() {
    isolated(|db| async move {
        let actor_user_oid = Uuid::new_v4();
        let actor_client_oid = Uuid::new_v4();
        let target_user_oid = Uuid::new_v4();

        let e1_oid = Uuid::new_v4();
        let e2_oid = Uuid::new_v4();
        let e3_oid = Uuid::new_v4();
        let e4_oid = Uuid::new_v4();

        // Fixed time stamps lie well before `now` so the recent e4 row never
        // falls into their calendar days. They straddle 2025-03-10 UTC vs
        // Asia/Shanghai (+08:00):
        // - e1: 2025-03-09T16:30:00Z = 2025-03-10 00:30:00+08:00 (Mar 10 in Shanghai, Mar 9 in UTC)
        // - e2: 2025-03-10T15:30:00Z = 2025-03-10 23:30:00+08:00 (Mar 10 in both)
        // - e3: 2025-03-10T16:30:00Z = 2025-03-11 00:30:00+08:00 (Mar 11 in Shanghai, Mar 10 in UTC)
        // - e4: now - 10s, a failed sign-in with no failure-free nullable columns
        let recent = (Utc::now() - Duration::seconds(10)).to_rfc3339();

        sql(
            &db,
            &format!(
                r#"
                INSERT INTO client (oid, protocol, name, built_in, enabled, version)
                VALUES ('{actor_client_oid}', 'openid_connect', 'Batch Lookup App', false, true, gen_random_uuid());
                INSERT INTO client_openid_connect (client_id, grant_types, token_endpoint_auth_methods)
                SELECT id, '["client_credentials"]'::jsonb, '["client_secret_basic"]'::jsonb
                FROM client WHERE oid = '{actor_client_oid}';

                INSERT INTO audit (
                    oid, occurred_at, category, action, outcome, failure_reason,
                    actor_kind, actor_oid, actor_label, target_kind, target_oid, target_label,
                    client_oid, auth_methods, ip_address, user_agent, request_id, trace_id, changes
                ) VALUES
                (
                    '{e1_oid}', '2025-03-09T16:30:00Z', 'management', 'user_create', 'success', NULL,
                    'user', '{actor_user_oid}', 'operator', 'user', '{target_user_oid}', 'alice',
                    NULL, NULL, NULL, NULL, 'req-alpha', 'trace-alpha',
                    '[{{"field":"username","type":"value","new":"alice"}}]'
                ),
                (
                    '{e2_oid}', '2025-03-10T15:30:00Z', 'management', 'user_update', 'success', NULL,
                    'client', '{actor_client_oid}', 'Batch Lookup App', 'user', '{target_user_oid}', 'Alice',
                    NULL, NULL, NULL, NULL, 'req-beta', 'trace-beta', NULL
                ),
                (
                    '{e3_oid}', '2025-03-10T16:30:00Z', 'management', 'client_update', 'success', NULL,
                    'system', NULL, NULL, 'client', '{actor_client_oid}', 'Batch Lookup App',
                    NULL, NULL, NULL, NULL, 'req-gamma', NULL, NULL
                ),
                (
                    '{e4_oid}', '{recent}', 'sign_in', 'sign_in', 'failure', 'invalid_credential',
                    'anonymous', NULL, NULL, 'user', '{target_user_oid}', 'alice',
                    '{actor_client_oid}', '["password"]', '203.0.113.7', 'Mozilla/5.0 Test', NULL, NULL, NULL
                );
                "#
            ),
        )
        .await;

        let repo = Arc::new(AuditQueryRepositoryImpl::new(db.clone()));
        let service = AuditQueryService::new(repo.clone(), Arc::new(PassthroughTestProtector));

        // 1. Time-zone-aware calendar date filtering
        let shanghai = service
            .list_events(AuditEventPageRequest {
                time_zone: Some("Asia/Shanghai".to_owned()),
                ..page("occurredAt:2025-03-10")
            })
            .await
            .unwrap();
        assert_eq!(oids(&shanghai), vec![e2_oid, e1_oid]);
        let utc = service
            .list_events(AuditEventPageRequest {
                time_zone: Some("UTC".to_owned()),
                ..page("occurredAt:2025-03-10")
            })
            .await
            .unwrap();
        assert_eq!(oids(&utc), vec![e3_oid, e2_oid]);

        // 2. NOT over a nullable column keeps rows where it is NULL
        let not_failed = oids(&service.list_events(page("NOT failureReason:invalid_credential")).await.unwrap());
        assert_eq!(not_failed, vec![e3_oid, e2_oid, e1_oid]);

        // 3. Enumerated values ignore letter case; labels and request facts match case-insensitively
        assert_eq!(service.count_events(count("outcome:FAILURE")).await.unwrap(), 1);
        assert_eq!(service.count_events(count("action:USER_*")).await.unwrap(), 2);
        assert_eq!(service.count_events(count("action:client_?pdate")).await.unwrap(), 1);
        assert_eq!(service.count_events(count("targetLabel:ALICE")).await.unwrap(), 3);
        assert_eq!(service.count_events(count("ipAddress:203.0.113.*")).await.unwrap(), 1);
        assert_eq!(service.count_events(count("authMethod:password")).await.unwrap(), 1);
        assert_eq!(service.count_events(count(&format!("client:{actor_client_oid}"))).await.unwrap(), 1);
        assert_eq!(service.count_events(count(&actor_user_oid.to_string())).await.unwrap(), 1);
        let unknown = service.count_events(count("outcome:denied")).await.unwrap_err();
        assert_eq!(unknown.code(), AuditErrorCode::QueryUnknownValue as u32);

        // 4. Relay Global IDs and the category field
        let target_gid = encode::<kind::User>(target_user_oid);
        let by_target = service
            .list_events(page(&format!("target:{target_gid} AND action:user_*")))
            .await
            .unwrap();
        assert_eq!(oids(&by_target), vec![e2_oid, e1_oid]);
        let sign_ins = service.list_events(page("category:sign_in")).await.unwrap();
        assert_eq!(oids(&sign_ins), vec![e4_oid]);

        // 5. Bidirectional Relay keyset pagination + frozen snapshot_at + filter mismatch rejection
        let asc = AuditEventOrder {
            field: AuditEventOrderField::OccurredAt,
            direction: AuditEventOrderDirection::Asc,
        };
        let range = AuditEventPageRequest {
            time_zone: Some("UTC".to_owned()),
            order: asc,
            first: Some(2),
            ..page("occurredAt:[2025-03-09T00:00:00Z TO now]")
        };
        let p1 = service.list_events(range.clone()).await.unwrap();
        assert_eq!(oids(&p1), vec![e1_oid, e2_oid]);
        assert!(!p1.has_previous_page);
        assert!(p1.has_next_page);

        let p2 = service
            .list_events(AuditEventPageRequest {
                after: Some(p1.items[1].cursor.clone()),
                ..range.clone()
            })
            .await
            .unwrap();
        assert_eq!(oids(&p2), vec![e3_oid, e4_oid]);
        assert!(p2.has_previous_page);
        assert!(!p2.has_next_page);
        assert_eq!(p1.snapshot_at.timestamp_micros(), p2.snapshot_at.timestamp_micros());

        let back_to_p1 = service
            .list_events(AuditEventPageRequest {
                first: None,
                last: Some(2),
                before: Some(p2.items[0].cursor.clone()),
                ..range.clone()
            })
            .await
            .unwrap();
        assert_eq!(oids(&back_to_p1), vec![e1_oid, e2_oid]);
        assert!(!back_to_p1.has_previous_page);
        assert!(back_to_p1.has_next_page);

        // A cursor cannot move to another query or time zone.
        for other in [
            AuditEventPageRequest { query: Some("action:user_*".to_owned()), ..range.clone() },
            AuditEventPageRequest { time_zone: Some("Asia/Shanghai".to_owned()), ..range.clone() },
        ] {
            let mismatch = service
                .list_events(AuditEventPageRequest {
                    after: Some(p1.items[1].cursor.clone()),
                    ..other
                })
                .await
                .unwrap_err();
            assert_eq!(mismatch.code(), AuditErrorCode::InvalidCursor as u32);
        }

        // 6. Stored rows decode into typed events
        let found = service.find_event(AuditEventOid::from_uuid(e1_oid)).await.unwrap().unwrap();
        assert_eq!(found.action, AuditAction::UserCreate);
        assert_eq!(found.actor.kind, AuditActorKind::User);
        assert_eq!(found.target.as_ref().and_then(|target| target.label.as_deref()), Some("alice"));
        assert_eq!(found.changes[0].field, AuditField::Username);
        let failed = service.find_event(AuditEventOid::from_uuid(e4_oid)).await.unwrap().unwrap();
        assert_eq!(failed.outcome, AuditOutcome::Failure);
        assert_eq!(failed.client_oid, Some(actor_client_oid));
        assert_eq!(failed.ip_address.as_deref(), Some("203.0.113.7"));

        let client_repo = ClientManagementRepositoryImpl::new(db.clone());
        let clients = client_repo
            .find_clients(vec![actor_client_oid, Uuid::new_v4()])
            .await
            .unwrap();
        assert_eq!(clients.len(), 1);
        assert_eq!(clients[0].oid, actor_client_oid);
        assert_eq!(clients[0].name, "Batch Lookup App");
    })
    .await;
}

#[tokio::test]
#[ignore = "requires explicitly configured PostgreSQL test database"]
async fn postgres_audit_writer_snapshots_labels_and_request_context_inside_the_transaction() {
    isolated(|db| async move {
        let user_oid = Uuid::new_v4();
        let role_oid = Uuid::new_v4();
        sql(
            &db,
            &format!(
                r#"
                INSERT INTO "user" (oid,name,name_normalized,email,email_normalized)
                VALUES ('{user_oid}','operator','operator','operator@example.test','operator@example.test');
                INSERT INTO role (oid,name,names) VALUES ('{role_oid}','Auditors','{{}}');
                "#
            ),
        )
        .await;

        let request = AuditRequestContext {
            ip_address: Some("2001:db8::1".parse().unwrap()),
            user_agent: Some("Mozilla/5.0 Test".to_owned()),
        };
        audit::with_request(request, async {
            let txn = db.begin().await.unwrap();
            audit::record(
                &txn,
                AuditRecord::success(AuditAction::RoleUpdate, role_oid)
                    .actor(AuditActor::user(user_oid))
                    .with_changes(|changes| {
                        changes.diff(AuditField::Name, "Readers", "Auditors");
                    }),
            )
            .await
            .unwrap();
            txn.commit().await.unwrap();

            // A rolled-back change leaves no audit record behind.
            let txn = db.begin().await.unwrap();
            audit::record(&txn, AuditRecord::success(AuditAction::RoleDisable, role_oid))
                .await
                .unwrap();
            txn.rollback().await.unwrap();
        })
        .await;

        let stored = row(
            &db,
            &format!("SELECT count(*)::bigint AS n FROM audit WHERE target_oid = '{role_oid}'"),
        )
        .await;
        assert_eq!(stored.try_get::<i64>("", "n").unwrap(), 1);

        let repo = AuditQueryRepositoryImpl::new(db.clone());
        let service = AuditQueryService::new(Arc::new(repo), Arc::new(PassthroughTestProtector));
        let result = service.list_events(page(&format!("target:{role_oid}"))).await.unwrap();
        let event = &result.items[0].event;
        assert_eq!(event.category, AuditCategory::Management);
        assert_eq!(event.actor.label.as_deref(), Some("operator"));
        assert_eq!(event.target.as_ref().and_then(|target| target.label.as_deref()), Some("Auditors"));
        assert_eq!(event.ip_address.as_deref(), Some("2001:db8::1"));
        assert_eq!(event.user_agent.as_deref(), Some("Mozilla/5.0 Test"));
        assert!(matches!(
            &event.changes[0].value,
            AuditChangeValue::Value { old: Some(old), new: Some(new) }
                if *old == json!("Readers") && *new == json!("Auditors")
        ));
    })
    .await;
}

#[tokio::test]
#[ignore = "requires explicitly configured PostgreSQL test database"]
async fn postgres_audit_query_rejects_rows_with_unknown_enum_values() {
    isolated(|db| async move {
        let oid = Uuid::new_v4();
        sql(
            &db,
            &format!(
                "INSERT INTO audit (oid, category, action, outcome, actor_kind) \
                 VALUES ('{oid}', 'management', 'retired_action', 'success', 'system')"
            ),
        )
        .await;
        let repo = AuditQueryRepositoryImpl::new(db.clone());
        let error = repo
            .find_event(AuditEventOid::from_uuid(oid))
            .await
            .unwrap_err();
        assert!(matches!(error, AuditQueryRepositoryError::CorruptRecord));
    })
    .await;
}

#[tokio::test]
#[ignore = "requires explicitly configured PostgreSQL test database"]
async fn postgres_token_replay_names_the_presenting_client_and_the_token_owner() {
    use identity_domain::client_authorization::repository::ClientAuthorizationRepository;
    use identity_infrastructure::database::repository::client_authorization::ClientAuthorizationRepositoryImpl;

    isolated(|db| async move {
        let user_oid = Uuid::new_v4();
        let client_oid = Uuid::new_v4();
        let code_oid = Uuid::new_v4();
        sql(
            &db,
            &format!(
                r#"
                INSERT INTO "user" (oid,name,name_normalized,email,email_normalized)
                VALUES ('{user_oid}','replayed','replayed','replayed@example.test','replayed@example.test');
                INSERT INTO client (oid,name,protocol) VALUES ('{client_oid}','Replay App','openid_connect');
                INSERT INTO client_authorization (oid,client_id,type,data,expires_at)
                  SELECT '{code_oid}',id,'authorization_code','{{"user_oid":"{user_oid}"}}',now()+interval '1 minute'
                  FROM client WHERE oid='{client_oid}';
                "#
            ),
        )
        .await;

        ClientAuthorizationRepositoryImpl::new(db.clone())
            .revoke_access_tokens_for_authorization_code(code_oid)
            .await
            .unwrap();

        let service = AuditQueryService::new(
            Arc::new(AuditQueryRepositoryImpl::new(db.clone())),
            Arc::new(PassthroughTestProtector),
        );
        let result = service.list_events(page("action:token_replay")).await.unwrap();
        assert_eq!(result.items.len(), 1);
        let event = &result.items[0].event;
        assert_eq!(event.outcome, AuditOutcome::Failure);
        assert_eq!(event.actor.kind, AuditActorKind::Client);
        assert_eq!(event.actor.label.as_deref(), Some("Replay App"));
        assert_eq!(event.client_oid, Some(client_oid));
        let target = event.target.as_ref().unwrap();
        assert_eq!(target.oid, user_oid);
        assert_eq!(target.label.as_deref(), Some("replayed"));
    })
    .await;
}

#[tokio::test]
#[ignore = "requires explicitly configured PostgreSQL test database"]
async fn postgres_identifier_rejection_is_audited_without_keeping_the_identifier() {
    use identity_domain::{audit::AuditFailureReason, auth::repository::LoginRepository};
    use identity_infrastructure::database::repository::login::LoginRepositoryImpl;

    isolated(|db| async move {
        let client_oid = Uuid::new_v4();
        let authorization_oid = Uuid::new_v4();
        let login_oid = Uuid::new_v4();
        sql(
            &db,
            &format!(
                r#"
                INSERT INTO client (oid,name,protocol) VALUES ('{client_oid}','Portal','openid_connect');
                INSERT INTO client_authorization (oid,client_id,type,data,expires_at)
                  SELECT '{authorization_oid}',id,'authorization_code','{{}}',now()+interval '1 minute'
                  FROM client WHERE oid='{client_oid}';
                INSERT INTO login (oid,client_id,client_authorization_id,status,expires_at)
                  SELECT '{login_oid}',c.id,a.id,'created',now()+interval '5 minutes'
                  FROM client c, client_authorization a
                  WHERE c.oid='{client_oid}' AND a.oid='{authorization_oid}';
                "#
            ),
        )
        .await;

        audit::with_request(
            AuditRequestContext {
                ip_address: Some("203.0.113.9".parse().unwrap()),
                user_agent: Some("probe/1.0".to_owned()),
            },
            LoginRepositoryImpl::new(db.clone()).record_identification_failure(
                login_oid,
                None,
                AuditFailureReason::UnknownAccount,
            ),
        )
        .await
        .unwrap();

        let service = AuditQueryService::new(
            Arc::new(AuditQueryRepositoryImpl::new(db.clone())),
            Arc::new(PassthroughTestProtector),
        );
        let result = service
            .list_events(page("action:sign_in AND failureReason:unknown_account"))
            .await
            .unwrap();
        assert_eq!(result.items.len(), 1);
        let event = &result.items[0].event;
        assert_eq!(event.outcome, AuditOutcome::Failure);
        assert_eq!(event.actor.kind, AuditActorKind::Anonymous);
        assert!(event.target.is_none());
        assert_eq!(event.client_oid, Some(client_oid));
        assert_eq!(event.ip_address.as_deref(), Some("203.0.113.9"));
        assert_eq!(event.user_agent.as_deref(), Some("probe/1.0"));
        assert!(event.changes.is_empty());
    })
    .await;
}
