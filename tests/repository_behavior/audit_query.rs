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
        AuditEventOid, AuditEventOrder, AuditEventOrderDirection, AuditEventOrderField,
        AuditQueryRepository,
    },
    data_protection::DataProtectionError,
    global_id::{encode, kind},
};
use identity_infrastructure::database::repository::{
    audit_query::AuditQueryRepositoryImpl, client_management::ClientManagementRepositoryImpl,
};
use uuid::Uuid;

use super::{isolated, sql};

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

#[tokio::test]
#[ignore = "requires explicitly configured PostgreSQL test database"]
async fn postgres_audit_query_supports_lucene_time_zones_null_not_and_frozen_cursors() {
    isolated(|db| async move {
        let actor_user_oid = Uuid::new_v4();
        let actor_client_oid = Uuid::new_v4();
        let target_user_oid = Uuid::new_v4();
        let resource_oid = Uuid::new_v4();
        let subject_oid = Uuid::new_v4();

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
        // - e4: now - 10s (nullable action & reason left NULL)
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

                INSERT INTO security_audit (
                    oid, occurred_at, transaction_id, resource_type, resource_oid, subject_oid,
                    operation, status, actor_type, actor_oid, action, target_type, target_oid,
                    reason, request_id, trace_id, event_kind
                ) VALUES
                (
                    '{e1_oid}', '2025-03-09T16:30:00Z', 101, 'user', '{resource_oid}', '{subject_oid}',
                    'mutation', 'success', 'user', '{actor_user_oid}', 'user.create', 'user', '{target_user_oid}',
                    'Provisioned Operator', 'req-alpha', 'trace-alpha', 'semantic'
                ),
                (
                    '{e2_oid}', '2025-03-10T15:30:00Z', 102, 'user', '{resource_oid}', NULL,
                    'mutation', 'success', 'client', '{actor_client_oid}', 'user.delete', 'user', '{target_user_oid}',
                    'Cleanup Inactive', 'req-beta', 'trace-beta', 'semantic'
                ),
                (
                    '{e3_oid}', '2025-03-10T16:30:00Z', 103, 'client', '{actor_client_oid}', NULL,
                    'mutation', 'success', 'system', '{nil}', 'client.update', 'client', '{actor_client_oid}',
                    'bootstrap reconciliation', 'req-gamma', NULL, 'semantic'
                ),
                (
                    '{e4_oid}', '{recent}', 104, 'session', '{resource_oid}', NULL,
                    'authorization', NULL, 'unknown', NULL, NULL, NULL, NULL,
                    NULL, NULL, NULL, 'semantic'
                );
                "#,
                nil = Uuid::nil()
            ),
        )
        .await;

        let repo = Arc::new(AuditQueryRepositoryImpl::new(db.clone()));
        let service = AuditQueryService::new(repo.clone(), Arc::new(PassthroughTestProtector));

        // 1. Time-zone-aware calendar date filtering
        let shanghai_nov20 = service
            .list_events(AuditEventPageRequest {
                query: Some("occurredAt:2025-03-10".to_owned()),
                time_zone: Some("Asia/Shanghai".to_owned()),
                order: AuditEventOrder::default(),
                first: Some(20),
                after: None,
                last: None,
                before: None,
            })
            .await
            .unwrap();
        let shanghai_oids: Vec<Uuid> = shanghai_nov20.items.iter().map(|i| i.event.oid.as_uuid()).collect();
        assert_eq!(shanghai_oids, vec![e2_oid, e1_oid]);

        let utc_nov20 = service
            .list_events(AuditEventPageRequest {
                query: Some("occurredAt:2025-03-10".to_owned()),
                time_zone: Some("UTC".to_owned()),
                order: AuditEventOrder::default(),
                first: Some(20),
                after: None,
                last: None,
                before: None,
            })
            .await
            .unwrap();
        let utc_oids: Vec<Uuid> = utc_nov20.items.iter().map(|i| i.event.oid.as_uuid()).collect();
        assert_eq!(utc_oids, vec![e3_oid, e2_oid]);

        // 2. NOT over nullable columns must still keep rows whose action/reason is NULL
        let not_create = service
            .list_events(AuditEventPageRequest {
                query: Some("NOT action:user.create".to_owned()),
                time_zone: None,
                order: AuditEventOrder::default(),
                first: Some(20),
                after: None,
                last: None,
                before: None,
            })
            .await
            .unwrap();
        let not_create_oids: Vec<Uuid> = not_create.items.iter().map(|i| i.event.oid.as_uuid()).collect();
        assert!(not_create_oids.contains(&e4_oid), "row with NULL action must match NOT");
        assert!(not_create_oids.contains(&e3_oid));
        assert!(not_create_oids.contains(&e2_oid));
        assert!(!not_create_oids.contains(&e1_oid));

        // 3. Prefix, wildcard, Relay Global ID, and FreeText search
        let target_gid = encode::<kind::User>(target_user_oid);
        let global_id_matches = service
            .list_events(AuditEventPageRequest {
                query: Some(format!("target:{target_gid} AND action:user.*")),
                time_zone: None,
                order: AuditEventOrder::default(),
                first: Some(20),
                after: None,
                last: None,
                before: None,
            })
            .await
            .unwrap();
        assert_eq!(
            global_id_matches.items.iter().map(|i| i.event.oid.as_uuid()).collect::<Vec<_>>(),
            vec![e2_oid, e1_oid]
        );

        let wildcard_matches = service
            .count_events(AuditEventCountRequest {
                query: Some("action:client.?pdate".to_owned()),
                time_zone: None,
                snapshot_at: None,
            })
            .await
            .unwrap();
        assert_eq!(wildcard_matches, 1);

        let free_text_uuid = service
            .count_events(AuditEventCountRequest {
                query: Some(actor_user_oid.to_string()),
                time_zone: None,
                snapshot_at: None,
            })
            .await
            .unwrap();
        assert_eq!(free_text_uuid, 1);

        // 4. Bidirectional Relay keyset pagination + frozen snapshot_at + filter mismatch rejection
        let asc = AuditEventOrder {
            field: AuditEventOrderField::OccurredAt,
            direction: AuditEventOrderDirection::Asc,
        };
        let p1 = service
            .list_events(AuditEventPageRequest {
                query: Some("occurredAt:[2025-03-09T00:00:00Z TO now]".to_owned()),
                time_zone: Some("UTC".to_owned()),
                order: asc,
                first: Some(2),
                after: None,
                last: None,
                before: None,
            })
            .await
            .unwrap();
        assert_eq!(p1.items.iter().map(|i| i.event.oid.as_uuid()).collect::<Vec<_>>(), vec![e1_oid, e2_oid]);
        assert!(!p1.has_previous_page);
        assert!(p1.has_next_page);

        let p2 = service
            .list_events(AuditEventPageRequest {
                query: Some("occurredAt:[2025-03-09T00:00:00Z TO now]".to_owned()),
                time_zone: Some("UTC".to_owned()),
                order: asc,
                first: Some(2),
                after: Some(p1.items[1].cursor.clone()),
                last: None,
                before: None,
            })
            .await
            .unwrap();
        assert_eq!(p2.items.iter().map(|i| i.event.oid.as_uuid()).collect::<Vec<_>>(), vec![e3_oid, e4_oid]);
        assert!(p2.has_previous_page);
        assert!(!p2.has_next_page);
        assert_eq!(p1.snapshot_at.timestamp_micros(), p2.snapshot_at.timestamp_micros());

        let back_to_p1 = service
            .list_events(AuditEventPageRequest {
                query: Some("occurredAt:[2025-03-09T00:00:00Z TO now]".to_owned()),
                time_zone: Some("UTC".to_owned()),
                order: asc,
                first: None,
                after: None,
                last: Some(2),
                before: Some(p2.items[0].cursor.clone()),
            })
            .await
            .unwrap();
        assert_eq!(
            back_to_p1.items.iter().map(|i| i.event.oid.as_uuid()).collect::<Vec<_>>(),
            vec![e1_oid, e2_oid]
        );
        assert!(!back_to_p1.has_previous_page);
        assert!(back_to_p1.has_next_page);

        let mismatch_err = service
            .list_events(AuditEventPageRequest {
                query: Some("action:user.*".to_owned()),
                time_zone: Some("UTC".to_owned()),
                order: asc,
                first: Some(2),
                after: Some(p1.items[1].cursor.clone()),
                last: None,
                before: None,
            })
            .await
            .unwrap_err();
        assert_eq!(mismatch_err.code(), AuditErrorCode::InvalidCursor as u32);

        // 5. find_event, list_distinct_actions, and ClientManagementRepositoryImpl::find_clients
        let found = service.find_event(AuditEventOid::from_uuid(e1_oid)).await.unwrap().unwrap();
        assert_eq!(found.request_id.as_deref(), Some("req-alpha"));
        let actions = repo.list_distinct_actions().await.unwrap();
        assert_eq!(
            actions,
            vec![
                "client.update".to_owned(),
                "user.create".to_owned(),
                "user.delete".to_owned()
            ]
        );

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
