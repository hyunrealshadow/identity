//! PostgreSQL repository behavior checks through public persistence ports.
mod common;
#[path = "repository_behavior/effective_permission_totals.rs"]
mod effective_permission_totals;
use common::isolated;

use chrono::{Duration, Utc};
use identity_application::{
    rbac::{RbacManagementRepository, RoleFilter, RoleOrder, RoleQuery, cursor::RbacPageDirection},
    setting::{
        DynamicRegistrationSettings, LoginDomainSetting, OpenIdConnectSettings, SettingChanges,
    },
};
use identity_domain::{
    auth::{
        SessionOid,
        repository::{SessionPageDirection, SessionRepository},
    },
    client_authorization::{
        ClientAuthorizationData, ClientAuthorizationRepository, DeviceAuthorizationRepository,
        DeviceConsumeOutcome, DeviceRequestStatus, PreparedAuthorizationRecord,
    },
    openid_connect::{OpenIdConnectCredentialRepository, OpenIdConnectCredentialType},
    user::{
        MfaMethod,
        repository::{UserIdentifierUpdate, UserProfilePatch},
    },
};
use sea_orm::{ConnectionTrait, DatabaseConnection, DbBackend, Statement};
use uuid::Uuid;

use identity_infrastructure::database::{
    repository,
    repository::{
        client_authorization::ClientAuthorizationRepositoryImpl,
        device_authorization::DeviceAuthorizationRepositoryImpl,
        openid_connect_credential::OpenIdConnectCredentialRepositoryImpl,
        rbac_management::RbacManagementRepositoryImpl,
        session::SessionRepositoryImpl,
        setting::{read_setting, write_settings},
        user::UserRepositoryImpl,
    },
};

async fn sql(db: &DatabaseConnection, sql: &str) {
    db.execute_unprepared(sql).await.unwrap();
}

async fn row(db: &DatabaseConnection, sql: &str) -> sea_orm::QueryResult {
    db.query_one_raw(Statement::from_string(DbBackend::Postgres, sql.to_owned()))
        .await
        .unwrap()
        .unwrap()
}

#[tokio::test]
#[ignore = "requires explicitly configured PostgreSQL test database"]
async fn postgres_device_token_set_is_committed_once_under_concurrent_redemption() {
    isolated(|db| async move {
        let (_, owner) = user(&db, "device-owner").await;
        let (_, app) = client(&db, "device-app").await;
        let relation = Uuid::new_v4();
        let repo = DeviceAuthorizationRepositoryImpl::new(db.clone());
        let request = repo.create_device_request(app, serde_json::from_value(serde_json::json!({
            "scope": "openid offline_access", "device_code_digest": "device-digest", "user_code": "ABCDEFGH",
            "user_code_display": "ABCD-EFGH", "interval_seconds": 5, "status": "pending",
        })).unwrap(), Utc::now()+Duration::minutes(5)).await.unwrap();
        let approval = serde_json::from_value(serde_json::json!({
            "user_oid": owner.to_string(), "approved_scope": "openid offline_access", "device_authorization_oid": relation,
        })).unwrap();
        assert_eq!(repo.approve_device_request(request.oid, approval, Utc::now()).await.unwrap(), Some(relation));
        let payload = serde_json::json!({"scope": "openid offline_access", "user_oid":owner.to_string(),"device_authorization_oid":relation.to_string()});
        let records = vec![
            PreparedAuthorizationRecord { oid:Uuid::new_v4(), data:ClientAuthorizationData::AccessToken(serde_json::from_value(payload.clone()).unwrap()), expires_at:Utc::now()+Duration::minutes(5) },
            PreparedAuthorizationRecord { oid:Uuid::new_v4(), data:ClientAuthorizationData::RefreshToken(serde_json::from_value(payload).unwrap()), expires_at:Utc::now()+Duration::days(1) },
        ];
        let (first, second) = tokio::join!(
            repo.consume_device_request_with_tokens(request.oid, records.clone(), Utc::now()),
            repo.consume_device_request_with_tokens(request.oid, records.clone(), Utc::now()),
        );
        let outcomes = [first.unwrap(), second.unwrap()];
        assert_eq!(outcomes.iter().filter(|&&o|o==DeviceConsumeOutcome::Consumed).count(),1);
        assert_eq!(outcomes.iter().filter(|&&o|o==DeviceConsumeOutcome::NotRedeemable).count(),1);
        assert_eq!(repo.consume_device_request_with_tokens(request.oid,records,Utc::now()).await.unwrap(),DeviceConsumeOutcome::NotRedeemable);
        let stored = repo.find_device_request_by_oid(request.oid).await.unwrap().unwrap();
        assert!(stored.completed_at.is_some());
        let ClientAuthorizationData::DeviceAuthorizationRequest(data) = stored.data else {panic!("wrong artifact kind")};
        assert_eq!(data.status,DeviceRequestStatus::Consumed);
        let count:i64 = row(&db,"SELECT count(*)::bigint n FROM client_authorization WHERE type IN ('access_token','refresh_token')").await.try_get("","n").unwrap();
        assert_eq!(count,2,"replay must not issue another token set");
    }).await;
}

async fn user(db: &DatabaseConnection, name: &str) -> (i64, Uuid) {
    let oid = Uuid::new_v4();
    let row = row(db, &format!(r#"INSERT INTO "user"(oid,name,name_normalized,email,email_normalized,email_verified,preferences)
        VALUES('{oid}','{name}','{name}','{name}@example.test','{name}@example.test',true,
        '{{"theme":"dark","compact_navigation":true}}') RETURNING id"#)).await;
    (row.try_get("", "id").unwrap(), oid)
}

async fn client(db: &DatabaseConnection, name: &str) -> (i64, Uuid) {
    let oid = Uuid::new_v4();
    let id = row(db, &format!("INSERT INTO client(oid,name,protocol) VALUES('{oid}','{name}','openid_connect') RETURNING id"))
        .await.try_get("", "id").unwrap();
    sql(
        db,
        &format!("INSERT INTO client_openid_connect(client_id) VALUES({id})"),
    )
    .await;
    (id, oid)
}

#[tokio::test]
#[ignore = "requires explicitly configured PostgreSQL test database"]
async fn postgres_par_consumption_checks_lifecycle_owner_and_replay() {
    isolated(|db| async move {
        let (id, owner) = client(&db, "owner").await;
        let (_, other) = client(&db, "other").await;
        for (digest, kind, expiry, completed, revoked, expired) in [
            ("valid", "pushed_authorization_request", "1 day", "NULL", "NULL", false),
            ("expired", "pushed_authorization_request", "-1 day", "NULL", "NULL", false),
            ("completed", "pushed_authorization_request", "1 day", "now()", "NULL", false),
            ("revoked", "pushed_authorization_request", "1 day", "NULL", "now()", false),
            ("marked", "pushed_authorization_request", "1 day", "NULL", "NULL", true),
            ("wrong-type", "access_token", "1 day", "NULL", "NULL", false),
        ] {
            sql(&db, &format!("INSERT INTO client_authorization(client_id,type,data,expires_at,completed_at,revoked_at,expired)
                VALUES({id},'{kind}','{{\"request_uri_digest\":\"{digest}\",\"parameters\":{{\"response_type\":\"code\",\"client_id\":\"{owner}\",\"scope\":\"openid\",\"redirect_uri\":\"https://app.example/callback\",\"state\":\"test-state\"}}}}',
                now()+interval '{expiry}',{completed},{revoked},{expired})")).await;
        }
        let repo = ClientAuthorizationRepositoryImpl::new(db.clone());
        assert!(repo.consume_pushed_authorization_request("valid", other, Utc::now()).await.unwrap().is_none());
        for digest in ["expired", "completed", "revoked", "marked", "wrong-type"] {
            assert!(repo.consume_pushed_authorization_request(digest, owner, Utc::now()).await.unwrap().is_none(), "{digest}");
        }
        let now = Utc::now();
        let (a, b) = tokio::join!(repo.consume_pushed_authorization_request("valid", owner, now), repo.consume_pushed_authorization_request("valid", owner, now));
        let consumed: Vec<_> = [a.unwrap(), b.unwrap()].into_iter().flatten().collect();
        assert_eq!(consumed.len(), 1, "exactly one concurrent redemption succeeds");
        assert_eq!(consumed[0].parameters.scope, "openid");
        assert!(repo.consume_pushed_authorization_request("valid", owner, now).await.unwrap().is_none());
    }).await;
}

#[tokio::test]
#[ignore = "requires explicitly configured PostgreSQL test database"]
async fn postgres_consent_isolated_by_user_client_and_resource() {
    isolated(|db| async move {
        let (a, alice) = user(&db, "alice").await;
        let (b, bob) = user(&db, "bob").await;
        let (c, app) = client(&db, "app").await;
        let (d, other_app) = client(&db, "other-app").await;
        let resource = Uuid::new_v4();
        sql(
            &db,
            &format!(
                "INSERT INTO resource(oid,uri,name) VALUES('{resource}','urn:test:api','API');
            INSERT INTO scope(id,code,name,description,resource_id,enabled) VALUES
            (1,'openid','OpenID','',NULL,true),(2,'email','Email','',NULL,true),
            (3,'read','Read','','{resource}',true),(4,'disabled','Disabled','',NULL,false);
            INSERT INTO user_client_consent(user_id,client_id,scope_id) VALUES
            ({a},{c},1),({a},{c},3),({a},{c},4),({b},{c},2),({a},{d},2)"
            ),
        )
        .await;
        let repo = ClientAuthorizationRepositoryImpl::new(db);
        let mut actual = repo
            .user_consented_scope_names(alice, app, &["urn:test:api".into()])
            .await
            .unwrap();
        actual.sort();
        assert_eq!(actual, ["openid", "read"]);
        assert_eq!(
            repo.user_consented_scope_names(alice, app, &["urn:other".into()])
                .await
                .unwrap(),
            ["openid"]
        );
        assert_eq!(
            repo.user_consented_scope_names(bob, app, &[])
                .await
                .unwrap(),
            ["email"]
        );
        assert_eq!(
            repo.user_consented_scope_names(alice, other_app, &[])
                .await
                .unwrap(),
            ["email"]
        );
    })
    .await;
}

#[tokio::test]
#[ignore = "requires explicitly configured PostgreSQL test database"]
async fn postgres_credential_lookup_excludes_unusable_and_orders_newest() {
    isolated(|db| async move {
        let (id, app) = client(&db, "app").await;
        let (other, other_app) = client(&db, "other").await;
        let mut expected = Vec::new();
        for (client, kind, age, expiry, revoked, secret) in [
            (id,"client_secret", "2 days", "1 day", "NULL", "older"),
            (id,"client_secret", "1 day", "1 day", "NULL", "newer"),
            (id,"client_secret", "0 days", "-1 day", "NULL", "expired"),
            (id,"client_secret", "0 days", "1 day", "now()", "revoked"),
            (id,"client_public_key", "0 days", "1 day", "NULL", "wrong-type"),
            (other,"client_secret", "0 days", "1 day", "NULL", "other-client"),
        ] {
            let oid = Uuid::new_v4();
            sql(&db, &format!("INSERT INTO client_openid_connect_credential(oid,client_id,type,data,hint,created_at,expires_at,revoked_at)
                VALUES('{oid}',{client},'{kind}','{{\"secret\":\"{secret}\"}}','hint',now()-interval '{age}',now()+interval '{expiry}',{revoked})")).await;
            if secret=="older" || secret=="newer" { expected.insert(0, oid); }
        }
        let repo = OpenIdConnectCredentialRepositoryImpl::new(db);
        let found = repo.find_active_by_client_oid_and_type(app, OpenIdConnectCredentialType::ClientSecret).await.unwrap();
        assert_eq!(found.iter().map(|v|v.oid).collect::<Vec<_>>(), expected);
        let other = repo.find_active_by_client_oid_and_type(other_app, OpenIdConnectCredentialType::ClientSecret).await.unwrap();
        assert_eq!(other.len(),1);
        assert!(!expected.contains(&other[0].oid));
    }).await;
}

#[tokio::test]
#[ignore = "requires explicitly configured PostgreSQL test database"]
async fn postgres_role_membership_filters_before_pagination() {
    isolated(|db| async move {
        let scope = Uuid::new_v4();
        sql(&db, &format!("INSERT INTO scope(id,oid,code,name,description) VALUES(1,'{scope}','read','Read','')")).await;
        for (id, name, matching) in [(1,"A unrelated",false),(2,"B match",true),(3,"C unrelated",false),(4,"D match",true)] {
            sql(&db, &format!("INSERT INTO role(id,oid,name,names) VALUES({id},'{}','{name}','{{\"en-US\":\"{name}\"}}')",Uuid::new_v4())).await;
            if matching { sql(&db, &format!("INSERT INTO role_permission(oid,role_id,scope_id) VALUES('{}',{id},1)",Uuid::new_v4())).await; }
        }
        let repo = RbacManagementRepositoryImpl::new(db);
        let query = |after| RoleQuery { filter: RoleFilter { scope_oid:Some(scope.into()),..Default::default() }, order:RoleOrder::NameAsc,
            direction:RbacPageDirection::Forward,after,before:None,limit:1 };
        let first = repo.list_roles(query(None)).await.unwrap();
        assert_eq!(first.items.iter().map(|r|r.record.name.as_str()).collect::<Vec<_>>(), ["B match"]);
        assert!(first.has_next_page);
        let next = repo.list_roles(query(Some(first.items[0].sort_key.clone()))).await.unwrap();
        assert_eq!(next.items.iter().map(|r|r.record.name.as_str()).collect::<Vec<_>>(), ["D match"]);
        assert!(!next.has_next_page);
    }).await;
}

#[tokio::test]
#[ignore = "requires explicitly configured PostgreSQL test database"]
async fn postgres_session_lifecycle_and_tied_cursor_round_trip() {
    isolated(|db| async move {
        let (id, owner) = user(&db, "owner").await;
        let (other_id, _) = user(&db, "other").await;
        let mut oids = Vec::new();
        for (user, status, expiry, revoked) in [(id,"active","1 day","NULL"),(id,"active","1 day","NULL"),(id,"active","1 day","NULL"),
            (id,"active","-1 day","NULL"),(id,"active","1 day","now()"),(id,"revoked","1 day","NULL"),(other_id,"active","1 day","NULL")] {
            let oid=Uuid::new_v4();oids.push(oid);
            sql(&db, &format!("INSERT INTO session(oid,user_id,status,amr,last_active_at,expires_at,revoked_at)
                VALUES('{oid}',{user},'{status}','[]','2026-01-01T00:00:00Z',now()+interval '{expiry}',{revoked})")).await;
        }
        let repo=SessionRepositoryImpl::new(db.clone());
        let first=repo.list_active_page_by_user_oid(owner,None,None,2,SessionPageDirection::Forward).await.unwrap();
        assert_eq!(first.items.iter().map(|v|Uuid::from(v.session.oid)).collect::<Vec<_>>(), [oids[2],oids[1]]);
        assert!(first.has_next_page);assert!(!first.has_previous_page);
        let next=repo.list_active_page_by_user_oid(owner,Some(first.items[1].sort_key),None,2,SessionPageDirection::Forward).await.unwrap();
        assert_eq!(next.items.iter().map(|v|Uuid::from(v.session.oid)).collect::<Vec<_>>(), [oids[0]]);
        assert!(!next.has_next_page);assert!(next.has_previous_page);
        let back=repo.list_active_page_by_user_oid(owner,None,Some(next.items[0].sort_key),2,SessionPageDirection::Backward).await.unwrap();
        assert_eq!(back.items.iter().map(|v|v.session.oid).collect::<Vec<_>>(),first.items.iter().map(|v|v.session.oid).collect::<Vec<_>>());
        assert!(!back.has_previous_page);assert!(back.has_next_page);
        for (oid, expected) in oids[..6].iter().zip([true,true,true,false,false,false]) {
            assert_eq!(repo.touch_active_by_oid(SessionOid(*oid)).await.unwrap(),expected);
            let timestamp:chrono::DateTime<chrono::FixedOffset>=row(&db,&format!("SELECT last_active_at FROM session WHERE oid='{oid}'")).await.try_get("","last_active_at").unwrap();
            assert_eq!(timestamp>"2026-01-01T00:00:00Z".parse::<chrono::DateTime<Utc>>().unwrap(),expected);
        }
        assert!(!repo.touch_active_by_oid(SessionOid(Uuid::new_v4())).await.unwrap());
    }).await;
}

#[tokio::test]
#[ignore = "requires explicitly configured PostgreSQL test database"]
async fn postgres_settings_upsert_preserves_distinct_keys_without_duplicates() {
    isolated(|db| async move {
        for (enabled, domain) in [
            (true, "https://first.example"),
            (false, "https://second.example"),
        ] {
            let changes = SettingChanges::default()
                .set_section_field(
                    &OpenIdConnectSettings {
                        dynamic_registration: DynamicRegistrationSettings { enabled },
                        ..Default::default()
                    },
                    "dynamic_registration.enabled",
                )
                .unwrap()
                .set::<LoginDomainSetting>(&Some(domain.to_owned()))
                .unwrap();
            write_settings(&db, changes).await.unwrap();
            assert_eq!(
                read_setting::<LoginDomainSetting, _>(&db).await.unwrap(),
                Some(domain.to_owned())
            );
            let actual = repository::setting::read_section::<OpenIdConnectSettings, _>(&db)
                .await
                .unwrap();
            assert_eq!(actual.dynamic_registration.enabled, enabled);
        }
        let count: i64 = row(&db, "SELECT count(*)::bigint n FROM setting")
            .await
            .try_get("", "n")
            .unwrap();
        assert_eq!(
            count, 2,
            "upsert must update existing keys instead of appending duplicates"
        );
    })
    .await;
}

#[tokio::test]
#[ignore = "requires explicitly configured PostgreSQL test database"]
async fn postgres_account_updates_preserve_preferences_and_reverify_changed_email() {
    isolated(|db| async move {
        let (_, oid)=user(&db,"owner").await;
        let repo=UserRepositoryImpl::new(db.clone());
        let updated=repo.update_profile(oid.into(),UserProfilePatch {preferred_mfa_method:Some(MfaMethod::Otp),..Default::default()}).await.unwrap().unwrap();
        assert_eq!(updated.preferred_mfa_method,MfaMethod::Otp);
        let prefs:serde_json::Value=row(&db,&format!("SELECT preferences FROM \"user\" WHERE oid='{oid}'")).await.try_get("","preferences").unwrap();
        assert_eq!(prefs,serde_json::json!({"theme":"dark","compact_navigation":true,"preferred_mfa_method":"otp"}));
        let unchanged=repo.update_identifier(oid.into(),UserIdentifierUpdate::Email { value:"OWNER@example.test".into(),normalized:"owner@example.test".into() }).await.unwrap().unwrap();
        assert!(unchanged.email_verified,"normalization-only changes keep verification");
        let changed=repo.update_identifier(oid.into(),UserIdentifierUpdate::Email {value:"new@example.test".into(),normalized:"new@example.test".into()}).await.unwrap().unwrap();
        assert_eq!(changed.name,"owner");assert_eq!(changed.email,"new@example.test");assert!(!changed.email_verified);
        assert_ne!(changed.version,unchanged.version);
    }).await;
}

#[tokio::test]
#[ignore = "requires explicitly configured PostgreSQL test database"]
async fn postgres_collection_totals_match_filters_without_page_limits_or_join_duplicates() {
    use identity_application::{
        rbac::{GroupFilter, GroupManagementRepository, ScopeFilter, ScopeOrder, ScopeQuery},
        user::management::{UserFilter, UserManagementRepository},
    };
    use identity_infrastructure::database::repository::{
        group_management::GroupManagementRepositoryImpl,
        user_management::UserManagementRepositoryImpl,
    };

    isolated(|db| async move {
        let (first_user, user_oid) = user(&db, "total_one").await;
        let (second_user, _) = user(&db, "totalXone").await;
        let (disabled_user, _) = user(&db, "total_two").await;
        sql(&db, &format!("UPDATE \"user\" SET enabled=false WHERE id={disabled_user}")).await;
        let users = UserManagementRepositoryImpl::new(db.clone());
        assert_eq!(users.count_users(UserFilter { query: Some("total_".into()), ..Default::default() }).await.unwrap(), 2);
        assert_eq!(users.count_users(UserFilter { query: Some("total_".into()), enabled: Some(true), ..Default::default() }).await.unwrap(), 1);
        assert_eq!(users.count_users(UserFilter { email: Some("missing@example.test".into()), ..Default::default() }).await.unwrap(), 0);

        let resource = Uuid::new_v4();
        let other_resource = Uuid::new_v4();
        let read = Uuid::new_v4();
        let role = Uuid::new_v4();
        sql(&db, &format!("INSERT INTO resource(oid,uri,name) VALUES('{resource}','urn:count:one','One'),('{other_resource}','urn:count:two','Two');
          INSERT INTO scope(id,oid,resource_id,code,name,description,enabled) VALUES
          (1,'{read}','{resource}','read','Read','',true),
          (2,'{}','{resource}','write','Write','',false),
          (3,'{}','{other_resource}','read','Read','',true),
          (4,'{}',NULL,'openid','OpenID','',true);
          INSERT INTO role(id,oid,name,names,enabled) VALUES
          (1,'{role}','Totals A','{{\"en-US\":\"Totals A\"}}',true),
          (2,'{}','Totals B','{{\"en-US\":\"Totals B\"}}',false),
          (3,'{}','Totals removed','{{\"en-US\":\"Totals removed\"}}',true);
          DELETE FROM role WHERE id=3;
          INSERT INTO role_permission(oid,role_id,scope_id) VALUES('{}',1,1),('{}',2,1);",
          Uuid::new_v4(),Uuid::new_v4(),Uuid::new_v4(),Uuid::new_v4(),Uuid::new_v4(),Uuid::new_v4(),Uuid::new_v4())).await;
        let rbac = RbacManagementRepositoryImpl::new(db.clone());
        let role_filter = RoleFilter { scope_oid: Some(read.into()), ..Default::default() };
        assert_eq!(rbac.count_roles(role_filter.clone()).await.unwrap(), 2);
        let first = rbac.list_roles(RoleQuery { filter:role_filter.clone(),order:RoleOrder::NameAsc,direction:RbacPageDirection::Forward,after:None,before:None,limit:1 }).await.unwrap();
        assert_eq!(first.items.len(), 1);
        let next = rbac.list_roles(RoleQuery { filter:role_filter.clone(),order:RoleOrder::NameAsc,direction:RbacPageDirection::Forward,after:Some(first.items[0].sort_key.clone()),before:None,limit:1 }).await.unwrap();
        assert_eq!(next.items.len(), 1);
        assert_eq!(rbac.count_roles(role_filter).await.unwrap(), 2);
        assert_eq!(rbac.count_roles(RoleFilter { enabled:Some(true),..Default::default() }).await.unwrap(), 1);
        assert_eq!(rbac.count_scopes(ScopeFilter { resource_oid:Some(resource.into()),..Default::default() }).await.unwrap(), 2);
        assert_eq!(rbac.count_scopes(ScopeFilter { api_only:true,enabled:Some(true),role_oid:Some(role.into()),..Default::default() }).await.unwrap(), 1);

        sql(&db, r#"UPDATE scope SET name='Read metadata',description='read',
          names='{"en-US":"read"}',descriptions='{"en-US":"read"}' WHERE id=2"#).await;
        for (term, expected) in [("ReAd", vec!["read"]), ("read%", vec![]), ("read_", vec![])] {
            let filter = ScopeFilter {
                query: Some(term.into()),
                resource_oid: Some(resource.into()),
                ..Default::default()
            };
            let scopes = rbac.list_scopes(ScopeQuery {
                filter: filter.clone(), order: ScopeOrder::CodeAsc,
                direction: RbacPageDirection::Forward, after: None, before: None, limit: 100,
            }).await.unwrap();
            assert_eq!(scopes.items.iter().map(|item| item.record.code.as_str()).collect::<Vec<_>>(), expected);
            assert_eq!(rbac.count_scopes(filter).await.unwrap(), expected.len() as u64);
        }

        let group = Uuid::new_v4();
        sql(&db, &format!("INSERT INTO user_group(id,oid,name,names,descriptions,enabled,deleted_at) VALUES
          (1,'{group}','Totals one','{{\"en-US\":\"Totals one\"}}','{{}}',true,NULL),
          (2,'{}','Totals two','{{\"en-US\":\"Totals two\"}}','{{}}',true,NULL),
          (3,'{}','Totals removed','{{\"en-US\":\"Totals removed\"}}','{{}}',true,now());
          INSERT INTO group_membership(oid,group_id,user_id,enabled,revoked_at,reason) VALUES
          ('{}',1,{first_user},true,NULL,''),('{}',1,{second_user},true,NULL,''),('{}',2,{first_user},false,now(),'');
          INSERT INTO group_role(oid,group_id,role_id,enabled,reason) VALUES('{}',1,1,true,''),('{}',1,2,true,''),('{}',2,1,false,'');",
          Uuid::new_v4(),Uuid::new_v4(),Uuid::new_v4(),Uuid::new_v4(),Uuid::new_v4(),Uuid::new_v4(),Uuid::new_v4(),Uuid::new_v4())).await;
        let groups = GroupManagementRepositoryImpl::new(db.clone());
        assert_eq!(groups.count_groups(GroupFilter { query:Some("Totals".into()),..Default::default() }).await.unwrap(), 2);
        assert_eq!(groups.count_groups(GroupFilter { user_oid:Some(user_oid.into()),role_oid:Some(role.into()),..Default::default() }).await.unwrap(), 1);

        let (app_id, app_oid) = client(&db, "count-app").await;
        let (other_app_id, other_app_oid) = client(&db, "count-other-app").await;
        sql(&db, &format!("INSERT INTO client_scope(client_id,scope_id) VALUES({app_id},1),({app_id},2),({other_app_id},1)")).await;
        assert_eq!(rbac.count_client_scopes(app_oid).await.unwrap(), 2);
        assert_eq!(rbac.count_client_scopes(other_app_oid).await.unwrap(), 1);
    }).await;
}

#[tokio::test]
#[ignore = "requires explicitly configured PostgreSQL test database"]
async fn postgres_client_scope_grant_separates_client_and_user_ceilings() {
    use identity_domain::{
        authorization::{ManagementAuthorityRepository, ManagementScope},
        client_authorization::AccessTokenPrincipal,
        openid_connect::resource::OAuthResourceRepository,
    };
    use identity_infrastructure::database::{
        repository::{
            authorization::AuthorizationRepositoryImpl, oauth_resource::OAuthResourceRepositoryImpl,
        },
        seed,
    };

    isolated(|db| async move {
        seed::run_all(&db).await.unwrap();
        let (client_id, client_oid) = client(&db, "machine-app").await;
        let resource = Uuid::new_v4();
        sql(&db, &format!("INSERT INTO resource(oid,uri,name) VALUES('{resource}','urn:orders','Orders');
          INSERT INTO scope(oid,resource_id,code,name,description,enabled) VALUES('{}','{resource}','orders.read','Read orders','',true);
          INSERT INTO client_scope(client_id,scope_id) SELECT {client_id}, id FROM scope WHERE code IN ('orders.read','management.user.read') AND resource_id IS NOT NULL;",
          Uuid::new_v4())).await;

        let resources = OAuthResourceRepositoryImpl::new(db.clone());
        let authority = AuthorizationRepositoryImpl::new(db.clone());
        let codes = |principal| {
            let resources = &resources;
            async move { resources.client_scope_codes(client_oid, "urn:orders", principal).await.unwrap().unwrap() }
        };

        // Assigned rows bound user-delegated requests only.
        assert_eq!(codes(AccessTokenPrincipal::User).await, vec!["orders.read".to_owned()]);
        assert!(codes(AccessTokenPrincipal::Client).await.is_empty());
        let machine = authority.find_client_scope_authority(client_oid).await.unwrap().unwrap();
        assert!(machine.permissions.is_empty());
        let before = resources.client_authority_fingerprint(client_oid).await.unwrap().unwrap();

        sql(&db, &format!("UPDATE client_scope SET client_granted=true WHERE client_id={client_id}")).await;

        assert_eq!(codes(AccessTokenPrincipal::Client).await, vec!["orders.read".to_owned()]);
        let machine = authority.find_client_scope_authority(client_oid).await.unwrap().unwrap();
        assert_eq!(machine.permissions.into_iter().collect::<Vec<_>>(), vec![ManagementScope::from_name("management.user.read").unwrap()]);
        // Granting the client itself changes its boundary, so issued artifacts
        // bound to the previous fingerprint stop validating.
        let after = resources.client_authority_fingerprint(client_oid).await.unwrap().unwrap();
        assert_ne!(before, after);
    })
    .await;
}

#[tokio::test]
#[ignore = "requires explicitly configured PostgreSQL test database"]
async fn postgres_relation_node_batches_return_only_existing_records() {
    use identity_application::user::management::UserManagementRepository;
    use identity_domain::{rbac::RoleOid, user::UserOid};
    use identity_infrastructure::database::repository::user_management::UserManagementRepositoryImpl;

    isolated(|db| async move {
        let (_, first_user) = user(&db, "batch_one").await;
        let (_, second_user) = user(&db, "batch_two").await;
        let (first_role, second_role) = (Uuid::new_v4(), Uuid::new_v4());
        sql(&db, &format!("INSERT INTO role(oid,name,names) VALUES('{first_role}','First','{{}}'),('{second_role}','Second','{{}}')")).await;
        let missing = Uuid::new_v4();

        let rbac = RbacManagementRepositoryImpl::new(db.clone());
        let mut roles = rbac
            .find_roles(vec![RoleOid(first_role), RoleOid(missing), RoleOid(second_role)])
            .await
            .unwrap()
            .into_iter()
            .map(|role| (Uuid::from(role.oid), role.name))
            .collect::<Vec<_>>();
        roles.sort();
        let mut expected = vec![(first_role, "First".to_owned()), (second_role, "Second".to_owned())];
        expected.sort();
        assert_eq!(roles, expected);
        assert!(rbac.find_roles(Vec::new()).await.unwrap().is_empty());

        let users = UserManagementRepositoryImpl::new(db.clone());
        let mut found = users
            .find_users(vec![UserOid(second_user), UserOid(missing), UserOid(first_user)])
            .await
            .unwrap()
            .into_iter()
            .map(|record| record.user.oid.0)
            .collect::<Vec<_>>();
        found.sort();
        let mut expected = vec![first_user, second_user];
        expected.sort();
        assert_eq!(found, expected);
        assert!(users.find_users(Vec::new()).await.unwrap().is_empty());
    })
    .await;
}
