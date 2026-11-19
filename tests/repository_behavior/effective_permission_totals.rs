use super::{isolated, row, sql, user};
use identity_application::rbac::{
    AccountGroupQuery, AccountPermissionQuery, AccountRoleGrant, AccountRoleQuery,
    AuthorizationSource, EffectivePermissionOrder, EffectivePermissionQuery,
    GroupManagementRepository, GroupOrder, RbacManagementRepository, UserRoleGrant,
    UserRoleGrantQuery, UserRoleOrder, cursor::RbacPageDirection,
};
use identity_domain::{
    authorization::ManagementScope,
    openid_connect::API_RESOURCE,
    rbac::{GroupOid, RoleOid, built_in_permission_oid},
};
use identity_infrastructure::database::repository::{
    group_management::GroupManagementRepositoryImpl, rbac_management::RbacManagementRepositoryImpl,
};
use uuid::Uuid;

#[tokio::test]
#[ignore = "requires explicitly configured PostgreSQL test database"]
async fn postgres_effective_permission_totals_follow_live_union_and_relay_pages() {
    isolated(|db| async move {
        let (subject, user_oid) = user(&db, "permission-total-subject").await;
        let (_, other_user) = user(&db, "permission-total-other").await;
        let resource = Uuid::new_v4();
        let other_resource = Uuid::new_v4();
        sql(&db, &format!(r#"
            INSERT INTO resource(oid,uri,name) VALUES ('{resource}','urn:permission-total:one','One'),('{other_resource}','urn:permission-total:two','Two');
            INSERT INTO scope(id,resource_id,code,name,description,enabled)
                SELECT n, '{resource}', 'read.' || lpad(n::text,3,'0'), 'Read', '', n <> 106 FROM generate_series(1,107) n;
            INSERT INTO scope(id,resource_id,code,name,description) VALUES (108,'{other_resource}','read.other','Other','');
            INSERT INTO role(id,oid,name,enabled) VALUES (1,gen_random_uuid(),'Direct',true),(2,gen_random_uuid(),'Group',true),(3,gen_random_uuid(),'Disabled',false);
            INSERT INTO role_permission(oid,role_id,scope_id) SELECT gen_random_uuid(),1,n FROM generate_series(1,100) n;
            INSERT INTO role_permission(oid,role_id,scope_id) SELECT gen_random_uuid(),2,n FROM generate_series(1,105) n WHERE n<=5 OR n>100;
            INSERT INTO role_permission(oid,role_id,scope_id) VALUES(gen_random_uuid(),1,106),(gen_random_uuid(),3,107),(gen_random_uuid(),1,108);
            INSERT INTO user_role(oid,user_id,role_id,reason) VALUES(gen_random_uuid(),{subject},1,''),(gen_random_uuid(),{subject},3,'');
            INSERT INTO user_group(id,oid,name) VALUES(1,gen_random_uuid(),'Test group');
            INSERT INTO group_membership(oid,group_id,user_id,reason) VALUES(gen_random_uuid(),1,{subject},'');
            INSERT INTO group_role(oid,group_id,role_id,reason) VALUES(gen_random_uuid(),1,2,'');
        "#)).await;
        let repo=RbacManagementRepositoryImpl::new(db.clone());
        assert_eq!(repo.count_effective_permissions(user_oid.into(),resource.into(),None).await.unwrap(),105);
        assert_eq!(repo.count_effective_permissions(other_user.into(),resource.into(),None).await.unwrap(),0);
        assert_eq!(repo.count_effective_permissions(user_oid.into(),other_resource.into(),None).await.unwrap(),1);
        assert_eq!(repo.count_effective_permissions(user_oid.into(),resource.into(),Some(AuthorizationSource::Direct)).await.unwrap(),100);
        assert_eq!(repo.count_effective_permissions(user_oid.into(),resource.into(),Some(AuthorizationSource::Group)).await.unwrap(),10);
        let group_only=repo.list_effective_permissions(EffectivePermissionQuery {user_oid:user_oid.into(),resource_oid:resource.into(),source:Some(AuthorizationSource::Group),order:EffectivePermissionOrder::CodeAsc,direction:RbacPageDirection::Forward,after:None,before:None,limit:3}).await.unwrap();
        assert_eq!(group_only.items.iter().map(|entry|entry.record.code.as_str()).collect::<Vec<_>>(),["read.001","read.002","read.003"]);
        assert!(group_only.items.iter().all(|entry|!entry.record.group_sources.is_empty()));
        let after_overlap=repo.list_effective_permissions(EffectivePermissionQuery {after:Some(group_only.items.last().unwrap().sort_key.clone()),limit:5,..EffectivePermissionQuery {user_oid:user_oid.into(),resource_oid:resource.into(),source:Some(AuthorizationSource::Group),order:EffectivePermissionOrder::CodeAsc,direction:RbacPageDirection::Forward,after:None,before:None,limit:5}}).await.unwrap();
        assert_eq!(after_overlap.items.iter().map(|entry|entry.record.code.as_str()).collect::<Vec<_>>(),["read.004","read.005","read.101","read.102","read.103"],"group pages skip direct-only scopes");
        for order in [EffectivePermissionOrder::CodeAsc,EffectivePermissionOrder::CodeDesc] {
            let query=EffectivePermissionQuery {user_oid:user_oid.into(),resource_oid:resource.into(),source:None,order,direction:RbacPageDirection::Forward,after:None,before:None,limit:100};
            let first=repo.list_effective_permissions(query.clone()).await.unwrap();
            assert_eq!(first.items.len(),100);
            assert!(first.has_next_page && !first.has_previous_page);
            let second=repo.list_effective_permissions(EffectivePermissionQuery {after:Some(first.items.last().unwrap().sort_key.clone()),..query.clone()}).await.unwrap();
            assert_eq!(second.items.len(),5);
            assert!(!second.has_next_page && second.has_previous_page);
            let previous=repo.list_effective_permissions(EffectivePermissionQuery {direction:RbacPageDirection::Backward,before:Some(second.items[0].sort_key.clone()),..query.clone()}).await.unwrap();
            assert_eq!(previous.items.iter().map(|entry|&entry.record.code).collect::<Vec<_>>(),first.items.iter().map(|entry|&entry.record.code).collect::<Vec<_>>());
            assert!(!previous.has_previous_page && previous.has_next_page);
            assert_eq!(repo.count_effective_permissions(user_oid.into(),resource.into(),None).await.unwrap(),105);
        }
        let first=repo.list_effective_permissions(EffectivePermissionQuery {user_oid:user_oid.into(),resource_oid:resource.into(),source:None,order:EffectivePermissionOrder::CodeAsc,direction:RbacPageDirection::Forward,after:None,before:None,limit:100}).await.unwrap();
        assert_eq!(first.items[0].record.sources.len(),1);
        assert_eq!(first.items[0].record.group_sources.len(),1,"overlapping sources stay visible but do not multiply totals");
        sql(&db,"UPDATE user_group SET enabled=false WHERE id=1").await;
        assert_eq!(repo.count_effective_permissions(user_oid.into(),resource.into(),None).await.unwrap(),100);
        sql(&db,"UPDATE user_group SET enabled=true WHERE id=1; UPDATE role SET enabled=false WHERE id=1").await;
        assert_eq!(repo.count_effective_permissions(user_oid.into(),resource.into(),None).await.unwrap(),10);
        sql(&db,&format!("UPDATE resource SET enabled=false WHERE oid='{resource}'")).await;
        assert_eq!(repo.count_effective_permissions(user_oid.into(),resource.into(),None).await.unwrap(),0);
        sql(&db,&format!(r#"UPDATE resource SET enabled=true WHERE oid='{resource}'; UPDATE "user" SET enabled=false WHERE id={subject}"#)).await;
        assert_eq!(repo.count_effective_permissions(user_oid.into(),resource.into(),None).await.unwrap(),0);
        let count:i64=row(&db,"SELECT count(*)::bigint AS n FROM scope").await.try_get("","n").unwrap();
        assert_eq!(count,108,"disabled and unrelated scopes remain stored");
    }).await;
}

#[tokio::test]
#[ignore = "requires explicitly configured PostgreSQL test database"]
async fn postgres_user_role_grants_merge_direct_and_inherited_roles_by_source() {
    isolated(|db| async move {
        let (subject, user_oid) = user(&db, "role-grant-subject").await;
        sql(&db, &format!(r#"
            INSERT INTO role(id,oid,name,enabled) VALUES (1,gen_random_uuid(),'Direct',true),(2,gen_random_uuid(),'Shared',true),(3,gen_random_uuid(),'Revoked',true),(4,gen_random_uuid(),'Hidden',true);
            INSERT INTO user_role(oid,user_id,role_id,reason,created_at) VALUES(gen_random_uuid(),{subject},1,'direct',now()-interval '5 days'),(gen_random_uuid(),{subject},2,'direct',now()-interval '4 days');
            INSERT INTO user_role(oid,user_id,role_id,reason,enabled,revoked_at,created_at) VALUES(gen_random_uuid(),{subject},3,'old',false,now(),now()-interval '6 days');
            INSERT INTO user_group(id,oid,name) VALUES(1,gen_random_uuid(),'Active'),(2,gen_random_uuid(),'Disabled');
            UPDATE user_group SET enabled=false WHERE id=2;
            INSERT INTO group_membership(oid,group_id,user_id,reason,created_at) VALUES(gen_random_uuid(),1,{subject},'',now()-interval '3 days'),(gen_random_uuid(),2,{subject},'',now()-interval '3 days');
            INSERT INTO group_role(oid,group_id,role_id,reason,created_at) VALUES(gen_random_uuid(),1,2,'',now()-interval '2 days'),(gen_random_uuid(),2,4,'',now()-interval '2 days');
        "#)).await;
        let repo = RbacManagementRepositoryImpl::new(db.clone());
        let query = |source, enabled, limit| UserRoleGrantQuery {
            user_oid: user_oid.into(),
            source,
            enabled,
            order: UserRoleOrder::CreatedAtDesc,
            direction: RbacPageDirection::Forward,
            after: None,
            before: None,
            limit,
        };
        let kinds = |items: &[identity_application::rbac::UserRoleGrantPageEntry]| {
            items
                .iter()
                .map(|entry| match &entry.grant {
                    UserRoleGrant::Direct(record) => ("direct", record.enabled),
                    UserRoleGrant::Group(_) => ("group", true),
                })
                .collect::<Vec<_>>()
        };

        let all = repo.list_user_role_grants(query(None, None, 10)).await.unwrap();
        assert_eq!(
            kinds(&all.items),
            [("group", true), ("direct", true), ("direct", true), ("direct", false)],
            "a role held both ways appears once per source; disabled groups grant nothing"
        );
        let active = repo.list_user_role_grants(query(None, Some(true), 10)).await.unwrap();
        assert_eq!(active.items.len(), 3);
        let revoked = repo.list_user_role_grants(query(None, Some(false), 10)).await.unwrap();
        assert_eq!(kinds(&revoked.items), [("direct", false)], "inherited roles have no revoked history");
        let inherited = repo
            .list_user_role_grants(query(Some(AuthorizationSource::Group), None, 10))
            .await
            .unwrap();
        assert_eq!(kinds(&inherited.items), [("group", true)]);
        let direct = repo
            .list_user_role_grants(query(Some(AuthorizationSource::Direct), Some(true), 10))
            .await
            .unwrap();
        assert_eq!(kinds(&direct.items), [("direct", true), ("direct", true)]);

        let first = repo.list_user_role_grants(query(None, None, 2)).await.unwrap();
        assert!(first.has_next_page && !first.has_previous_page);
        let second = repo
            .list_user_role_grants(UserRoleGrantQuery {
                after: Some(first.items.last().unwrap().sort_key.clone()),
                ..query(None, None, 2)
            })
            .await
            .unwrap();
        assert_eq!(kinds(&second.items), [("direct", true), ("direct", false)]);
        assert!(!second.has_next_page && second.has_previous_page);
        let back = repo
            .list_user_role_grants(UserRoleGrantQuery {
                direction: RbacPageDirection::Backward,
                before: Some(second.items[0].sort_key.clone()),
                ..query(None, None, 2)
            })
            .await
            .unwrap();
        assert_eq!(
            back.items.iter().map(|entry| entry.sort_key.clone()).collect::<Vec<_>>(),
            first.items.iter().map(|entry| entry.sort_key.clone()).collect::<Vec<_>>()
        );
        assert!(!back.has_previous_page && back.has_next_page);
        assert_eq!(all.user_version, first.user_version);

        sql(&db, &format!("UPDATE group_membership SET enabled=false, revoked_at=now() WHERE user_id={subject} AND group_id=1")).await;
        let after_leave = repo.list_user_role_grants(query(Some(AuthorizationSource::Group), None, 10)).await.unwrap();
        assert!(after_leave.items.is_empty(), "leaving the group removes its roles immediately");
    })
    .await;
}

#[tokio::test]
#[ignore = "requires explicitly configured PostgreSQL test database"]
async fn postgres_account_groups_list_active_memberships_and_batch_lookup() {
    isolated(|db| async move {
        let (subject, user_oid) = user(&db, "account-group-subject").await;
        let (other, other_oid) = user(&db, "account-group-other").await;
        let g1 = Uuid::new_v4();
        let g2 = Uuid::new_v4();
        let g3 = Uuid::new_v4();
        let g_disabled = Uuid::new_v4();
        let g_deleted = Uuid::new_v4();
        let g_revoked = Uuid::new_v4();
        let g_disabled_membership = Uuid::new_v4();
        let g_other = Uuid::new_v4();
        sql(
            &db,
            &format!(
                r#"
                INSERT INTO user_group(id, oid, name, built_in, enabled, deleted_at) VALUES
                    (1, '{g1}', 'Alpha', false, true, NULL),
                    (2, '{g2}', 'Beta', true, true, NULL),
                    (3, '{g3}', 'Gamma', false, true, NULL),
                    (4, '{g_disabled}', 'Disabled', false, false, NULL),
                    (5, '{g_deleted}', 'Deleted', false, true, now()),
                    (6, '{g_revoked}', 'RevokedMembership', false, true, NULL),
                    (7, '{g_disabled_membership}', 'DisabledMembership', false, true, NULL),
                    (8, '{g_other}', 'Other', false, true, NULL);
                INSERT INTO group_membership(oid, group_id, user_id, reason, enabled, revoked_at, created_at) VALUES
                    (gen_random_uuid(), 1, {subject}, '', true, NULL, now() - interval '4 hours'),
                    (gen_random_uuid(), 2, {subject}, '', true, NULL, now() - interval '3 hours'),
                    (gen_random_uuid(), 3, {subject}, '', true, NULL, now() - interval '2 hours'),
                    (gen_random_uuid(), 4, {subject}, '', true, NULL, now() - interval '1 hour'),
                    (gen_random_uuid(), 5, {subject}, '', true, NULL, now() - interval '1 hour'),
                    (gen_random_uuid(), 6, {subject}, '', false, now(), now() - interval '1 hour'),
                    (gen_random_uuid(), 7, {subject}, '', false, NULL, now() - interval '1 hour'),
                    (gen_random_uuid(), 8, {other}, '', true, NULL, now() - interval '1 hour');
                "#
            ),
        )
        .await;

        let repo = GroupManagementRepositoryImpl::new(db.clone());
        assert!(repo.find_groups(Vec::new()).await.unwrap().is_empty());
        let found = repo
            .find_groups(vec![
                GroupOid(g1),
                GroupOid(g2),
                GroupOid(g_deleted),
                GroupOid(Uuid::new_v4()),
            ])
            .await
            .unwrap();
        let found_oids = found.iter().map(|group| group.oid).collect::<Vec<_>>();
        assert_eq!(found_oids.len(), 2);
        assert!(found_oids.contains(&GroupOid(g1)));
        assert!(found_oids.contains(&GroupOid(g2)));

        assert_eq!(repo.count_account_groups(user_oid.into()).await.unwrap(), 3);
        assert_eq!(repo.count_account_groups(other_oid.into()).await.unwrap(), 1);

        let desc_all = repo
            .list_account_groups(AccountGroupQuery {
                user_oid: user_oid.into(),
                order: GroupOrder::CreatedAtDesc,
                direction: RbacPageDirection::Forward,
                after: None,
                before: None,
                limit: 10,
            })
            .await
            .unwrap();
        assert_eq!(
            desc_all
                .items
                .iter()
                .map(|entry| entry.record.group.name.as_str())
                .collect::<Vec<_>>(),
            ["Gamma", "Beta", "Alpha"]
        );
        assert!(desc_all.items[0].record.joined_at > desc_all.items[1].record.joined_at);
        assert!(desc_all.items[1].record.joined_at > desc_all.items[2].record.joined_at);
        assert!(!desc_all.items[0].record.group.built_in);
        assert!(desc_all.items[1].record.group.built_in);

        for (order, expected) in [
            (GroupOrder::CreatedAtAsc, ["Alpha", "Beta", "Gamma"]),
            (GroupOrder::CreatedAtDesc, ["Gamma", "Beta", "Alpha"]),
        ] {
            let base = AccountGroupQuery {
                user_oid: user_oid.into(),
                order,
                direction: RbacPageDirection::Forward,
                after: None,
                before: None,
                limit: 2,
            };
            let first = repo.list_account_groups(base.clone()).await.unwrap();
            assert_eq!(
                first
                    .items
                    .iter()
                    .map(|entry| entry.record.group.name.as_str())
                    .collect::<Vec<_>>(),
                &expected[..2]
            );
            assert!(!first.has_previous_page && first.has_next_page);

            let second = repo
                .list_account_groups(AccountGroupQuery {
                    after: Some(first.items.last().unwrap().sort_key.clone()),
                    ..base.clone()
                })
                .await
                .unwrap();
            assert_eq!(
                second
                    .items
                    .iter()
                    .map(|entry| entry.record.group.name.as_str())
                    .collect::<Vec<_>>(),
                &expected[2..]
            );
            assert!(second.has_previous_page && !second.has_next_page);

            let back = repo
                .list_account_groups(AccountGroupQuery {
                    direction: RbacPageDirection::Backward,
                    before: Some(second.items[0].sort_key.clone()),
                    ..base
                })
                .await
                .unwrap();
            assert_eq!(
                back.items
                    .iter()
                    .map(|entry| entry.record.group.name.as_str())
                    .collect::<Vec<_>>(),
                &expected[..2]
            );
            assert!(!back.has_previous_page && back.has_next_page);
        }

        sql(
            &db,
            &format!(r#"UPDATE "user" SET enabled = false WHERE id = {subject}"#),
        )
        .await;
        assert_eq!(repo.count_account_groups(user_oid.into()).await.unwrap(), 0);
        let disabled_page = repo
            .list_account_groups(AccountGroupQuery {
                user_oid: user_oid.into(),
                order: GroupOrder::CreatedAtDesc,
                direction: RbacPageDirection::Forward,
                after: None,
                before: None,
                limit: 10,
            })
            .await
            .unwrap();
        assert!(disabled_page.items.is_empty());
        assert!(!disabled_page.has_previous_page && !disabled_page.has_next_page);
    })
    .await;
}

#[tokio::test]
#[ignore = "requires explicitly configured PostgreSQL test database"]
async fn postgres_account_roles_and_permissions_follow_active_self_service_rules() {
    isolated(|db| async move {
        let (subject, user_oid) = user(&db, "account-access-subject").await;
        let graphql_res = Uuid::new_v4();
        let orders_res = Uuid::new_v4();
        let disabled_res = Uuid::new_v4();
        let trusted_scope_oid = built_in_permission_oid(ManagementScope::UsersRead).0;
        let trusted_scope_code = ManagementScope::UsersRead.name();
        let r_direct = Uuid::new_v4();
        let r_group = Uuid::new_v4();
        let r_disabled = Uuid::new_v4();
        let r_revoked = Uuid::new_v4();
        let r_inactive_group = Uuid::new_v4();
        let g_active = Uuid::new_v4();
        let g_disabled = Uuid::new_v4();
        let g_deleted = Uuid::new_v4();
        let g_revoked_member = Uuid::new_v4();

        sql(
            &db,
            &format!(
                r#"
                INSERT INTO resource(oid, uri, name, enabled) VALUES
                    ('{graphql_res}', '{API_RESOURCE}', 'Identity API', true),
                    ('{orders_res}', 'urn:orders:api', 'Orders', true),
                    ('{disabled_res}', 'urn:disabled:api', 'Disabled API', false);
                INSERT INTO scope(id, oid, resource_id, code, name, names, description, descriptions, built_in, enabled) VALUES
                    (1, '{trusted_scope_oid}', '{graphql_res}', '{trusted_scope_code}', 'Read users', '{{"zh-CN":"读取用户"}}'::jsonb, 'Read directory', '{{"zh-CN":"查看用户目录"}}'::jsonb, true, true),
                    (2, gen_random_uuid(), '{graphql_res}', 'custom.untrusted', 'Untrusted', '{{}}'::jsonb, '', '{{}}'::jsonb, false, true),
                    (3, gen_random_uuid(), NULL, 'openid', 'OpenID', '{{}}'::jsonb, '', '{{}}'::jsonb, true, true),
                    (4, gen_random_uuid(), '{orders_res}', 'orders.read', 'Read orders', '{{"zh-CN":"读取订单"}}'::jsonb, '', '{{}}'::jsonb, false, true),
                    (5, gen_random_uuid(), '{orders_res}', 'orders.write', 'Write orders', '{{}}'::jsonb, '', '{{}}'::jsonb, false, true),
                    (6, gen_random_uuid(), '{orders_res}', 'orders.disabled', 'Disabled scope', '{{}}'::jsonb, '', '{{}}'::jsonb, false, false),
                    (7, gen_random_uuid(), '{disabled_res}', 'disabled.read', 'Disabled resource scope', '{{}}'::jsonb, '', '{{}}'::jsonb, false, true),
                    (8, gen_random_uuid(), '{orders_res}', 'orders.disabled_role', 'Via disabled role', '{{}}'::jsonb, '', '{{}}'::jsonb, false, true),
                    (9, gen_random_uuid(), '{orders_res}', 'orders.revoked_role', 'Via revoked role', '{{}}'::jsonb, '', '{{}}'::jsonb, false, true),
                    (10, gen_random_uuid(), '{orders_res}', 'orders.hidden_group', 'Via inactive group', '{{}}'::jsonb, '', '{{}}'::jsonb, false, true);
                INSERT INTO role(id, oid, name, enabled) VALUES
                    (1, '{r_direct}', 'DirectReader', true),
                    (2, '{r_group}', 'GroupWriter', true),
                    (3, '{r_disabled}', 'DisabledRole', false),
                    (4, '{r_revoked}', 'RevokedDirectRole', true),
                    (5, '{r_inactive_group}', 'InactiveGroupRole', true);
                INSERT INTO role_permission(oid, role_id, scope_id) VALUES
                    (gen_random_uuid(), 1, 1),
                    (gen_random_uuid(), 1, 2),
                    (gen_random_uuid(), 1, 3),
                    (gen_random_uuid(), 1, 4),
                    (gen_random_uuid(), 1, 6),
                    (gen_random_uuid(), 1, 7),
                    (gen_random_uuid(), 2, 4),
                    (gen_random_uuid(), 2, 5),
                    (gen_random_uuid(), 3, 8),
                    (gen_random_uuid(), 4, 9),
                    (gen_random_uuid(), 5, 10);
                INSERT INTO user_role(oid, user_id, role_id, reason, enabled, revoked_at, created_at) VALUES
                    (gen_random_uuid(), {subject}, 1, '', true, NULL, now() - interval '5 hours'),
                    (gen_random_uuid(), {subject}, 3, '', true, NULL, now() - interval '4 hours'),
                    (gen_random_uuid(), {subject}, 4, '', false, now(), now() - interval '4 hours');
                INSERT INTO user_group(id, oid, name, enabled, deleted_at) VALUES
                    (1, '{g_active}', 'ActiveGroup', true, NULL),
                    (2, '{g_disabled}', 'DisabledGroup', false, NULL),
                    (3, '{g_deleted}', 'DeletedGroup', true, now()),
                    (4, '{g_revoked_member}', 'RevokedMemberGroup', true, NULL);
                INSERT INTO group_membership(oid, group_id, user_id, reason, enabled, revoked_at, created_at) VALUES
                    (gen_random_uuid(), 1, {subject}, '', true, NULL, now() - interval '4 hours'),
                    (gen_random_uuid(), 2, {subject}, '', true, NULL, now() - interval '4 hours'),
                    (gen_random_uuid(), 3, {subject}, '', true, NULL, now() - interval '4 hours'),
                    (gen_random_uuid(), 4, {subject}, '', false, now(), now() - interval '4 hours');
                INSERT INTO group_role(oid, group_id, role_id, reason, enabled, revoked_at, created_at) VALUES
                    (gen_random_uuid(), 1, 2, '', true, NULL, now() - interval '3 hours'),
                    (gen_random_uuid(), 1, 3, '', true, NULL, now() - interval '3 hours'),
                    (gen_random_uuid(), 2, 5, '', true, NULL, now() - interval '3 hours'),
                    (gen_random_uuid(), 3, 5, '', true, NULL, now() - interval '3 hours'),
                    (gen_random_uuid(), 4, 5, '', true, NULL, now() - interval '3 hours');
                "#
            ),
        )
        .await;

        let repo = RbacManagementRepositoryImpl::new(db.clone());

        assert_eq!(repo.count_account_roles(user_oid.into(), None).await.unwrap(), 2);
        assert_eq!(
            repo.count_account_roles(user_oid.into(), Some(AuthorizationSource::Direct))
                .await
                .unwrap(),
            1
        );
        assert_eq!(
            repo.count_account_roles(user_oid.into(), Some(AuthorizationSource::Group))
                .await
                .unwrap(),
            1
        );

        let role_base = AccountRoleQuery {
            user_oid: user_oid.into(),
            source: None,
            order: UserRoleOrder::CreatedAtDesc,
            direction: RbacPageDirection::Forward,
            after: None,
            before: None,
            limit: 1,
        };
        let roles_first = repo.list_account_roles(role_base.clone()).await.unwrap();
        assert_eq!(roles_first.items.len(), 1);
        assert!(!roles_first.has_previous_page && roles_first.has_next_page);
        assert!(matches!(
            roles_first.items[0].grant,
            AccountRoleGrant::Group { role_oid, group_oid, .. }
            if role_oid == RoleOid(r_group) && group_oid == GroupOid(g_active)
        ));

        let roles_second = repo
            .list_account_roles(AccountRoleQuery {
                after: Some(roles_first.items[0].sort_key.clone()),
                ..role_base.clone()
            })
            .await
            .unwrap();
        assert_eq!(roles_second.items.len(), 1);
        assert!(roles_second.has_previous_page && !roles_second.has_next_page);
        assert!(matches!(
            roles_second.items[0].grant,
            AccountRoleGrant::Direct { role_oid, .. } if role_oid == RoleOid(r_direct)
        ));

        let roles_back = repo
            .list_account_roles(AccountRoleQuery {
                direction: RbacPageDirection::Backward,
                before: Some(roles_second.items[0].sort_key.clone()),
                ..role_base
            })
            .await
            .unwrap();
        assert_eq!(roles_back.items.len(), 1);
        assert_eq!(roles_back.items[0].grant.role_oid(), RoleOid(r_group));
        assert!(!roles_back.has_previous_page && roles_back.has_next_page);

        assert_eq!(
            repo.count_account_permissions(user_oid.into(), None, None)
                .await
                .unwrap(),
            3
        );
        assert_eq!(
            repo.count_account_permissions(user_oid.into(), None, Some(AuthorizationSource::Direct))
                .await
                .unwrap(),
            2
        );
        assert_eq!(
            repo.count_account_permissions(user_oid.into(), None, Some(AuthorizationSource::Group))
                .await
                .unwrap(),
            2
        );
        assert_eq!(
            repo.count_account_permissions(user_oid.into(), Some(orders_res.into()), None)
                .await
                .unwrap(),
            2
        );
        assert_eq!(
            repo.count_account_permissions(user_oid.into(), Some(graphql_res.into()), None)
                .await
                .unwrap(),
            1
        );
        assert_eq!(
            repo.count_account_permissions(user_oid.into(), Some(disabled_res.into()), None)
                .await
                .unwrap(),
            0
        );
        assert_eq!(
            repo.count_account_permissions(user_oid.into(), Some(Uuid::new_v4().into()), None)
                .await
                .unwrap(),
            0
        );

        let all_perms = repo
            .list_account_permissions(AccountPermissionQuery {
                user_oid: user_oid.into(),
                resource_oid: None,
                source: None,
                order: EffectivePermissionOrder::CodeAsc,
                direction: RbacPageDirection::Forward,
                after: None,
                before: None,
                limit: 10,
            })
            .await
            .unwrap();
        assert_eq!(
            all_perms
                .items
                .iter()
                .map(|entry| entry.record.code.as_str())
                .collect::<Vec<_>>(),
            [trusted_scope_code, "orders.read", "orders.write"]
        );
        let mgmt_perm = &all_perms.items[0].record;
        assert_eq!(mgmt_perm.resource_uri, API_RESOURCE);
        assert_eq!(mgmt_perm.names[0].locale, "zh-CN");
        assert_eq!(mgmt_perm.names[0].value, "读取用户");
        assert_eq!(mgmt_perm.sources.len(), 1);
        assert!(mgmt_perm.group_sources.is_empty());

        let shared_perm = &all_perms.items[1].record;
        assert_eq!(shared_perm.resource_uri, "urn:orders:api");
        assert_eq!(shared_perm.resource_name, "Orders");
        assert_eq!(shared_perm.sources.len(), 1);
        assert_eq!(shared_perm.group_sources.len(), 1);

        let write_perm = &all_perms.items[2].record;
        assert!(write_perm.sources.is_empty());
        assert_eq!(write_perm.group_sources.len(), 1);

        for (order, expected) in [
            (
                EffectivePermissionOrder::CodeAsc,
                [trusted_scope_code, "orders.read", "orders.write"],
            ),
            (
                EffectivePermissionOrder::CodeDesc,
                ["orders.write", "orders.read", trusted_scope_code],
            ),
        ] {
            let base = AccountPermissionQuery {
                user_oid: user_oid.into(),
                resource_oid: None,
                source: None,
                order,
                direction: RbacPageDirection::Forward,
                after: None,
                before: None,
                limit: 2,
            };
            let first = repo.list_account_permissions(base.clone()).await.unwrap();
            assert_eq!(
                first
                    .items
                    .iter()
                    .map(|entry| entry.record.code.as_str())
                    .collect::<Vec<_>>(),
                &expected[..2]
            );
            assert!(!first.has_previous_page && first.has_next_page);

            let second = repo
                .list_account_permissions(AccountPermissionQuery {
                    after: Some(first.items.last().unwrap().sort_key.clone()),
                    ..base.clone()
                })
                .await
                .unwrap();
            assert_eq!(
                second
                    .items
                    .iter()
                    .map(|entry| entry.record.code.as_str())
                    .collect::<Vec<_>>(),
                &expected[2..]
            );
            assert!(second.has_previous_page && !second.has_next_page);

            let back = repo
                .list_account_permissions(AccountPermissionQuery {
                    direction: RbacPageDirection::Backward,
                    before: Some(second.items[0].sort_key.clone()),
                    ..base
                })
                .await
                .unwrap();
            assert_eq!(
                back.items
                    .iter()
                    .map(|entry| entry.record.code.as_str())
                    .collect::<Vec<_>>(),
                &expected[..2]
            );
            assert!(!back.has_previous_page && back.has_next_page);
        }

        sql(
            &db,
            &format!(r#"UPDATE "user" SET enabled = false WHERE id = {subject}"#),
        )
        .await;
        assert_eq!(repo.count_account_roles(user_oid.into(), None).await.unwrap(), 0);
        assert!(
            repo.list_account_roles(AccountRoleQuery {
                user_oid: user_oid.into(),
                source: None,
                order: UserRoleOrder::CreatedAtDesc,
                direction: RbacPageDirection::Forward,
                after: None,
                before: None,
                limit: 10,
            })
            .await
            .unwrap()
            .items
            .is_empty()
        );
        assert_eq!(
            repo.count_account_permissions(user_oid.into(), None, None)
                .await
                .unwrap(),
            0
        );
        assert!(
            repo.list_account_permissions(AccountPermissionQuery {
                user_oid: user_oid.into(),
                resource_oid: None,
                source: None,
                order: EffectivePermissionOrder::CodeAsc,
                direction: RbacPageDirection::Forward,
                after: None,
                before: None,
                limit: 10,
            })
            .await
            .unwrap()
            .items
            .is_empty()
        );
    })
    .await;
}
