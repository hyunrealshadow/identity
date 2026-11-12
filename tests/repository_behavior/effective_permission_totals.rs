use super::{isolated, row, sql, user};
use identity_application::rbac::{
    AuthorizationSource, EffectivePermissionOrder, EffectivePermissionQuery,
    RbacManagementRepository, UserRoleGrant, UserRoleGrantQuery, UserRoleOrder,
    cursor::RbacPageDirection,
};
use identity_infrastructure::database::repository::rbac_management::RbacManagementRepositoryImpl;
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
