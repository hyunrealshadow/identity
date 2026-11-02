use super::{isolated, row, sql, user};
use identity_application::rbac::{
    EffectivePermissionOrder, EffectivePermissionQuery, RbacManagementRepository,
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
            INSERT INTO user_role_binding(oid,user_id,role_id,reason) VALUES(gen_random_uuid(),{subject},1,''),(gen_random_uuid(),{subject},3,'');
            INSERT INTO user_group(id,oid,name) VALUES(1,gen_random_uuid(),'Test group');
            INSERT INTO group_membership(oid,group_id,user_id,reason) VALUES(gen_random_uuid(),1,{subject},'');
            INSERT INTO group_role_binding(oid,group_id,role_id,reason) VALUES(gen_random_uuid(),1,2,'');
        "#)).await;
        let repo=RbacManagementRepositoryImpl::new(db.clone());
        assert_eq!(repo.count_effective_permissions(user_oid.into(),resource.into()).await.unwrap(),105);
        assert_eq!(repo.count_effective_permissions(other_user.into(),resource.into()).await.unwrap(),0);
        assert_eq!(repo.count_effective_permissions(user_oid.into(),other_resource.into()).await.unwrap(),1);
        for order in [EffectivePermissionOrder::CodeAsc,EffectivePermissionOrder::CodeDesc] {
            let query=EffectivePermissionQuery {user_oid:user_oid.into(),resource_oid:resource.into(),order,direction:RbacPageDirection::Forward,after:None,before:None,limit:100};
            let first=repo.list_effective_permissions(query.clone()).await.unwrap();
            assert_eq!(first.items.len(),100);
            assert!(first.has_next_page && !first.has_previous_page);
            let second=repo.list_effective_permissions(EffectivePermissionQuery {after:Some(first.items.last().unwrap().sort_key.clone()),..query.clone()}).await.unwrap();
            assert_eq!(second.items.len(),5);
            assert!(!second.has_next_page && second.has_previous_page);
            let previous=repo.list_effective_permissions(EffectivePermissionQuery {direction:RbacPageDirection::Backward,before:Some(second.items[0].sort_key.clone()),..query.clone()}).await.unwrap();
            assert_eq!(previous.items.iter().map(|entry|&entry.record.code).collect::<Vec<_>>(),first.items.iter().map(|entry|&entry.record.code).collect::<Vec<_>>());
            assert!(!previous.has_previous_page && previous.has_next_page);
            assert_eq!(repo.count_effective_permissions(user_oid.into(),resource.into()).await.unwrap(),105);
        }
        let first=repo.list_effective_permissions(EffectivePermissionQuery {user_oid:user_oid.into(),resource_oid:resource.into(),order:EffectivePermissionOrder::CodeAsc,direction:RbacPageDirection::Forward,after:None,before:None,limit:100}).await.unwrap();
        assert_eq!(first.items[0].record.sources.len(),1);
        assert_eq!(first.items[0].record.group_sources.len(),1,"overlapping sources stay visible but do not multiply totals");
        sql(&db,"UPDATE user_group SET enabled=false WHERE id=1").await;
        assert_eq!(repo.count_effective_permissions(user_oid.into(),resource.into()).await.unwrap(),100);
        sql(&db,"UPDATE user_group SET enabled=true WHERE id=1; UPDATE role SET enabled=false WHERE id=1").await;
        assert_eq!(repo.count_effective_permissions(user_oid.into(),resource.into()).await.unwrap(),10);
        sql(&db,&format!("UPDATE resource SET enabled=false WHERE oid='{resource}'")).await;
        assert_eq!(repo.count_effective_permissions(user_oid.into(),resource.into()).await.unwrap(),0);
        sql(&db,&format!(r#"UPDATE resource SET enabled=true WHERE oid='{resource}'; UPDATE "user" SET enabled=false WHERE id={subject}"#)).await;
        assert_eq!(repo.count_effective_permissions(user_oid.into(),resource.into()).await.unwrap(),0);
        let count:i64=row(&db,"SELECT count(*)::bigint AS n FROM scope").await.try_get("","n").unwrap();
        assert_eq!(count,108,"disabled and unrelated scopes remain stored");
    }).await;
}
