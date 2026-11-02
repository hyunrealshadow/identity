use super::*;
use async_graphql::{EmptyMutation, EmptySubscription, Object, Schema};
use chrono::Utc;
use identity_application::rbac::{ScopeDescription, ScopeOid, ScopeRecord};
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};
use uuid::Uuid;

struct Query {
    reads: Arc<AtomicUsize>,
}

#[Object]
impl Query {
    #[graphql(complexity = "1 + first as usize * (1 + child_complexity)")]
    async fn scopes(&self, first: i32) -> ScopeConnection {
        self.reads.fetch_add(1, Ordering::SeqCst);
        let mut connection = ScopeConnection::new(false, true, 150);
        for index in 0..first {
            connection.edges.push(ScopeEdge::new(
                RbacConnectionCursor::from_backend(format!("cursor-{index}")),
                ScopeNode::new(ScopeRecord {
                    oid: ScopeOid(Uuid::new_v4()),
                    resource_oid: None,
                    code: format!("item.{index}"),
                    name: "Read item".into(),
                    names: vec![ScopeDescription {
                        locale: "en-US".into(),
                        value: "Read item".into(),
                    }],
                    description: "Read an item".into(),
                    descriptions: vec![],
                    built_in: false,
                    enabled: true,
                    version: Uuid::new_v4(),
                    created_at: Utc::now(),
                    updated_at: None,
                }),
            ));
        }
        connection
    }
}

#[tokio::test]
async fn a_full_localized_page_fits_without_relaxing_nested_query_costs() {
    let reads = Arc::new(AtomicUsize::new(0));
    let schema = Schema::build(
        Query {
            reads: reads.clone(),
        },
        EmptyMutation,
        EmptySubscription,
    )
    .limit_complexity(300)
    .extension(crate::graphql::schema::limits::ResponseAliasLimit(300))
    .finish();
    let response = schema.execute("{ scopes(first: 100) { totalCount pageInfo { hasNextPage hasPreviousPage startCursor endCursor } edges { cursor node { id code name names { locale value } description descriptions { locale value } builtIn enabled version createdAt updatedAt } } } }").await;
    assert!(response.errors.is_empty(), "{:?}", response.errors);
    let data = response.data.into_json().unwrap();
    assert_eq!(data["scopes"]["edges"].as_array().unwrap().len(), 100);
    assert_eq!(data["scopes"]["pageInfo"]["startCursor"], "cursor-0");
    assert_eq!(data["scopes"]["pageInfo"]["endCursor"], "cursor-99");
    assert_eq!(data["scopes"]["totalCount"], 150);
    let response = schema
        .execute("{ scopes(first: 100) { nodes { roles(first: 100) { nodes { id } } } } }")
        .await;
    assert!(
        response
            .errors
            .iter()
            .any(|error| error.message.contains("complex"))
    );
    assert_eq!(
        reads.load(Ordering::SeqCst),
        1,
        "nested query must be rejected before loading rows"
    );
    let fields = (0..301)
        .map(|index| format!("alias{index}: code"))
        .collect::<Vec<_>>()
        .join(" ");
    let response = schema
        .execute(format!(
            "{{ scopes(first: 100) {{ nodes {{ {fields} }} }} }}"
        ))
        .await;
    assert!(
        response
            .errors
            .iter()
            .any(|error| error.message.contains("complex"))
    );
    assert_eq!(
        reads.load(Ordering::SeqCst),
        1,
        "alias amplification must be rejected before loading rows"
    );
}
