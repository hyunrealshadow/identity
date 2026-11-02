use std::future::Future;

use async_graphql::{Context, Result, SimpleObject};

/// Full cardinality of an already-authorized collection after filtering.
/// Page cursors and limits do not change this value.
#[derive(SimpleObject)]
pub(crate) struct ConnectionTotal {
    pub total_count: u64,
}

pub(crate) async fn connection_total(
    ctx: &Context<'_>,
    count: impl Future<Output = Result<u64>>,
) -> Result<ConnectionTotal> {
    let total_count = if ctx.look_ahead().field("totalCount").exists() {
        count.await?
    } else {
        0
    };
    Ok(ConnectionTotal { total_count })
}

#[cfg(test)]
mod tests {
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };

    use async_graphql::{
        EmptyMutation, EmptySubscription, Object, Schema,
        connection::{Connection, Edge},
    };

    use super::*;

    #[derive(SimpleObject)]
    struct Item {
        id: i32,
    }

    struct Query {
        reads: Arc<AtomicUsize>,
    }

    #[Object]
    impl Query {
        async fn items(
            &self,
            ctx: &Context<'_>,
        ) -> Result<Connection<usize, Item, ConnectionTotal>> {
            let additional = connection_total(ctx, async {
                self.reads.fetch_add(1, Ordering::SeqCst);
                Ok(7)
            })
            .await?;
            let mut connection = Connection::with_additional_fields(false, true, additional);
            connection.edges.push(Edge::new(0, Item { id: 1 }));
            Ok(connection)
        }
    }

    #[tokio::test]
    async fn row_only_selection_does_not_run_a_count_query() {
        let reads = Arc::new(AtomicUsize::new(0));
        let schema = Schema::new(
            Query {
                reads: reads.clone(),
            },
            EmptyMutation,
            EmptySubscription,
        );
        let response = schema.execute("{ items { edges { node { id } } } }").await;
        assert!(response.errors.is_empty(), "{:?}", response.errors);
        assert_eq!(reads.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn count_selection_in_a_named_fragment_honors_aliases_and_uses_full_cardinality() {
        let reads = Arc::new(AtomicUsize::new(0));
        let schema = Schema::new(
            Query {
                reads: reads.clone(),
            },
            EmptyMutation,
            EmptySubscription,
        );
        let response = schema.execute("query { items { ...Totals edges { node { id } } } } fragment Totals on ItemConnection { matching: totalCount }").await;
        assert!(response.errors.is_empty(), "{:?}", response.errors);
        let data = response.data.into_json().unwrap();
        assert_eq!(data["items"]["matching"], 7);
        assert_eq!(data["items"]["edges"].as_array().unwrap().len(), 1);
        assert_eq!(reads.load(Ordering::SeqCst), 1);
    }
}
