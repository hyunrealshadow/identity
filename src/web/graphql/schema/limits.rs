use async_graphql::{
    ServerError, ServerResult, Variables,
    extensions::{Extension, ExtensionContext, ExtensionFactory, NextParseQuery},
    parser::types::{ExecutableDocument, Selection},
};
use std::sync::Arc;

/// Aliases must remain bounded even for fields projected from an already-loaded row.
pub(crate) struct ResponseAliasLimit(pub usize);
impl ExtensionFactory for ResponseAliasLimit {
    fn create(&self) -> Arc<dyn Extension> {
        Arc::new(ResponseAliasLimit(self.0))
    }
}

#[async_trait::async_trait]
impl Extension for ResponseAliasLimit {
    async fn parse_query(
        &self,
        ctx: &ExtensionContext<'_>,
        query: &str,
        variables: &Variables,
        next: NextParseQuery<'_>,
    ) -> ServerResult<ExecutableDocument> {
        let document = next.run(ctx, query, variables).await?;
        let mut pending = document
            .operations
            .iter()
            .map(|(_, operation)| &operation.node.selection_set.node)
            .chain(
                document
                    .fragments
                    .values()
                    .map(|fragment| &fragment.node.selection_set.node),
            )
            .collect::<Vec<_>>();
        let mut aliases = 0usize;
        while let Some(set) = pending.pop() {
            for selection in &set.items {
                match &selection.node {
                    Selection::Field(field) => {
                        aliases += usize::from(field.node.alias.is_some());
                        if aliases > self.0 {
                            return Err(ServerError::new("Query is too complex.", Some(field.pos)));
                        }
                        pending.push(&field.node.selection_set.node);
                    }
                    Selection::InlineFragment(fragment) => {
                        pending.push(&fragment.node.selection_set.node)
                    }
                    Selection::FragmentSpread(_) => {}
                }
            }
        }
        Ok(document)
    }
}
