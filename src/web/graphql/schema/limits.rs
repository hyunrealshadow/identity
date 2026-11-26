//! Document cost limits enforced before any resolver runs.
//!
//! The limits are checked here instead of through async-graphql's built-in
//! `limit_depth`/`limit_complexity`, whose rejections are untyped English
//! messages. Every rejection is a catalog error with its configured maximum.

use std::sync::Arc;

use async_graphql::{
    ServerError, ServerResult, ValidationResult, Variables,
    extensions::{Extension, ExtensionContext, ExtensionFactory, NextParseQuery, NextValidation},
    parser::types::{ExecutableDocument, Selection},
};
use identity_application::error::{AppError, codes::graphql_transport};
use unic_langid::langid;

use super::{context::RequestContext, error::project};
use crate::infrastructure::i18n::I18n;

#[derive(Debug, Clone, Copy)]
pub(crate) struct QueryLimits {
    pub max_depth: usize,
    pub max_complexity: usize,
    /// Aliases must remain bounded even for fields projected from an
    /// already-loaded row, so they share the complexity budget.
    pub max_aliases: usize,
}

impl ExtensionFactory for QueryLimits {
    fn create(&self) -> Arc<dyn Extension> {
        Arc::new(*self)
    }
}

#[async_trait::async_trait]
impl Extension for QueryLimits {
    async fn parse_query(
        &self,
        ctx: &ExtensionContext<'_>,
        query: &str,
        variables: &Variables,
        next: NextParseQuery<'_>,
    ) -> ServerResult<ExecutableDocument> {
        let document = next.run(ctx, query, variables).await?;
        if alias_count_exceeds(&document, self.max_aliases) {
            return Err(rejection(
                ctx,
                graphql_transport::error::QueryTooComplex::new(self.max_complexity).into(),
            ));
        }
        Ok(document)
    }

    async fn validation(
        &self,
        ctx: &ExtensionContext<'_>,
        next: NextValidation<'_>,
    ) -> Result<ValidationResult, Vec<ServerError>> {
        let result = next.run(ctx).await?;
        if result.depth > self.max_depth {
            return Err(vec![rejection(
                ctx,
                graphql_transport::error::QueryTooDeep::new(self.max_depth).into(),
            )]);
        }
        if result.complexity > self.max_complexity {
            return Err(vec![rejection(
                ctx,
                graphql_transport::error::QueryTooComplex::new(self.max_complexity).into(),
            )]);
        }
        Ok(result)
    }
}

fn alias_count_exceeds(document: &ExecutableDocument, max_aliases: usize) -> bool {
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
                    if aliases > max_aliases {
                        return true;
                    }
                    pending.push(&field.node.selection_set.node);
                }
                Selection::InlineFragment(fragment) => {
                    pending.push(&fragment.node.selection_set.node);
                }
                Selection::FragmentSpread(_) => {}
            }
        }
    }
    false
}

fn rejection(ctx: &ExtensionContext<'_>, error: AppError) -> ServerError {
    let projected = match ctx.data_opt::<RequestContext>() {
        Some(request) => project(request.state.resources().i18n(), &request.locale, &error),
        None => {
            let i18n = I18n::disabled();
            project(&i18n, &langid!("en-US"), &error)
        }
    };
    ServerError {
        message: projected.message,
        source: projected.source,
        locations: Vec::new(),
        path: Vec::new(),
        extensions: projected.extensions,
    }
}
