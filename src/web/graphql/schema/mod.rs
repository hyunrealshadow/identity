mod authorization;
mod context;
mod error;
mod modules;

use async_graphql::{EmptySubscription, Schema};

pub use context::RequestContext;
use modules::{MutationRoot, QueryRoot};

pub type ApiSchema = Schema<QueryRoot, MutationRoot, EmptySubscription>;

pub const RESOURCE_AUDIENCE: &str = "urn:identity:graphql";

pub fn build_schema(max_depth: usize, max_complexity: usize) -> ApiSchema {
    Schema::build(
        QueryRoot::default(),
        MutationRoot::default(),
        EmptySubscription,
    )
    .limit_depth(max_depth)
    .limit_complexity(max_complexity)
    .finish()
}
