use async_graphql::{EmptySubscription, Schema};
use modules::{MutationRoot, QueryRoot};

pub(crate) mod access;
pub(crate) mod authorization;
pub(crate) mod connection;
mod context;
mod error;
mod limits;
pub(crate) mod management_guard;
mod modules;

pub use context::RequestContext;

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
    // Bound response amplification from aliases of in-memory projections.
    .extension(limits::ResponseAliasLimit(max_complexity))
    .finish()
}
