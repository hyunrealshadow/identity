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

/// Export the full executable schema without the removed `viewer` wrapper.
///
/// The binary can re-export this from `web::graphql` when SDL export is needed;
/// parent owns that root visibility.
#[must_use]
pub fn schema_sdl() -> String {
    build_schema(12, 300).sdl()
}
