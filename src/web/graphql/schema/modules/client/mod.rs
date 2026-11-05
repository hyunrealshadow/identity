//! OAuth client management: definitions, protocol settings, credentials and
//! lifecycle. Scope assignment stays with the scope module.

pub(crate) mod integration;
pub(crate) mod mutation;
pub(crate) mod query;
pub(crate) mod types;

pub(crate) use mutation::ClientMutation;
pub(crate) use query::ClientQuery;
