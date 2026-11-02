pub(crate) mod client;
pub(crate) mod connection;
pub(crate) mod integration;
pub(crate) mod mutation;
pub(crate) mod query;
pub(crate) mod types;

pub(crate) use client::{ClientScopeMutation, ClientScopeQuery};
pub(crate) use mutation::ScopeMutation;
pub(crate) use query::ScopeQuery;
