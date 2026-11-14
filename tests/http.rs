//! Production HTTP and GraphQL flows with isolated persistence fixtures.
extern crate identity_application as application;
extern crate identity_infrastructure as infrastructure;
#[path = "http/graphql.rs"]
mod graphql;
#[path = "http/metadata.rs"]
mod metadata;
#[path = "http/oauth2/mod.rs"]
mod oauth2;
#[path = "http/openid.rs"]
mod openid;

#[cfg(feature = "oidc-conformance")]
#[path = "http/conformance.rs"]
mod conformance;

#[path = "http/workload_runtime.rs"]
mod workload_runtime;
