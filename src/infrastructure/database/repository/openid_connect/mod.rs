//! OIDC client persistence, split into mapping, queries, and registration.

pub(crate) mod mapping;
mod queries;
pub(crate) mod registration;

pub use queries::OpenIdConnectClientRepositoryImpl;

#[cfg(test)]
mod mapping_tests;
#[cfg(test)]
mod registration_tests;
