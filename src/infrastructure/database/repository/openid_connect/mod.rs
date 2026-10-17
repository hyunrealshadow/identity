//! OIDC client persistence, split into mapping, queries, and registration.

mod mapping;
mod queries;
mod registration;

pub use queries::OpenIdConnectClientRepositoryImpl;

#[cfg(test)]
mod mapping_tests;
#[cfg(test)]
mod registration_tests;
