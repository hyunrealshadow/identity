//! Current persistence schema expressed as SeaORM entities.
//!
//! These definitions evolve with the current database schema; historical
//! structure remains encoded by the ordered migration crate.

pub mod prelude;
pub mod resource;

pub mod client;
pub mod client_authorization;
pub mod client_openid_connect;
pub mod client_openid_connect_cors_origin;
pub mod client_openid_connect_credential;
pub mod client_openid_connect_platform;
pub mod client_scope;
pub mod key;
pub mod key_jwk;
pub mod login;
pub mod scope;
pub mod session;
pub mod setting;
pub mod user;
pub mod user_client_consent;
pub mod user_credential;
