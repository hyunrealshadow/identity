//! OpenID Connect endpoints beyond the OAuth 2.0 core: UserInfo, RP-initiated
//! logout, and the session management iframe.

mod routes;
mod session;
mod user_info;

pub use routes::routes;
