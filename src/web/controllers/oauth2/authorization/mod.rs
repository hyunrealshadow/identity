mod authorize;
mod consent;
mod continuation;
mod error;
mod initiate_login;
mod interaction;
mod par;
mod request;
mod response;

pub(super) use authorize::endpoint as authorize;
pub(super) use consent::{get_endpoint as consent_get, post_endpoint as consent_post};
pub(super) use continuation::endpoint as continue_authorization;
pub(super) use initiate_login::endpoint as initiate_login;
pub(super) use par::{endpoint as par, method_not_allowed};

#[cfg(test)]
mod tests;
