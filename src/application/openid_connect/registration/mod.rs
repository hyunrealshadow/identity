mod credential;
mod request;
mod response;
#[cfg(test)]
mod tests;
mod token;
mod validation;

pub use request::{
    DynamicClientJwks, DynamicClientRegistrationRequest, DynamicClientUpdateRequest,
};
pub use response::DynamicClientRegistrationResponse;
pub(crate) use validation::{
    fetch_sector_redirect_uris, sector_redirect_uris_include_registered_redirects,
};

mod service;
pub use service::DynamicClientRegistrationService;
