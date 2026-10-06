mod service;
pub use service::{
    BackChannelLogoutDelivery, BackChannelLogoutNotification, BackChannelLogoutSender,
    FrontChannelLogoutNotification, LogoutOutcome, LogoutService, LogoutServiceDependencies,
    RpInitiatedLogoutRequest,
};

#[cfg(test)]
mod tests;
