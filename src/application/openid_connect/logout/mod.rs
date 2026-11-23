mod service;
pub use service::{
    BackChannelLogoutDelivery, BackChannelLogoutNotification, BackChannelLogoutSender,
    FrontChannelLogoutNotification, LogoutOutcome, LogoutService, LogoutServiceDependencies,
    RpInitiatedLogout, RpInitiatedLogoutRequest,
};

#[cfg(test)]
mod tests;
