mod service;
pub use service::{
    DEVICE_VERIFICATION_PATH, DeviceAuthorizationParams, DeviceAuthorizationResponse,
    DeviceAuthorizationService, DeviceAuthorizationServiceDependencies, DeviceVerificationDecision,
    DeviceVerificationDescription, DeviceVerificationOutcome, DeviceVerificationStatus,
    DeviceVerificationUser,
};

#[cfg(test)]
mod tests;
