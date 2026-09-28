use thiserror::Error;

#[derive(Debug, Error)]
#[error("{message}")]
pub struct SettingValidationError {
    message: String,
}

impl SettingValidationError {
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }

    pub fn message(&self) -> &str {
        &self.message
    }
}
