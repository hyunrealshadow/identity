use std::error::Error as StdError;

use super::{
    code::AppErrorCode, kind::ErrorKind, params::ErrorParams, validation::ValidationError,
};

#[derive(Debug)]
enum AppErrorDetails {
    Validation(ValidationError),
}

#[derive(Debug)]
pub struct AppError {
    kind: ErrorKind,
    code: u32,
    params: ErrorParams,
    details: Option<AppErrorDetails>,
    source: Option<Box<dyn StdError + Send + Sync + 'static>>,
}

impl AppError {
    pub fn from_code(code: impl AppErrorCode) -> Self {
        Self {
            kind: code.kind(),
            code: code.code(),
            params: ErrorParams::new(),
            details: None,
            source: None,
        }
    }

    pub fn with_param(mut self, key: &'static str, value: impl Into<String>) -> Self {
        self.params = std::mem::take(&mut self.params).insert(key, value);
        self
    }

    pub fn with_source(mut self, source: impl StdError + Send + Sync + 'static) -> Self {
        self.source = Some(Box::new(source));
        self
    }

    pub fn with_field_error(mut self, field: impl Into<String>, error: AppError) -> Self {
        self.push_field_error(field, error);
        self
    }

    pub fn with_field(mut self, field: impl Into<String>) -> Self {
        let code = self.code;
        let params = self.params.clone();
        self.validation_mut().push_parts(field, code, params);
        self
    }

    pub fn push_field_error(&mut self, field: impl Into<String>, error: AppError) {
        self.validation_mut().push(field, error);
    }

    pub fn kind(&self) -> ErrorKind {
        self.kind
    }

    pub fn code(&self) -> u32 {
        self.code
    }

    pub fn params(&self) -> &ErrorParams {
        &self.params
    }

    pub fn validation(&self) -> Option<&ValidationError> {
        match self.details.as_ref()? {
            AppErrorDetails::Validation(validation) => Some(validation),
        }
    }

    fn validation_mut(&mut self) -> &mut ValidationError {
        let details = self
            .details
            .get_or_insert_with(|| AppErrorDetails::Validation(ValidationError::default()));
        match details {
            AppErrorDetails::Validation(validation) => validation,
        }
    }
}

impl std::fmt::Display for AppError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "[{:?}] error {}", self.kind, self.code)
    }
}

impl StdError for AppError {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        self.source
            .as_deref()
            .map(|source| source as &(dyn StdError + 'static))
    }
}
