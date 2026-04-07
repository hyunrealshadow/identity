use std::error::Error as StdError;

use super::{code::AppErrorCode, kind::ErrorKind, params::ErrorParams};

#[derive(Debug)]
pub struct AppError {
    kind: ErrorKind,
    code: u32,
    params: ErrorParams,
    source: Option<Box<dyn StdError + Send + Sync + 'static>>,
}

impl AppError {
    pub fn from_code(code: impl AppErrorCode) -> Self {
        Self {
            kind: code.kind(),
            code: code.code(),
            params: ErrorParams::new(),
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

    pub fn kind(&self) -> ErrorKind {
        self.kind
    }

    pub fn code(&self) -> u32 {
        self.code
    }

    pub fn params(&self) -> &ErrorParams {
        &self.params
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
