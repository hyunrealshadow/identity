use std::error::Error as StdError;

use salvo::{Request, Response, Writer, async_trait, prelude::Json};
use serde::Serialize;

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

#[derive(Debug, Serialize)]
struct BusinessErrorResponse {
    error: ErrorDetail,
}

#[derive(Debug, Serialize)]
struct ErrorDetail {
    code: u32,
    message: String,
}

impl BusinessErrorResponse {
    fn new(code: u32, message: impl Into<String>) -> Self {
        Self {
            error: ErrorDetail {
                code,
                message: message.into(),
            },
        }
    }
}

#[async_trait]
impl Writer for AppError {
    async fn write(self, _req: &mut Request, _depot: &mut salvo::Depot, res: &mut Response) {
        let status = self.kind().http_status();
        if status.is_server_error() {
            tracing::error!(
                error = %self,
                source = ?self.source(),
                code = self.code(),
                "internal error"
            );
        } else {
            tracing::debug!(error = %self, code = self.code(), "business error");
        }

        let body = BusinessErrorResponse::new(self.code(), self.code().to_string());
        res.status_code(status);
        res.render(Json(body));
    }
}
